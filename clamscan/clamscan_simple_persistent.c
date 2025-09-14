/*
 * Simple ClamScan Persistent Wrapper with User-Mode Server
 *
 * Goal:
 *  - Keep ClamAV signatures loaded and compiled in a long-lived, user-mode server
 *  - Subsequent command invocations connect to the server over a per-user UNIX socket
 *  - No daemon privileges, no setgid/setuid required
 *  - Falls back to in-process scanning if the server cannot be started
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <limits.h>

// libclamav
#include "clamav.h"

// common
#include "optparser.h"
#include "output.h"

// Simple persistent engine
static struct cl_engine *persistent_engine = NULL;
static int engine_loaded = 0;
static char g_sock_path[108] = {0}; // UNIX domain socket path for cleanup
static char g_lock_path[128] = {0}; // Instance lock path
static int g_lock_fd = -1;

static void cleanup_handler(int sig) {
    if (persistent_engine) {
        cl_engine_free(persistent_engine);
        persistent_engine = NULL;
    }
#ifndef _WIN32
    if (g_sock_path[0]) {
        unlink(g_sock_path);
        g_sock_path[0] = '\0';
    }
    if (g_lock_fd >= 0) {
        close(g_lock_fd);
        g_lock_fd = -1;
    }
    if (g_lock_path[0]) {
        unlink(g_lock_path);
        g_lock_path[0] = '\0';
    }
#endif
    exit(0);
}

// -------- Common helpers --------
static int write_full(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_full(int fd, void *buf, size_t len) {
    char *p = (char *)buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n == 0) return -1; // EOF
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static const char *get_socket_path(void) {
#ifdef _WIN32
    return NULL; // Not supported on Windows in this simple implementation
#else
    static char path[128];
    uid_t uid = getuid();
    snprintf(path, sizeof(path), "/tmp/clamav_userd_%u.sock", (unsigned)uid);
    return path;
#endif
}

#ifndef _WIN32
static const char *get_lock_path(void) {
    static char path[128];
    uid_t uid = getuid();
    snprintf(path, sizeof(path), "/tmp/clamav_userd_%u.lock", (unsigned)uid);
    return path;
}

static int acquire_instance_lock(const char *lock_path) {
    int fd;
    char buf[32];
    pid_t mypid = getpid();

retry:
    fd = open(lock_path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd >= 0) {
        int n = snprintf(buf, sizeof(buf), "%ld\n", (long)mypid);
        if (write(fd, buf, (size_t)n) < 0) { /* ignore */ }
        g_lock_fd = fd;
        strncpy(g_lock_path, lock_path, sizeof(g_lock_path) - 1);
        g_lock_path[sizeof(g_lock_path) - 1] = '\0';
        return 0; // acquired
    }
    if (errno == EEXIST) {
        // Check if owner is alive
        fd = open(lock_path, O_RDONLY);
        if (fd < 0) return -1; // can't read
        ssize_t r = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (r > 0) {
            buf[r] = '\0';
            long pid = strtol(buf, NULL, 10);
            if (pid > 1 && kill((pid_t)pid, 0) == 0) {
                // Another instance is alive
                return 1;
            }
        }
        // Stale lock
        if (unlink(lock_path) == 0) goto retry;
        return -1;
    }
    return -1;
}
#endif

static int load_signatures_simple(const char *dbdir) {
    int ret;
    unsigned int sigs = 0;

    if (engine_loaded) {
        return CL_SUCCESS; // Already loaded
    }

    if ((ret = cl_init(CL_INIT_DEFAULT))) {
        fprintf(stderr, "Can't initialize libclamav: %s\n", cl_strerror(ret));
        return ret;
    }

    if (!(persistent_engine = cl_engine_new())) {
        fprintf(stderr, "Can't create new engine\n");
        return CL_EMEM;
    }
    
    // Disable digital signature verification temporarily
    cl_engine_set_num(persistent_engine, CL_ENGINE_DISABLE_PE_CERTS, 1);
    cl_engine_set_num(persistent_engine, CL_ENGINE_KEEPTMP, 0);

    // Load signatures from database directory (matching clamscan default options)
    unsigned int dboptions = CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE | CL_DB_BYTECODE_UNSIGNED;
    if ((ret = cl_load(dbdir ? dbdir : cl_retdbdir(), persistent_engine, &sigs, dboptions))) {
        fprintf(stderr, "Database loading error: %s\n", cl_strerror(ret));
        cl_engine_free(persistent_engine);
        persistent_engine = NULL;
        return ret;
    }

    // Compile the engine
    if ((ret = cl_engine_compile(persistent_engine))) {
        fprintf(stderr, "Database compilation error: %s\n", cl_strerror(ret));
        cl_engine_free(persistent_engine);
        persistent_engine = NULL;
        return ret;
    }

    printf("Signatures loaded: %u\n", sigs);
    engine_loaded = 1;
    return CL_SUCCESS;
}

typedef struct ScanResult {
    int code;            // 0 clean, 1 infected-like, 2 error
    const char *name;    // alert name (may be NULL)
} ScanResult;

static ScanResult scan_file_result(const char *filename) {
    cl_verdict_t verdict;
    const char *alert_name = NULL;
    uint64_t scanned = 0;
    int ret;
    struct cl_scan_options options;

    if (!persistent_engine) {
        fprintf(stderr, "Engine not loaded\n");
        return (ScanResult){ .code = 2, .name = NULL };
    }

    // Initialize scan options with defaults
    memset(&options, 0, sizeof(struct cl_scan_options));

    ret = cl_scanfile_ex(
        filename,
        &verdict,
        &alert_name,
        &scanned,
        persistent_engine,
        &options,
        NULL,      // context
        NULL,      // hash_hint
        NULL,      // hash_out
        NULL,      // hash_alg
        NULL,      // file_type_hint
        NULL       // file_type_out
    );

    if (ret == CL_SUCCESS) {
        switch (verdict) {
            case CL_VERDICT_NOTHING_FOUND:
            case CL_VERDICT_TRUSTED:
                return (ScanResult){ .code = 0, .name = NULL };
                
            case CL_VERDICT_STRONG_INDICATOR:
            case CL_VERDICT_POTENTIALLY_UNWANTED:
                return (ScanResult){ .code = 1, .name = alert_name };
                
            default:
                return (ScanResult){ .code = 2, .name = NULL };
        }
    } else {
        return (ScanResult){ .code = 2, .name = NULL };
    }
}

static int scan_file_simple(const char *filename) {
    ScanResult r = scan_file_result(filename);
    if (r.code == 0) {
        printf("%s: OK\n", filename);
    } else if (r.code == 1) {
        printf("%s: %s FOUND\n", filename, r.name ? r.name : "UNKNOWN");
    } else {
        printf("%s: ERROR\n", filename);
    }
    return r.code;
}

#ifndef _WIN32
// -------- Server implementation (Linux/WSL) --------
static int ensure_socket_dir_perms(const char *sock_path) {
    // Ensure parent dir is writable; for /tmp it's fine. Set strict umask for socket file.
    (void)sock_path;
    umask(0077);
    return 0;
}

static void server_cleanup_socket(const char *sock_path) { if (sock_path) unlink(sock_path); }
static void server_atexit(void) { if (g_sock_path[0]) unlink(g_sock_path); }

static int run_server(const char *dbdir, const char *sock_path) {
    int ret = 0;
    int srv_fd = -1;
    struct sockaddr_un addr;

    // Load engine once
    if (dbdir && *dbdir) {
        fprintf(stderr, "Server: starting with DB dir: %s\n", dbdir);
    } else {
        fprintf(stderr, "Server: starting with default DB dir\n");
    }
#ifndef _WIN32
    {
        const char *lock = get_lock_path();
        int l = acquire_instance_lock(lock);
        if (l == 1) {
            fprintf(stderr, "Server: another instance is running (lock: %s)\n", lock);
            return 2;
        } else if (l != 0) {
            fprintf(stderr, "Server: failed to acquire lock %s: %s\n", lock, strerror(errno));
            return 1;
        }
        fprintf(stderr, "Server: acquired lock %s\n", lock);
    }
#endif
    if ((ret = load_signatures_simple(dbdir)) != CL_SUCCESS) {
        fprintf(stderr, "Server: failed to load signatures: %s\n", cl_strerror(ret));
        return 1;
    }
    fflush(stderr);

    ensure_socket_dir_perms(sock_path);

    srv_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv_fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    // Check for existing live server; avoid racing/unlinking a live socket
    {
        int probe = socket(AF_UNIX, SOCK_STREAM, 0);
        if (probe >= 0) {
            struct sockaddr_un paddr; memset(&paddr, 0, sizeof(paddr));
            paddr.sun_family = AF_UNIX;
            strncpy(paddr.sun_path, sock_path, sizeof(paddr.sun_path) - 1);
            if (connect(probe, (struct sockaddr *)&paddr, sizeof(paddr)) == 0) {
                // Someone is already listening
                close(probe);
                fprintf(stderr, "Server: another instance is already listening on %s\n", sock_path);
                close(srv_fd);
                return 2;
            } else {
                // If the path exists but is stale, unlink it
                if (errno != ENOENT) {
                    unlink(sock_path);
                }
                close(probe);
            }
        }
    }

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(srv_fd);
        return 1;
    }

    if (listen(srv_fd, 8) < 0) {
        perror("listen");
        close(srv_fd);
        unlink(sock_path);
        return 1;
    }

    // Cleanup on signals
    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);
    signal(SIGHUP, SIG_IGN);

    // Also make sure socket gets unlinked on exit
    if (sock_path) {
        strncpy(g_sock_path, sock_path, sizeof(g_sock_path) - 1);
        g_sock_path[sizeof(g_sock_path) - 1] = '\0';
        atexit(server_atexit);
    }

    fprintf(stderr, "Server: ready on %s\n", sock_path);
    fflush(stderr);

    // Protocol:
    // request: uint32_t file_count; repeat file_count times { uint32_t path_len; bytes }
    // response: repeat file_count times { uint32_t code; uint32_t name_len; bytes }

    for (;;) {
        int cfd = accept(srv_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        uint32_t nfiles = 0;
        if (read_full(cfd, &nfiles, sizeof(nfiles)) != 0) {
            close(cfd);
            continue;
        }

        {
            uint32_t i;
            for (i = 0; i < nfiles; i++) {
            uint32_t plen = 0;
            if (read_full(cfd, &plen, sizeof(plen)) != 0) { close(cfd); goto next_conn; }
            if (plen == 0 || plen > (32u * 1024u)) { // guard
                close(cfd); goto next_conn;
            }
            char *path = (char *)malloc(plen + 1);
            if (!path) { close(cfd); goto next_conn; }
            if (read_full(cfd, path, plen) != 0) { free(path); close(cfd); goto next_conn; }
            path[plen] = '\0';

            ScanResult r = scan_file_result(path);
            free(path);

            uint32_t code = (uint32_t)r.code;
            uint32_t nlen = r.name ? (uint32_t)strlen(r.name) : 0u;
            if (write_full(cfd, &code, sizeof(code)) != 0) { close(cfd); goto next_conn; }
            if (write_full(cfd, &nlen, sizeof(nlen)) != 0) { close(cfd); goto next_conn; }
            if (nlen) {
                if (write_full(cfd, r.name, nlen) != 0) { close(cfd); goto next_conn; }
            }
            }
        }

        close(cfd);
    next_conn:
        ;
    }

    close(srv_fd);
    unlink(sock_path);
    return 0;
}

static int connect_server(const char *sock_path) {9
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int spawn_server_background(const char *self_path, const char *dbdir, const char *sock_path) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        // child
        // Close stdio
        int nullfd = open("/dev/null", O_RDWR);
        if (nullfd >= 0) {
            dup2(nullfd, 0); dup2(nullfd, 1); dup2(nullfd, 2);
            if (nullfd > 2) close(nullfd);
        }
        if (dbdir && *dbdir) {
            execl(self_path, self_path, "--serve", "--database", dbdir, (char *)NULL);
        } else {
            execl(self_path, self_path, "--serve", (char *)NULL);
        }
        _exit(127);
    }
    // parent: wait briefly for server
    (void)sock_path;
    return 0;
}
#endif

int main(int argc, char **argv) {
    int i, ret;
    char *dbdir = NULL;
    int serve_mode = 0;

    // Parse basic arguments
    // Simple argument parsing
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--serve") == 0) {
            serve_mode = 1;
        } else if (strncmp(argv[i], "--database=", 11) == 0) {
            dbdir = argv[i] + 11;
        } else if (strcmp(argv[i], "--database") == 0 && (i + 1) < argc) {
            dbdir = argv[++i];
        } else if (argv[i][0] == '-') {
            // Unknown option
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 2;
        } else {
            break; // First non-option argument is start of files
        }
    }

#ifndef _WIN32
    if (serve_mode) {
        const char *sock_path = get_socket_path();
        if (!sock_path) {
            fprintf(stderr, "Server mode not supported on this platform.\n");
            return 2;
        }
        // Set up signal handlers for engine cleanup; socket cleanup handled in run_server
        signal(SIGINT, cleanup_handler);
        signal(SIGTERM, cleanup_handler);
        return run_server(dbdir, sock_path);
    }
#endif

    if (i >= argc) {
        printf("Usage: %s [--database=DIR] [--serve] file1 [file2 ...]\n", argv[0]);
        return 2;
    }

#ifndef _WIN32
    // Try to use the user-mode server if available
    const char *sock_path = get_socket_path();
    int fd = -1;
    if (sock_path) {
        fd = connect_server(sock_path);
        if (fd < 0) {
            // Attempt to autostart server (no elevated privileges required)
            char self_path[PATH_MAX];
            ssize_t slen = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
            if (slen > 0) {
                int tries;
                self_path[slen] = '\0';
                if (spawn_server_background(self_path, dbdir, sock_path) == 0) {
                    // Wait up to ~2s for server
                    for (tries = 0; tries < 20; tries++) {
                        usleep(100 * 1000);
                        fd = connect_server(sock_path);
                        if (fd >= 0) break;
                    }
                }
            }
        }
    }

    if (fd >= 0) {
        // Send request
        uint32_t nfiles = (uint32_t)(argc - i);
        if (write_full(fd, &nfiles, sizeof(nfiles)) != 0) { close(fd); fd = -1; }
        else {
            int k;
            for (k = i; k < argc; k++) {
                uint32_t plen = (uint32_t)strlen(argv[k]);
                if (write_full(fd, &plen, sizeof(plen)) != 0 || write_full(fd, argv[k], plen) != 0) {
                    close(fd); fd = -1; break;
                }
            }
        }

        int scan_results = 0;
        if (fd >= 0) {
            uint32_t idx;
            for (idx = 0; idx < (uint32_t)(argc - i); idx++) {
                uint32_t code = 2, nlen = 0;
                if (read_full(fd, &code, sizeof(code)) != 0 || read_full(fd, &nlen, sizeof(nlen)) != 0) {
                    scan_results = 2; break;
                }
                char *name = NULL;
                if (nlen) {
                    name = (char *)malloc(nlen + 1);
                    if (!name) { scan_results = 2; break; }
                    if (read_full(fd, name, nlen) != 0) { free(name); scan_results = 2; break; }
                    name[nlen] = '\0';
                }

                const char *file = argv[i + idx];
                if (code == 0) {
                    printf("%s: OK\n", file);
                } else if (code == 1) {
                    printf("%s: %s FOUND\n", file, name ? name : "UNKNOWN");
                } else {
                    printf("%s: ERROR\n", file);
                }
                if ((int)code > scan_results) scan_results = (int)code;
                if (name) free(name);
            }
        }

        if (fd >= 0) close(fd);
        return scan_results;
    }
#endif

    // Fallback: in-process (loads DB now, scans once)
    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);
    printf("Loading virus signatures...\n");
    if ((ret = load_signatures_simple(dbdir)) != CL_SUCCESS) return 2;
    int scan_results = 0;
    for (; i < argc; i++) {
        ret = scan_file_simple(argv[i]);
        if (ret > scan_results) scan_results = ret;
    }
    cleanup_handler(0);
    return scan_results;
}
