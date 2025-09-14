# ClamAV Persistent Wrapper

A container-friendly alternative to clamscan that loads virus signatures once and reuses them for multiple file scans.

## Problem Solved

In container environments where running clamd daemon is not feasible, regular clamscan has to reload the entire virus database (8M+ signatures) for each scan, causing significant overhead.

## Solution

The persistent wrapper (`clamscan_simple_persistent`) loads signatures once at startup and reuses the loaded engine for scanning multiple files in a single process.

## Performance

- **Regular clamscan**: ~20 seconds (loads 8.7M signatures each time)
- **Persistent wrapper**: ~16 seconds (loads signatures once)
- **Improvement**: ~21% faster for multiple file scans

## Usage

```bash
# Build the wrapper
cmake --build build --target clamscan_simple_persistent

# Scan files (loads signatures once, scans multiple files)
./build/clamscan/clamscan_simple_persistent --database=/path/to/clamdb file1 file2 file3

# Example with freshclam database
./build/clamscan/clamscan_simple_persistent --database=/tmp/clamdb /bin/ls /bin/cat /bin/echo
```

## Output Example

```
Loading virus signatures...
Signatures loaded: 8707831
/bin/ls: OK
/bin/cat: OK
/bin/echo: OK
```

## Container Usage

```dockerfile
# Add to your container
COPY clamscan_simple_persistent /usr/local/bin/
COPY clamdb/ /var/lib/clamav/

# Scan files in container
RUN clamscan_simple_persistent --database=/var/lib/clamav/ /app/*
```

## Key Features

- No daemon process required
- Uses modern ClamAV 1.5.0 API (cl_scanfile_ex with cl_verdict_t)
- Compatible with all ClamAV database formats
- Supports unsigned databases for testing
- Drop-in replacement for basic clamscan usage
- Container and CI/CD friendly

## Database Setup

Use freshclam to download virus databases:

```bash
# Download to custom directory
freshclam --datadir=/tmp/clamdb

# Use with wrapper
./clamscan_simple_persistent --database=/tmp/clamdb files...
```
