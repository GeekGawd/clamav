#!/bin/bash
# ClamScan Persistent Wrapper Script
# Keeps clamscan process alive and accepts scan requests via named pipe

PIPE_PATH="/tmp/clamscan_requests"
PID_FILE="/tmp/clamscan_persistent.pid"
LOG_FILE="/tmp/clamscan_persistent.log"

# Function to cleanup on exit
cleanup() {
    echo "Cleaning up..." >> "$LOG_FILE"
    rm -f "$PIPE_PATH" "$PID_FILE"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Create named pipe for requests
mkfifo "$PIPE_PATH" 2>/dev/null || {
    echo "Failed to create named pipe" >> "$LOG_FILE"
    exit 1
}

# Store our PID
echo $$ > "$PID_FILE"

echo "ClamScan Persistent Wrapper started. PID: $$" >> "$LOG_FILE"
echo "Listening for scan requests on: $PIPE_PATH" >> "$LOG_FILE"

# Pre-load signatures (optional warm-up)
echo "Pre-loading signatures..." >> "$LOG_FILE"
echo "test" > /tmp/dummy.txt
clamscan /tmp/dummy.txt > /dev/null 2>&1
rm -f /tmp/dummy.txt
echo "Signatures pre-loaded" >> "$LOG_FILE"

# Main loop - listen for scan requests
while true; do
    if read -r scan_request < "$PIPE_PATH"; then
        echo "Received scan request: $scan_request" >> "$LOG_FILE"
        
        # Parse the request (format: "SCAN:/path/to/file")
        if [[ "$scan_request" =~ ^SCAN:(.+)$ ]]; then
            scan_path="${BASH_REMATCH[1]}"
            echo "Scanning: $scan_path" >> "$LOG_FILE"
            
            # Perform the scan (signatures already loaded in memory by OS cache)
            clamscan "$scan_path" 2>&1 | tee -a "$LOG_FILE"
            
        elif [[ "$scan_request" == "SHUTDOWN" ]]; then
            echo "Shutdown requested" >> "$LOG_FILE"
            break
            
        else
            echo "Invalid request format: $scan_request" >> "$LOG_FILE"
        fi
    fi
done

cleanup
