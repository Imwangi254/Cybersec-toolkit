#!/bin/bash
# port_scanner.sh - Scans common ports on a target host

if [ -z "$1" ]; then
    echo "Usage: $0 <target-ip-or-hostname>"
    exit 1
fi

TARGET=$1

# List of common ports to check
PORTS=(21 22 23 25 53 80 110 135 139 143 443 445 993 995 1723 3306 3389 5900 8080 8443)

echo "=== Port Scan Report for $TARGET ==="
echo ""

for PORT in "${PORTS[@]}"; do
    timeout 1 bash -c "echo > /dev/tcp/$TARGET/$PORT" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "Port $PORT: OPEN"
    else
        echo "Port $PORT: closed"
    fi
done

echo ""
echo "=== Scan complete ==="
