#!/bin/bash
# failed_logins.sh - Scan systemd journal for failed SSH login attempts

echo "=== Failed SSH Login Report ==="
echo ""

DATA=$(sudo journalctl -u ssh --no-pager | grep -i "Failed password")

if [ -z "$DATA" ]; then
    echo "No failed login attempts found."
    exit 0
fi

echo "Top offending source IPs:"
echo "$DATA" | grep -oP 'from \K[^ ]+' | sort | uniq -c | sort -nr

echo ""
echo "Usernames targeted:"
echo "$DATA" | grep -oP 'for \K[^ ]+' | sort | uniq -c | sort -nr

echo ""
echo "Total failed attempts:"
echo "$DATA" | wc -l
