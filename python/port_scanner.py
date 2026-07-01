#!/usr/bin/env python3
"""
port_scanner.py
A simple TCP port scanner written in Python.
Scans a target host for open ports within a given range.
"""

import socket
import sys
from datetime import datetime

def scan_port(target_ip, port, timeout=1):
    """
    Attempts to connect to a single port on the target IP.
    Returns True if open, False if closed/filtered.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

def scan_range(target_ip, start_port, end_port, timeout=1):
    """
    Scans a range of ports on the target IP and prints results.
    """
    print(f"=== Python Port Scanner ===")
    print(f"Target: {target_ip}")
    print(f"Port range: {start_port}-{end_port}")
    print(f"Started: {datetime.now()}")
    print("-" * 40)

    open_ports = []

    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port, timeout):
            print(f"Port {port}: OPEN")
            open_ports.append(port)

    print("-" * 40)
    print(f"Scan finished: {datetime.now()}")
    print(f"Total open ports found: {len(open_ports)}")
    if open_ports:
        print(f"Open ports: {open_ports}")
    else:
        print("No open ports found in this range.")

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 port_scanner.py <target_ip> <start_port> <end_port>")
        print("Example: python3 port_scanner.py 127.0.0.1 1 1024")
        sys.exit(1)

    target_ip = sys.argv[1]
    try:
        start_port = int(sys.argv[2])
        end_port = int(sys.argv[3])
    except ValueError:
        print("Error: start_port and end_port must be integers.")
        sys.exit(1)

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Error: Invalid port range. Must be between 1 and 65535.")
        sys.exit(1)

    try:
        # Validate the target resolves to a real IP
        socket.gethostbyname(target_ip)
    except socket.gaierror:
        print(f"Error: Could not resolve target '{target_ip}'.")
        sys.exit(1)

    scan_range(target_ip, start_port, end_port)

if __name__ == "__main__":
    main()
