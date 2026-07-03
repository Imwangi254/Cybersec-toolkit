# Cybersec-toolkit
Growing collection of Bash and Python tools built while learning cybersecurity through Africahackon's AH200 program.

## failed_logins.sh

A Bash script that scans the systemd journal for failed SSH login attempts and summarizes the results.

### What it does
- Pulls SSH login activity from journalctl -u ssh
- Filters for Failed password entries
- Reports:
  - Top offending source IPs
  - Usernames targeted
  - Total number of failed attempts

### Usage
cd bash
chmod +x failed_logins.sh
sudo ./failed_logins.sh

sudo is required because journal logs need elevated permissions to read.

### Example output
=== Failed SSH Login Report ===

Top offending source IPs:
      3 ::1

Usernames targeted:
      3 kali

Total failed attempts:
3

### What I learned
- Modern Kali uses journalctl for logging instead of a flat /var/log/auth.log file
- Parsing structured text with grep -oP, sort, and uniq -c
- Debugging real permission and authentication issues (sudo, GitHub PATs)


## port_scanner.sh
A Bash script that scans a target host for open TCP ports using `/dev/tcp`.

### What it does
- Takes a target IP and a port range as input
- Attempts a TCP connection to each port in the range
- Reports which ports are open

### Usage
cd bash
chmod +x port_scanner.sh
./port_scanner.sh

### Example output
Port 22: OPEN

## port_scanner.py
A Python TCP port scanner covering the same functionality as the Bash version, built to compare approaches across languages.

### What it does
- Takes a target IP, start port, and end port as command-line arguments
- Uses Python's `socket` module to attempt a connection to each port
- Reports open ports and a summary at the end

### Usage
cd python
python3 port_scanner.py <target_ip> <start_port> <end_port>

Example:
python3 port_scanner.py 127.0.0.1 1 100

### Example output
=== Python Port Scanner ===
Target: 127.0.0.1
Port range: 1-100
Port 22: OPEN
----------------------------------------
Total open ports found: 1
Open ports: [22]

### What I learned
- Using Python's socket module and connect_ex() to test TCP ports
- Handling command-line arguments with sys.argv
- Comparing how Bash and Python approach the same networking task
## header_grabber.py
A Python HTTP header grabber for passive web reconnaissance. Fetches a target's HTTP response headers and flags security-relevant findings.
### What it does
- Prompts the user for a target URL
- Uses the `requests` module to fetch the site's HTTP response headers
- Prints all response headers
- Identifies the server software from the `Server` header
- Flags missing security headers (HSTS, Content-Security-Policy, X-Frame-Options)
- Handles connection errors gracefully instead of crashing
### Usage
cd python
python3 header_grabber.py
Then enter a URL when prompted (e.g. https://example.com).
### Example output
----------------------------------------
Headers for: https://example.com
----------------------------------------
Server : cloudflare
...
----------------------------------------
Findings:
[i] Server software: cloudflare
[-] Missing security header: Strict-Transport-Security
[-] Missing security header: Content-Security-Policy
[-] Missing security header: X-Frame-Options
### What I learned
- Reading HTTP response headers as a source of recon intelligence
- Identifying server software and detecting missing security headers
- Handling network errors with try/except (RequestException)
- Interpreting connection errors (DNS resolution failures vs refused vs timeout)
