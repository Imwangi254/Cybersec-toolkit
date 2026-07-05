# Cybersec-toolkit
Growing collection of Bash and Python tools built while learning cybersecurity through Africahackon's AH200 program.

## Tools at a glance

| Tool | Language | Purpose |
|------|----------|---------|
| `bash/failed_logins.sh` | Bash | Summarise failed SSH logins from the journal |
| `bash/port_scanner.sh` | Bash | TCP port scanner using /dev/tcp |
| `python/port_scanner.py` | Python | TCP port scanner (socket module) |
| `python/header_grabber.py` | Python | Grab HTTP headers, flag missing security headers |
| `python/whois_lookup.py` | Python | Passive WHOIS domain recon |
| `python/subdomain_enum.py` | Python | Subdomain discovery via Certificate Transparency |
| `python/recon.py` | Python | Combined passive recon suite |
| `log-detector/detector.py` | Python | SSH intrusion detector (brute-force + breach) |
| `misconfig-scanner/scanner.py` | Python | Local security misconfiguration auditor |
| `file-integrity-monitor/fim.py` | Python | Detect file tampering via SHA-256 baselines |
| `password-auditor/auditor.py` | Python | Audit password strength and check breaches (k-anonymity) |

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
## whois_lookup.py
A Python WHOIS lookup tool for passive domain reconnaissance. Queries public registry data for a domain and presents a clean intelligence report.
### What it does
- Prompts the user for a target domain
- Uses the `python-whois` library to query registry data
- Reports registrar, creation/expiration/updated dates, and name servers
- Flags whether registrant contact info is exposed or redacted
- Detects non-existent domains and reports honestly instead of showing empty data
- Handles lookup errors gracefully instead of crashing
### Usage
cd python
python3 whois_lookup.py
Then enter a domain when prompted (e.g. example.com). Enter the domain only, not a full URL.
### Example output
----------------------------------------
WHOIS Report for: example.com
----------------------------------------
Registrar: RESERVED-Internet Assigned Numbers Authority
Creation date: 1995-08-14 04:00:00
Name servers:
  - ELLIOTT.NS.CLOUDFLARE.COM
----------------------------------------
Findings:
[i] Registrant contact info is redacted or private
### What I learned
- WHOIS as the most passive form of recon (never touches the target)
- Reading domain age and redacted fields as intelligence signals
- Extracting specific fields from a structured result object
- Making a tool honest: distinguishing "private data" from "no domain found"
## subdomain_enum.py
A Python subdomain enumeration tool for passive reconnaissance. Discovers subdomains of a target by querying public Certificate Transparency logs via crt.sh, without ever touching the target's infrastructure.
### What it does
- Prompts the user for a target domain
- Queries the crt.sh Certificate Transparency log API for certificates issued to the domain
- Extracts subdomains from certificate records and removes duplicates using a set
- Filters out wildcards, email addresses, lookalike domains, and the root domain itself
- Prints a clean, sorted list of unique subdomains with a total count
- Handles request failures and unreadable responses gracefully
### Usage
cd python
python3 subdomain_enum.py
Then enter a domain when prompted (e.g. example.com). Enter the domain only, not a full URL.
### Example output
----------------------------------------
Subdomains found for: example.com
----------------------------------------
dev.example.com
m.example.com
products.example.com
support.example.com
www.example.com
----------------------------------------
Total unique subdomains: 5
### What I learned
- Certificate Transparency logs as a passive source of subdomain intelligence
- Passive vs active enumeration and why passive is safe and legal
- Using a set to automatically de-duplicate results
- Filtering messy real-world data (newlines, wildcards, lookalike domains)
- The leading-dot check that distinguishes a true subdomain from a lookalike (e.g. testexample.com)
- Layered error handling for network requests vs unreadable responses
## recon.py
A passive reconnaissance suite that combines the header grabber, WHOIS lookup, and subdomain enumerator into a single tool. Takes one domain and runs all three recon tasks in sequence, producing one combined report.
### What it does
- Prompts the user for a target domain once
- Runs three recon functions against it in sequence:
  - HTTP header grab (server software, missing security headers)
  - WHOIS lookup (registrar, dates, name servers)
  - Subdomain enumeration via crt.sh Certificate Transparency logs
- Each section is clearly separated with headers
- Resilient by design: if one section fails, the others still run
### Usage
cd python
python3 recon.py
Then enter a domain when prompted (e.g. example.com).
### Example output
==================================================
HTTP HEADERS
==================================================
[i] Server software: cloudflare
[-] Missing security header: Strict-Transport-Security
==================================================
WHOIS
==================================================
Registrar: RESERVED-Internet Assigned Numbers Authority
==================================================
SUBDOMAINS
==================================================
dev.example.com
Total unique subdomains: 5
### What I learned
- Functions: packaging code into named, reusable, callable units
- Passing a parameter (domain) into functions instead of asking for input in each
- Using return instead of exit() so one failing section does not kill the whole run
- Composition: combining separate tools into a single suite
- Building incrementally in stages and testing after each one

## log-detector/detector.py

An SSH log intrusion detector that analyses authentication logs to detect brute-force attacks and possible breaches, with timestamped alerting and deduplication.

### What it does
- Reads an SSH auth log line by line and isolates failed/successful logins
- Groups events per source IP and applies a sliding time window (measures *rate*, not just count)
- Detects brute-force attacks (5+ failures from one IP within 2 minutes)
- Detects possible breaches (a successful login from an IP that also had many failures)
- Writes timestamped alerts to a persistent `alerts.log`
- Deduplicates so the same alert is not reported twice

### Usage
cd log-detector
python3 detector.py

### What I learned
- The read -> reason -> report loop that underpins all detection tools
- Rate-based detection using sliding time windows, not just raw counts
- The false-positive / false-negative trade-off (threshold tuning and alert fatigue)
- Alert deduplication with a persistent state file
- Testing detection logic *both ways*: proving it stays silent on normal activity and fires on real attacks

## misconfig-scanner/scanner.py

A local misconfiguration scanner - the on-host equivalent of a Cloud Security Posture Management (CSPM) scan. Audits the system for common security misconfigurations that mirror the classes of problems behind most cloud breaches.

### What it does
- Checks sensitive files (e.g. /etc/shadow) for world-readable permissions
- Parses /etc/ssh/sshd_config for the PermitRootLogin policy, correctly ignoring commented-out lines
- Inspects listening sockets (via `ss`) and flags risky services exposed on all interfaces (FTP, Telnet, databases), treating SSH as informational
- Reports findings with graded severity: RISK / WARN / INFO / OK

### Usage
cd misconfig-scanner
python3 scanner.py

### What I learned
- Proactive ("shift-left") security: finding open doors before an attacker does
- Reading Linux permission bits in code (stat / S_IROTH) - the local twin of a public S3 bucket
- Parsing config files safely (skipping comments) and driving system commands from Python (subprocess)
- Graded severity instead of flagging everything equally, to reduce false-positive noise
- How on-host checks map directly to cloud CSPM concepts (0.0.0.0 exposure = security group open to the internet)
