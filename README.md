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
