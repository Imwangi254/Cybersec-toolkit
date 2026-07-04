# Local Misconfiguration Scanner

A Python tool that audits a Linux system for common security
misconfigurations - the local equivalent of a Cloud Security Posture
Management (CSPM) scan. Detects the same *classes* of problems that
cause most cloud breaches (exposed services, weak permissions,
unhardened defaults), on the machine it runs on.

Built to learn proactive ("shift-left") security: finding open doors
before an attacker walks through them, rather than reacting to attacks
after the fact.

## What it checks

1. **Sensitive file permissions** - flags files like `/etc/shadow` that
   are readable by all users (the local twin of a public S3 bucket).
2. **SSH root login policy** - parses `/etc/ssh/sshd_config` and reports
   whether direct root login over SSH is allowed, restricted, or left to
   the system default. Correctly ignores commented-out settings.
3. **Services exposed on all interfaces** - inspects listening sockets
   (`ss`) and flags risky services (FTP, Telnet, databases) reachable
   from the whole network - the local twin of a cloud security group
   open to 0.0.0.0/0. SSH is treated as informational since remote
   access is normally intended.

## Severity levels

- `[!] RISK`  - a real exposure that should be addressed.
- `[WARN]`    - not actively dangerous, but a hardening improvement.
- `[INFO]`    - expected exposure, shown for awareness.
- `[OK]`      - checked and safe.

## Usage

```bash
python3 scanner.py
```

Some checks (process names, certain sockets) may show more detail with
`sudo python3 scanner.py`.

## Known limitations

- Checks a fixed set of common misconfigurations; not exhaustive.
- Rule-based, so it only finds what it was told to look for.
- Judgement (e.g. which ports are "risky") is a sensible default and
  should be tuned to the environment - an FTP server may be intended on
  some hosts and forbidden on others.

## Design notes

Follows the same read -> reason -> report loop as a detection tool, and
reuses concepts like deduplication (each exposed port reported once) and
graded severity rather than flagging everything equally - reducing
false-positive noise.
