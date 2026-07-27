# Cybersecurity Toolkit

**Why this exists**

I built this toolkit to learn cybersecurity the only way that really sticks — by making things. Each project started as a question ("how does a port scanner actually work?", "how would you catch a brute-force attack?", "how do you stop an AI agent from doing something dangerous?") and became a small, working tool that answers it. The goal was never just to use security tools, but to understand them well enough to build my own.

The collection spans three sides of security: **offensive** (recon and scanning), **defensive** (detection and monitoring), and **AI security** (guarding autonomous agents). Every tool has its own README explaining what it does and what I learned building it.

Built while learning through Africahackon's AH200 program.

## Tools at a glance

| Tool | Language | Purpose |
|------|----------|---------|
| [agentgate](agentgate/) | Python | Safety gatekeeper for AI agents: authorizes, approves, and logs every action |
| [python/recon.py](python/) | Python | Passive recon suite: HTTP headers, WHOIS, and subdomain discovery |
| [python/subdomain_enum.py](python/) | Python | Find subdomains passively via Certificate Transparency logs |
| [python/header_grabber.py](python/) | Python | Grab HTTP headers and flag missing security headers |
| [python/whois_lookup.py](python/) | Python | Passive WHOIS domain reconnaissance |
| [web-vuln-scanner](web-vuln-scanner/) | Python | Scan a site for missing headers and exposed files |
| [misconfig-scanner](misconfig-scanner/) | Python | Local security misconfiguration auditor (like an on-host CSPM) |
| [log-detector](log-detector/) | Python | Detect SSH brute-force attacks and breaches from auth logs |
| [file-integrity-monitor](file-integrity-monitor/) | Python | Detect file tampering using SHA-256 baselines |
| [password-auditor](password-auditor/) | Python | Check password strength and breaches (k-anonymity) |
| [hash-cracker](hash-cracker/) | Python | Dictionary attack on password hashes (learning tool) |
| [ip-lookup](ip-lookup/) | Python | Look up IP geolocation and ownership via REST API |
| [scam-detector](scam-detector/) | Python | Detect Kenyan SMS / mobile-money scams and phishing links |
| [scam-detector-web](scam-detector-web/) | Python/Flask | Web version of the scam detector |
| [bash/](bash/) | Bash | Failed-login summariser, TCP port scanner, and system automation |

## A note on ethics

These tools are for learning and for testing systems I own or am explicitly authorized to test. Recon and scanning against systems without permission is illegal — the skill includes knowing where that line is.
