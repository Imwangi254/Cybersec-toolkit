# Web Vulnerability Scanner

A Python tool that performs basic web application security checks against a
target URL. Built to learn what common web weaknesses look like and how a
scanner probes for them - a step toward web reconnaissance and bug bounty.

FOR AUTHORISED TESTING ONLY. Only scan targets you own or have explicit
permission to test. Unauthorised scanning is illegal in most jurisdictions,
including Kenya under the Computer Misuse and Cybercrimes Act.

## What it checks

1. Missing security headers - protective HTTP headers whose absence weakens
   a site: Strict-Transport-Security, Content-Security-Policy,
   X-Frame-Options, X-Content-Type-Options, Referrer-Policy. Also reports the
   Server banner (information disclosure).
2. Exposed sensitive files - probes common paths that should never be public:
   .git/config (source code leak), .env (secrets), backups, config files,
   admin panels. Reads the HTTP status code to judge exposure.

## How status codes are interpreted

- 200 = file exists and is readable (a real finding).
- 403 = file exists but access is denied (still confirms it is there).
- 404 = not found (good; skipped silently).

## Usage

    python3 scanner.py <url>

Example (safe reference target):

    python3 scanner.py https://example.com

## Recommended practice targets (legal)

- OWASP Juice Shop (run locally - you own it)
- testphp.vulnweb.com (Acunetix's deliberately vulnerable demo)
- demo.testfire.net (IBM's test site)

## What I learned

- Which HTTP security headers matter and why their absence is a weakness.
- That missing headers are extremely common, even on legitimate sites, which
  is why they are usually low-severity findings.
- Probing for sensitive files and interpreting HTTP status codes (200/403/404).
- The difference between passive recon and active scanning, and the legal line
  that comes with active probing.
- Graceful error handling for unreachable hosts and per-request failures.

## Limitations and ethics

- Checks a fixed set of common issues; not a full scanner (real tools like
  Nikto, OWASP ZAP, and Burp Suite go far deeper).
- Active probing must only be done against authorised targets.
