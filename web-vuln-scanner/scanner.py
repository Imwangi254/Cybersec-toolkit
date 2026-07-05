import requests
import sys

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS (prevents downgrade attacks)",
    "Content-Security-Policy": "Restricts scripts (mitigates XSS)",
    "X-Frame-Options": "Prevents clickjacking (framing)",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "Referrer-Policy": "Controls referrer info leakage",
}

# sensitive paths that should NOT be publicly accessible
SENSITIVE_PATHS = {
    "/.git/config": "Git repository exposed - source code may be downloadable!",
    "/.env": "Environment file - may contain secrets/DB passwords!",
    "/robots.txt": "May reveal hidden paths (informational)",
    "/.htaccess": "Server config file exposed",
    "/backup.zip": "Backup archive exposed",
    "/config.php.bak": "Backup of config file exposed",
    "/admin/": "Admin panel found (informational)",
}

def check_security_headers(url):
    print("[*] Checking security headers...")
    try:
        r = requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"  [!] Could not connect: {e}")
        return False
    findings = 0
    for header, why in SECURITY_HEADERS.items():
        if header in r.headers:
            print(f"  [OK] {header} is present")
        else:
            print(f"  [!] MISSING: {header} - {why}")
            findings += 1
    if "Server" in r.headers:
        print(f"  [i] Server banner reveals: {r.headers['Server']} (information disclosure)")
    print(f"  {findings} missing security header(s).")
    return True

def check_sensitive_files(url):
    print("\n[*] Checking for exposed sensitive files...")
    url = url.rstrip("/")
    found = 0
    for path, why in SENSITIVE_PATHS.items():
        try:
            r = requests.get(url + path, timeout=10, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code == 200:
            print(f"  [!] EXPOSED ({r.status_code}): {path} - {why}")
            found += 1
        elif r.status_code == 403:
            print(f"  [~] FORBIDDEN ({r.status_code}): {path} - exists but access denied")
        # 404 and others: silently skip (not found = good)
    if found == 0:
        print("  No obviously exposed sensitive files found.")
    else:
        print(f"  {found} exposed file(s) - investigate!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <url>")
        print("Example: python3 scanner.py https://example.com")
        sys.exit(1)
    target = sys.argv[1]
    print("=== Web Vulnerability Scanner ===")
    print(f"Target: {target}")
    print("(Only scan targets you own or are authorized to test)")
    print()
    if check_security_headers(target):
        check_sensitive_files(target)
