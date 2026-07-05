import re
import hashlib
import requests

def check_strength(password):
    findings = []
    score = 0
    if len(password) >= 12:
        score += 2
        findings.append("[+] Good length (12+ characters)")
    elif len(password) >= 8:
        score += 1
        findings.append("[~] Acceptable length (8-11), longer is better")
    else:
        findings.append("[-] Too short (under 8 characters)")
    if re.search(r"[a-z]", password): score += 1
    else: findings.append("[-] No lowercase letters")
    if re.search(r"[A-Z]", password): score += 1
    else: findings.append("[-] No uppercase letters")
    if re.search(r"[0-9]", password): score += 1
    else: findings.append("[-] No digits")
    if re.search(r"[^a-zA-Z0-9]", password): score += 1
    else: findings.append("[-] No symbols")
    common = ["password", "123456", "qwerty", "admin", "letmein"]
    if password.lower() in common:
        findings.append("[-] This is a very common password!")
        score = 0
    return score, findings

def check_breach(password):
    """Check HIBP using k-anonymity. Returns breach count, or -1 on error."""
    # 1. SHA-1 hash the password, uppercase hex
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    # 2. split into prefix (first 5) and suffix (rest)
    prefix = sha1[:5]
    suffix = sha1[5:]
    # 3. send ONLY the prefix to the API
    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return -1
    except requests.RequestException:
        return -1
    # 4. the response is many "SUFFIX:count" lines - check ours locally
    for line in response.text.splitlines():
        returned_suffix, count = line.split(":")
        if returned_suffix == suffix:
            return int(count)      # found - it's been breached this many times
    return 0                       # our suffix not in the list - not breached

if __name__ == "__main__":
    pw = input("Enter a password to audit: ")

    score, findings = check_strength(pw)
    print()
    print("--- Strength ---")
    for f in findings:
        print(" ", f)
    if score >= 5:
        print(f"  Strength: STRONG (score {score}/6)")
    elif score >= 3:
        print(f"  Strength: MODERATE (score {score}/6)")
    else:
        print(f"  Strength: WEAK (score {score}/6)")

    print()
    print("--- Breach check (via Have I Been Pwned) ---")
    breaches = check_breach(pw)
    if breaches == -1:
        print("  [!] Could not reach the breach database (check your connection).")
    elif breaches == 0:
        print("  [+] Not found in any known breaches.")
    else:
        print(f"  [-] WARNING: found in breaches {breaches:,} times - do NOT use this password!")
