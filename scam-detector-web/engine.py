import re
import sys

SCAM_SIGNALS = {
    "PIN/password request": {"weight": 3, "patterns": ["enter your pin", "your pin", "confirm your pin", "send pin", "your password", "confirm your password", "otp", "one time password"]},
    "Urgency/threat": {"weight": 2, "patterns": ["will be blocked", "account blocked", "suspended", "act now", "within 24", "immediately", "urgent", "final warning", "expire"]},
    "Prize/reward bait": {"weight": 2, "patterns": ["you have won", "congratulations", "winner", "claim your", "you've won", "lucky", "free", "reward", "bonus"]},
    "Money reversal scam": {"weight": 3, "patterns": ["sent to you in error", "please reverse", "reverse the", "wrong number", "sent by mistake", "return the money"]},
    "Impersonation": {"weight": 1, "patterns": ["safaricom", "m-pesa", "mpesa", "kcb", "equity", "co-op", "your bank", "customer care"]},
}

# URL shortener services often used to hide malicious links
SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly"]

# brand names scammers impersonate, and the REAL domains they should be on
BRANDS = {
    "safaricom": "safaricom.co.ke",
    "mpesa": "safaricom.co.ke",
    "kcb": "kcbgroup.com",
    "equity": "equitybank.co.ke",
    "coop": "co-opbank.co.ke",
}

def extract_domain(url):
    """Get the real registered domain from a URL (the part before the TLD)."""
    # strip protocol
    url = re.sub(r"^https?://", "", url)
    # take everything before the first / or ? or space
    host = re.split(r"[/?\s]", url)[0]
    return host.lower()

def check_urls(text):
    findings = []
    score = 0
    # find anything that looks like a URL or domain
    urls = re.findall(r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}[^\s]*)", text)

    for url in urls:
        domain = extract_domain(url)

        # 1. shortener?
        if any(s in domain for s in SHORTENERS):
            score += 2
            findings.append(f"[!] Shortened URL '{domain}' - hides the real destination")

        # 2. IP-address URL?
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            score += 3
            findings.append(f"[!] IP-address link '{domain}' - almost always malicious")

        # 3. lookalike domain? (brand name present but NOT the real domain)
        for brand, real_domain in BRANDS.items():
            if brand in domain and real_domain not in domain:
                score += 3
                findings.append(f"[!] LOOKALIKE: '{domain}' mentions '{brand}' but is NOT {real_domain}")

        # 4. no HTTPS on a link?
        if url.startswith("http://"):
            score += 1
            findings.append(f"[!] Insecure link (http, not https): '{domain}'")

    return score, findings

def check_message(text):
    text_lower = text.lower()
    score = 0
    findings = []

    for signal_type, info in SCAM_SIGNALS.items():
        for pattern in info["patterns"]:
            if pattern in text_lower:
                score += info["weight"]
                findings.append(f"[!] {signal_type}: found '{pattern}'")
                break

    money_request = re.search(r"(send|need|mpesa|m-pesa|loan|borrow).{0,15}\d{3,}", text_lower)
    if money_request:
        score += 2
        findings.append("[!] Money request: someone is asking for money")
        findings.append("     -> VERIFY: call the person directly before sending anything.")

    # add URL analysis
    url_score, url_findings = check_urls(text)
    score += url_score
    findings.extend(url_findings)

    return score, findings

if __name__ == "__main__":
    print("=== Scam Message Detector ===")
    print("Paste a suspicious SMS/message to analyze.\n")

    if len(sys.argv) > 1:
        message = " ".join(sys.argv[1:])
    else:
        message = input("Message: ")

    score, findings = check_message(message)

    print()
    if findings:
        for f in findings:
            print(" ", f)
    else:
        print("  No obvious scam signals detected.")

    print()
    if score >= 5:
        print(f"[VERDICT] HIGH RISK - very likely a scam (score {score})")
    elif score >= 2:
        print(f"[VERDICT] SUSPICIOUS - be careful (score {score})")
    else:
        print(f"[VERDICT] LOW RISK - but stay alert (score {score})")

    print("\n  Remember: no real bank or Safaricom will EVER ask for your PIN.")
    print("  Never click links in unexpected messages. Type the official site yourself.")
