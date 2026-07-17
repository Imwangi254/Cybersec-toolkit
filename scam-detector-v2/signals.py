"""
signals.py
----------
Tier 2 heuristics: sender and URL analysis.

Content analysis (scam_detector.py) reads the message body. But the strongest
signals often live OUTSIDE the text:

  * Sender: a message claiming to be M-Pesa but sent from a personal number
    (+2547...) is almost certainly fraud, regardless of wording.
  * URLs: lookalike domains (safaricom-verify.xyz), link shorteners hiding the
    destination, raw-IP links, and disposable TLDs are classic phishing tells.

Each function returns {"score": int, "flags": [str, ...]} so the caller can
add the score and surface the reasons independently (explainability).

Static analysis only: URLs are inspected, never fetched or expanded (that
would mean contacting attacker infrastructure).

Author: Peter (AH200 / Cybersec-toolkit)
"""

import re

# ---------------------------------------------------------------------------
# Sender analysis
# ---------------------------------------------------------------------------

# Alphanumeric sender IDs legitimate institutions use (Kenya-first + global).
KNOWN_SENDER_IDS = {
    "mpesa", "m-pesa", "safaricom", "airtel", "airtelmoney", "telkom",
    "kcb", "equity", "equitybank", "co-opbank", "coopbank", "ncba", "dtb",
    "stanbic", "absa", "familybank", "kra", "helb", "itax", "ecitizen",
    "vodafone", "mtn", "orange", "att", "verizon", "t-mobile",
    "apple", "google", "microsoft", "amazon", "paypal", "netflix",
    "chase", "hsbc", "barclays", "citibank", "wellsfargo", "bankofamerica",
    "standardchartered", "revolut", "wise", "monzo",
}

# Institution categories a scammer impersonates -> patterns that appear in body.
IMPERSONATED = {
    "M-Pesa/Safaricom": [r"\bm-?pesa\b", r"\bsafaricom\b"],
    "a bank": [r"\bbank\b", r"\bkcb\b", r"\bequity\b", r"\bco-?op\b",
               r"\bncba\b", r"\bdtb\b", r"\bstanbic\b", r"\babsa\b",
               r"\bchase\b", r"\bhsbc\b", r"\bpaypal\b", r"\brevolut\b"],
    "a government agency": [r"\bkra\b", r"\bhelb\b", r"\becitizen\b",
                            r"\bgovernment\b"],
    "a tech company": [r"\bapple\b", r"\bgoogle\b", r"\bmicrosoft\b",
                       r"\bamazon\b", r"\bnetflix\b"],
}

PERSONAL_NUMBER = re.compile(r"^\+?\d[\d\s\-]{7,14}$")

WEIGHT_MISMATCH = 6
WEIGHT_SHORTCODE = 1


def analyse_sender(message, sender):
    """Cross-check sender against body. -> {"score", "flags"}."""
    result = {"score": 0, "flags": []}
    if not sender:
        return result

    body = (message or "").lower()
    raw = sender.strip()
    norm = raw.lower().replace(" ", "")
    known = {s.replace(" ", "") for s in KNOWN_SENDER_IDS}

    if norm in known:
        result["flags"].append(f"sender '{raw}' is a recognised institutional ID")
        return result

    if PERSONAL_NUMBER.match(raw):
        for label, patterns in IMPERSONATED.items():
            if any(re.search(p, body) for p in patterns):
                result["score"] += WEIGHT_MISMATCH
                result["flags"].append(
                    f"MISMATCH -- body claims to be {label} but was sent from "
                    f"a personal number ({raw}); real institutions use named "
                    f"sender IDs, not mobile numbers")
                break
    elif raw.isdigit() and len(raw) <= 6:
        result["score"] += WEIGHT_SHORTCODE
        result["flags"].append(f"sender '{raw}' is an unrecognised shortcode")

    return result


# ---------------------------------------------------------------------------
# URL analysis
# ---------------------------------------------------------------------------

URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "cutt.ly", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "shorturl.at", "wa.me",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".club",
    ".click", ".link", ".work", ".zip", ".mov", ".country",
}

LEGIT_DOMAINS = {
    "safaricom": "safaricom.co.ke",
    "mpesa": "safaricom.co.ke",
    "kcb": "kcbgroup.com",
    "equity": "equitybank.co.ke",
    "kra": "kra.go.ke",
    "ecitizen": "ecitizen.go.ke",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
}

WEIGHT_IP = 5
WEIGHT_LOOKALIKE = 5
WEIGHT_SHORTENER = 2
WEIGHT_TLD = 2

IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _host(url):
    host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    host = host.split("/")[0].split("?")[0].split("#")[0]
    host = host.split("@")[-1].split(":")[0]
    return host.lower().strip(".")


def _registered(host):
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyse_urls(message):
    """Inspect any URLs in the body. -> {"score", "flags"}."""
    result = {"score": 0, "flags": []}
    for url in URL_RE.findall(message or ""):
        host = _host(url)
        if not host:
            continue

        if IP_HOST_RE.match(host):
            result["score"] += WEIGHT_IP
            result["flags"].append(
                f"URL uses a raw IP address ({host}); legitimate institutions "
                f"use domain names")
            continue

        reg = _registered(host)

        if reg in SHORTENERS:
            result["score"] += WEIGHT_SHORTENER
            result["flags"].append(
                f"URL shortener ({reg}) hides the true destination")

        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                result["score"] += WEIGHT_TLD
                result["flags"].append(f"suspicious TLD ({tld}) in {host}")
                break

        for brand, real in LEGIT_DOMAINS.items():
            if brand in host and reg != real and reg not in SHORTENERS:
                result["score"] += WEIGHT_LOOKALIKE
                result["flags"].append(
                    f"lookalike domain '{host}' references '{brand}' but is "
                    f"not the official {real}")
                break

    return result
