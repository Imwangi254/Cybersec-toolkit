#!/usr/bin/env python3
"""
scam_detector.py
----------------
Rule-based social-engineering scam detector.

Scores a message against weighted linguistic markers and returns an
explainable verdict: which categories fired, why, and a risk level.

Explainability is deliberate: for a security tool, "here is my reasoning"
is worth more than an opaque score. Every flag can be traced to a term.

Usage (as a library):
    from scam_detector import analyse
    result = analyse("Your M-Pesa is blocked. Send your PIN to reactivate.")

Author: Peter (AH200 / Cybersec-toolkit)
"""

import re
from scam_patterns import (
    CATEGORIES, THRESHOLDS, DANGER_COMBO, DANGER_COMBO_BONUS,
    PROTECTIVE_CONTEXT,
)
from signals import analyse_sender, analyse_urls

_PROTECTIVE = [re.compile(p, re.IGNORECASE) for p in PROTECTIVE_CONTEXT]


def _is_protective(message: str) -> bool:
    """True if the message contains security-reminder language that warns
    against sharing credentials (e.g. 'never share your PIN')."""
    return any(p.search(message) for p in _PROTECTIVE)

# Pre-compile every pattern once at import for speed and to fail fast
# on any malformed regex.
_COMPILED = {
    cat: [(t, re.compile(t, re.IGNORECASE)) for t in cfg["terms"]]
    for cat, cfg in CATEGORIES.items()
}


def analyse(message: str, sender: str = "") -> dict:
    """
    Analyse a single message.

    Args:
        message: the message body.
        sender:  optional -- the sender ID or phone number the message came
                 from. When supplied, sender/impersonation heuristics are added.

    Returns a dict:
        {
          "score": int,
          "risk": "HIGH" | "MEDIUM" | "LOW",
          "verdict": human-readable string,
          "categories": { category: [matched_terms...] },
          "combo": bool,          # did the danger stack co-occur?
          "explanation": [str...] # plain-language reasons
        }
    """
    if not message or not message.strip():
        return {
            "score": 0, "risk": "LOW", "verdict": "Empty message",
            "categories": {}, "combo": False, "explanation": [],
        }

    hits = {}
    score = 0
    explanation = []
    protective = _is_protective(message)

    for cat, patterns in _COMPILED.items():
        matched = sorted({
            pat.search(message).group(0).lower()
            for raw, pat in patterns if pat.search(message)
        })
        # A credential mention inside a protective reminder ("never share
        # your PIN") is not an attack -- suppress it to avoid false alarms.
        if cat == "credential" and protective:
            if matched:
                explanation.append(
                    "Credential terms found but within protective/warning "
                    "context (e.g. 'do not share your PIN') -- not counted."
                )
            continue
        if matched:
            weight = CATEGORIES[cat]["weight"]
            contribution = weight * len(matched)
            score += contribution
            hits[cat] = matched
            explanation.append(
                f"{cat.replace('_', ' ').title()} "
                f"({CATEGORIES[cat]['description']}): "
                f"matched {', '.join(repr(m) for m in matched)} "
                f"[+{contribution}]"
            )

    # The stack is the real signal: authority + urgency + credential together.
    combo = DANGER_COMBO.issubset(hits.keys())
    if combo:
        score += DANGER_COMBO_BONUS
        explanation.append(
            f"Danger combo (authority + urgency + credential all present) "
            f"[+{DANGER_COMBO_BONUS}] -- this is the classic attack pattern."
        )

    content_score = score  # snapshot before Tier 2 signals

    # Tier 2 -- signals outside the message body.
    sender_result = analyse_sender(message, sender)
    if sender_result["score"]:
        score += sender_result["score"]
    for f in sender_result["flags"]:
        explanation.append(f"Sender check: {f}")

    url_result = analyse_urls(message)
    if url_result["score"]:
        score += url_result["score"]
    for f in url_result["flags"]:
        explanation.append(f"URL check: {f}")

    signals = {
        "content": content_score,
        "sender": sender_result["score"],
        "url": url_result["score"],
    }

    if score >= THRESHOLDS["high"]:
        risk = "HIGH"
        verdict = "HIGH RISK -- very likely a scam. Do not respond or share any code."
    elif score >= THRESHOLDS["medium"]:
        risk = "MEDIUM"
        verdict = "SUSPICIOUS -- treat with caution. Verify via an official channel."
    else:
        risk = "LOW"
        verdict = "LOW RISK -- no strong scam indicators found."

    return {
        "score": score,
        "risk": risk,
        "verdict": verdict,
        "categories": hits,
        "combo": combo,
        "signals": signals,
        "explanation": explanation,
    }


def format_report(message: str, result: dict) -> str:
    """Render a human-readable report for one analysed message."""
    lines = []
    lines.append("=" * 60)
    preview = message.strip().replace("\n", " ")
    if len(preview) > 70:
        preview = preview[:67] + "..."
    lines.append(f"Message : {preview}")
    lines.append(f"Score   : {result['score']}")
    sig = result.get("signals")
    if sig:
        lines.append(f"          (content {sig['content']} + "
                     f"sender {sig['sender']} + url {sig['url']})")
    lines.append(f"Risk    : {result['risk']}")
    lines.append(f"Verdict : {result['verdict']}")
    if result["explanation"]:
        lines.append("Reasons :")
        for e in result["explanation"]:
            lines.append(f"   - {e}")
    else:
        lines.append("Reasons : none")
    lines.append("=" * 60)
    return "\n".join(lines)


if __name__ == "__main__":
    # Quick self-demo when run directly.
    sample = ("URGENT: Your M-Pesa account will be suspended within 24 hours. "
              "Confirm your PIN to reactivate. Safaricom customer care.")
    print(format_report(sample, analyse(sample)))
