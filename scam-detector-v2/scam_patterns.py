"""
scam_patterns.py
----------------
Weighted linguistic markers for social-engineering scam detection,
tuned for the Kenyan messaging landscape (M-Pesa, Safaricom, local banks).

Each category carries a weight reflecting how strongly it signals a scam.
The real signal is co-occurrence: legitimate institutions may hit one
marker, but rarely stack authority + urgency + a credential request.

Author: Peter (AH200 / Cybersec-toolkit)
"""

# Word-boundary regexes keep matches precise (e.g. 'pin' won't match 'spinning').
CATEGORIES = {
    "authority": {
        "weight": 1,
        "description": "Impersonates a trusted institution",
        "terms": [
            r"\bsafaricom\b", r"\bm-?pesa\b", r"\bairtel\b", r"\btelkom\b",
            r"\bkcb\b", r"\bequity\b", r"\bco-?op(erative)? bank\b", r"\bncba\b",
            r"\bdtb\b", r"\bstanbic\b", r"\bkra\b", r"\bhelb\b",
            r"\bcentral bank\b", r"\bcbk\b", r"\byour bank\b",
            r"\bcustomer (care|service)\b", r"\bofficial\b", r"\bgovernment\b",
        ],
    },
    "urgency": {
        "weight": 2,
        "description": "Manufactures time pressure to bypass judgement",
        "terms": [
            r"\bimmediately\b", r"\burgent(ly)?\b",
            r"\bwithin \d+ ?(hours?|hrs?|minutes?|mins?)\b",
            r"\bsuspend(ed|ing)?\b", r"\bblock(ed)?\b",
            r"\bdeactivat(e|ed|ion)\b", r"\bexpir(e|es|ing|ed)\b",
            r"\bfinal (notice|warning)\b", r"\bact now\b",
            r"\bfailure to\b", r"\bright away\b", r"\bas soon as possible\b",
        ],
    },
    "credential": {
        # Highest weight: this is the actual attack payload.
        "weight": 4,
        "description": "Requests a secret that should never be shared",
        "terms": [
            r"\botp\b", r"\bpin\b", r"\bpassword\b", r"\bone[- ]?time (pin|password|code)\b",
            r"\bverification code\b", r"\bsecret code\b", r"\bcvv\b",
            r"\bconfirm your (pin|code|password|otp)\b",
            r"\benter (the|your) (code|otp|pin)\b",
            r"\bsend (the|your|me the) (code|otp|pin)\b",
            r"\bshare (the|your) (code|otp|pin)\b",
            r"\bprovide (the|your) (code|otp|pin)\b",
        ],
    },
    "bait": {
        "weight": 2,
        "description": "Reward or fear hook that justifies the request",
        "terms": [
            r"\byou('| ha)?ve won\b", r"\bcongratulations\b", r"\bwinner\b",
            r"\bprize\b", r"\brefund\b", r"\breversal\b",
            r"\bwrong (transaction|number|sent)\b", r"\bsent (to you )?by mistake\b",
            r"\bclaim (your|now)\b", r"\bfree\b", r"\bbonus\b",
            r"\bpromo(tion)?\b", r"\bloan (approved|offer)\b", r"\bgift\b",
        ],
    },
    "action": {
        "weight": 1,
        "description": "Directs the victim to a channel the attacker controls",
        "terms": [
            r"\bclick (the|this|below) link\b", r"\bdial \*?\d+#?\b",
            r"\breply with\b", r"\bsend (to|money to)\b",
            r"http[s]?://\S+", r"\bbit\.ly\b", r"\btinyurl\b", r"\bcutt\.ly\b",
            r"\bwa\.me\b", r"\bwhatsapp (this|number)\b",
        ],
    },
    "share_plea": {
        "weight": 1,
        "description": "Chain-message tell: begs to be forwarded",
        "terms": [
            r"\bshare (with|this)\b", r"\bforward to (everyone|all|your)\b",
            r"\bsend to all (your )?contacts\b", r"\bspread the word\b",
            r"\btell everyone\b",
        ],
    },
}

# Protective context: phrases that legitimate senders use to WARN against
# sharing credentials. When a credential term is preceded by one of these,
# it is a safety reminder, not an attack -- so we suppress the credential hit.
# This defeats the naive-keyword failure where "never share your PIN"
# scores identically to "share your PIN".
PROTECTIVE_CONTEXT = [
    r"\b(do not|don'?t|never)\s+(share|give|send|disclose|reveal|provide|tell)\b",
    r"\bwe (will )?never (ask|request)\b",
    r"\bwill never (ask|request) (you )?(for|to)\b",
    r"\bkeep (your|it) (pin|password|otp|code) (safe|secret|private)\b",
    r"\bdo not disclose\b",
]

# Verdict thresholds — tune these against a labelled sample set.
THRESHOLDS = {
    "high": 10,   # >= this  -> HIGH RISK
    "medium": 5,  # >= this  -> SUSPICIOUS
}

# Bonus applied when the classic attack stack co-occurs.
DANGER_COMBO = {"authority", "urgency", "credential"}
DANGER_COMBO_BONUS = 5
