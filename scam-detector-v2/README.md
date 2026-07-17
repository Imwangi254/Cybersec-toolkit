# Scam Message Detector (Kenya-tuned)

A rule-based, **explainable** detector for social-engineering scam messages —
OTP/PIN phishing, fake prize/refund baits, account-suspension threats — tuned
for the Kenyan messaging landscape (M-Pesa, Safaricom, local banks, KRA).

Part of the [Cybersec-toolkit](https://github.com/Imwangi254/Cybersec-toolkit).

## Why rule-based and explainable

Scam messages share a consistent grammar. Rather than a black-box classifier,
this tool scores messages against weighted linguistic markers and reports
**which** categories fired and **why**. For a security tool, transparent
reasoning beats an opaque score — a user can see the evidence and decide.

## The detection model

Every social-engineering message tends to stack the same ingredients:

| Marker | Weight | What it signals |
|---|---|---|
| **Credential request** | 4 | The payload — "send your OTP/PIN". Highest weight. |
| **Urgency / threat** | 2 | "within 24 hours", "account suspended" |
| **Bait** | 2 | "you've won", "refund", "wrong transaction" |
| **Authority claim** | 1 | "Safaricom", "your bank", "KRA" |
| **Action instruction** | 1 | "click the link", "dial *123#" |
| **Share plea** | 1 | "forward to everyone" (chain-message tell) |

**The key rule:** no single marker means "scam". The signal is *co-occurrence*.
A **danger combo** bonus (+5) fires when authority + urgency + credential all
appear together — the classic attack pattern that legitimate senders rarely
produce.

**Protective-context suppression:** a naive keyword matcher flags "never share
your PIN" (a safety reminder) the same as "share your PIN" (an attack). This
tool detects protective phrasing and suppresses the credential hit, eliminating
that whole class of false positive.

## Files

| File | Purpose |
|---|---|
| `scam_patterns.py` | Weighted marker definitions + thresholds (tune here) |
| `scam_detector.py` | Core engine: `analyse()` and `format_report()` |
| `scam_cli.py` | Command-line front-end (`-m`, `-f`, stdin, `--json`) |
| `test_samples.py` | Labelled test harness with accuracy reporting |

## Usage

```bash
# Analyse a message directly
python3 scam_cli.py -m "Your M-Pesa is blocked. Send your PIN to reactivate."

# From a file
python3 scam_cli.py -f message.txt

# From a pipe
echo "You won a prize, click http://bit.ly/x" | python3 scam_cli.py

# JSON output for chaining into other tools
python3 scam_cli.py -m "..." --json
```

Exit codes signal risk for scripting: `0` = LOW, `1` = MEDIUM, `2` = HIGH.

### As a library

```python
from scam_detector import analyse

result = analyse("Confirm your OTP now, Safaricom customer care, urgent")
print(result["risk"])          # HIGH
print(result["explanation"])   # list of plain-language reasons
```

## Testing

```bash
python3 test_samples.py -v
```

The harness reports accuracy, **false positives** (legit flagged as scam) and
**false negatives** (scam missed). False positives are the metric that matters:
a detector that flags real bank/M-Pesa messages is useless in practice.

Current labelled set: **14/14 correct (0 false positives, 0 false negatives).**

## Roadmap

- [ ] Expand the labelled corpus with real-world samples (the weights should be
      tuned against genuine scam SMS *and* real bank/M-Pesa messages).
- [ ] Sender heuristics: flag "claims to be M-Pesa but sender is a personal
      number" — a very strong, cheap signal.
- [ ] URL analysis: lookalike domains (`safaricom-verify.com`) and shortener
      expansion.
- [ ] Optional Flask front-end (see the existing web-app wrapper in the repo).

## Disclaimer

A heuristic aid, not a guarantee. It reduces risk but cannot catch every scam;
always verify suspicious messages through an official channel. No legitimate
bank, telco, or agency will ever ask you to read back an OTP or PIN.
