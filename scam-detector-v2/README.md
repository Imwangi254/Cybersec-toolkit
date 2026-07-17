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
| `signals.py` | Tier 2: sender-impersonation + URL (lookalike/shortener/IP) checks |
| `scam_detector.py` | Core engine: `analyse(message, sender="")` |
| `scam_cli.py` | Command-line front-end (`-m`, `-f`, stdin, `--json`) |
| `test_samples.py` | Quick hardcoded smoke test (pass/fail) |
| `evaluate.py` | Corpus-driven evaluation: precision / recall / F1 |
| `samples.csv` | Labelled corpus (`label,message`) — grow this with real data |

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

# With sender check (flags brand impersonation from personal numbers)
python3 scam_cli.py -s "+254712345678" -m "Safaricom: confirm your PIN"
```

Exit codes signal risk for scripting: `0` = LOW, `1` = MEDIUM, `2` = HIGH.

### As a library

```python
from scam_detector import analyse

result = analyse("Confirm your OTP now, Safaricom customer care, urgent")
print(result["risk"])          # HIGH
print(result["explanation"])   # list of plain-language reasons
```

## Testing & evaluation

Two harnesses:

```bash
# Quick smoke test (hardcoded samples, pass/fail)
python3 test_samples.py -v

# Full evaluation on a labelled corpus (precision / recall / F1)
python3 evaluate.py                  # uses samples.csv
python3 evaluate.py -c my.csv        # custom corpus
python3 evaluate.py --errors-only    # show only the mistakes, with reasons
```

**Why precision and recall, not just accuracy:** a single accuracy % hides *how*
you fail. Precision = of the messages flagged, how many were truly scams (low
precision means false alarms on real bank/M-Pesa texts). Recall = of the real
scams, how many were caught (low recall means dangerous misses). For a scam
detector, watch **precision** hardest — flagging legitimate messages destroys
user trust faster than the occasional miss.

**Growing the corpus is the most important next step.** The seed `samples.csv`
is hand-written, so it shares the same assumptions as the rules and can't reveal
their blind spots. Paste *real* scam SMS and *real* bank/M-Pesa/delivery
messages into `samples.csv` (no code change needed) and re-run `evaluate.py`.
The weights in `scam_patterns.py` are only truly validated once they survive
messages they weren't built from.

## Roadmap

- [x] Corpus-driven evaluation (`evaluate.py`) with precision/recall/F1.
- [x] Sender heuristics: flag "claims to be M-Pesa but sender is a personal
      number" (`signals.py`).
- [x] URL analysis: lookalike domains, shorteners, raw-IP links (`signals.py`).
- [ ] Grow `samples.csv` with real-world scam + legit messages (highest value).
- [ ] Swahili / Sheng coverage ("tuma pin yako", "akaunti imefungwa").
- [ ] Hybrid ML tiebreaker for reworded scams the rules miss.
- [ ] Flask front-end (see the existing web-app wrapper in the repo).

## Disclaimer

A heuristic aid, not a guarantee. It reduces risk but cannot catch every scam;
always verify suspicious messages through an official channel. No legitimate
bank, telco, or agency will ever ask you to read back an OTP or PIN.
