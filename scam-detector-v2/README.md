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

## Beyond the body: sender & URL signals (Tier 2)

The message text is only half the story. Two of the strongest signals live
*outside* the words, in `signals.py`:

**Sender mismatch** (`--sender`). Real M-Pesa comes from the sender ID `MPESA`;
a scam claiming to be M-Pesa comes from `+2547...`. When a body name-drops an
institution but the sender is a personal number, that mismatch scores heavily
(+6) — identical scam text scores LOW from `MPESA` and MEDIUM from a mobile
number.

**URL heuristics.** Any link is inspected (never fetched):

| Tell | Weight | Example |
|---|---|---|
| Raw IP address | 5 | `http://196.201.45.10/login` |
| Lookalike domain | 5 | `safaricom-verify.xyz` vs `safaricom.co.ke` |
| URL shortener | 2 | `bit.ly/x` hides the destination |
| Disposable TLD | 2 | `.xyz`, `.top`, `.tk` |

Content, sender and URL are scored as **separate signals** that feed one
combined verdict — each reports its own findings, so the reasoning stays
transparent (the report shows `content N + sender N + url N`).

## Bilingual coverage: Swahili & Sheng (Tier 3)

Generic scam detectors are English-only, so a Kenyan scam written in Swahili —
"*tuma pin yako ya M-Pesa haraka*" — sails straight through them. This tool
carries Swahili/Sheng terms alongside the English patterns in every category,
scored identically. Examples now caught:

| Swahili phrase | Meaning | Category |
|---|---|---|
| `tuma pin yako` | send your PIN | credential |
| `namba ya siri` | secret number (PIN) | credential |
| `haraka`, `sasa hivi` | quickly, right now | urgency |
| `imefungwa` | (account) has been blocked | urgency |
| `umeshinda`, `zawadi`, `bahati` | you've won, prize, luck | bait |
| `mkopo`, `nafasi ya kazi` | loan, job opportunity | bait |
| `sambaza` | forward/spread | share plea |

Term choices are grounded in Kenyan mobile-money fraud reporting (M-Pesa
impersonation, lucky-draw, loan/job-offer scams). A benign Swahili M-Pesa
confirmation is included in the corpus as a false-positive control.

**Known gap (not yet solved):** advance-fee *job-offer* scams that only carry
bait + "send money to this number" (no urgency, no credential ask) can still
score LOW — e.g. "*Nafasi ya kazi... tuma KES 500 kwa hii number*". The right
fix is a considered "unsolicited offer + pay a personal number" rule validated
against real samples, not a weight hack to pass one test. Logged for a future
build.

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
