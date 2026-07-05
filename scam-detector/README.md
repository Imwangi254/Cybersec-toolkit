# Scam Message Detector (Kenya-focused)

A Python tool that analyses suspicious SMS/messages for signs of the scams
commonly used to steal money from Kenyan mobile-money and bank customers.
It explains WHY a message is risky and gives the user safe next steps.

Built to address a real local problem: most banking/M-Pesa fraud in Kenya
works by deceiving the customer (phishing links, fake reversal requests,
hacked-account money requests) rather than by hacking the bank. This tool
targets that human attack surface with awareness and detection.

## What it detects

- PIN/password/OTP requests (no real bank or Safaricom ever asks for these)
- Urgency and threat language ("account will be blocked", "act now")
- Prize/reward bait ("you have won", "claim now")
- Money-reversal scams ("sent in error, please reverse")
- Money requests ("send me 2000") with advice to verify by calling
- Suspicious links:
  - URL shorteners that hide the real destination
  - IP-address links
  - LOOKALIKE domains (e.g. safaricom-verify.com is NOT safaricom.co.ke)
  - Insecure http links

It scores the message and returns a verdict: LOW RISK, SUSPICIOUS, or HIGH RISK,
with an explanation of each signal found.

## Usage

Interactive (recommended, avoids shell-quoting issues):

    python3 scamcheck.py

Or pass the message as an argument (use single quotes):

    python3 scamcheck.py 'your message here'

## Honest limitations

- Rule-based: it catches known scam patterns, not every possible scam.
  Social-engineering that avoids these patterns can still slip through -
  which is why the tool teaches verification habits, not blind trust in a
  green light.
- It is an awareness/first-line tool for individuals, NOT a bank-level fraud
  system and not a guarantee of safety.
- The best defence against the "stuck friend needs money" scam remains
  calling the person on a number you already know.

## Roadmap

The detection engine here could later be wrapped in a simple web page or a
WhatsApp bot (ideal for Kenya, where WhatsApp is ubiquitous) so non-technical
users can forward a suspicious message and get an instant verdict.

## What I learned

- Turning real-world attack knowledge into detection rules.
- Distinguishing a real domain from a lookalike (the true registered domain
  is the part before the TLD, not just where the brand name appears).
- Weighted scoring and graded verdicts instead of a single yes/no.
- The honest limits of rule-based detection and why user education matters
  as much as the tool.

## Note on brand names

Brand names (Safaricom, M-Pesa, KCB, Equity, etc.) are referenced only to
help users identify impersonation attempts. This tool is not affiliated with,
endorsed by, or representing any of these companies.
