# Password Strength Auditor + Breach Checker

A Python tool that audits password strength against best-practice rules
AND checks whether a password has appeared in known data breaches - using
the Have I Been Pwned (HIBP) database of ~850 million leaked passwords.

Crucially, the breach check never sends the password anywhere. It uses
k-anonymity: only the first 5 characters of the password's SHA-1 hash are
sent, and the final match is done locally.

## Why k-anonymity matters

Sending a password to a website to "check" it would be dangerous - the
site could log it, misuse it, or be breached itself. Instead:

1. The password is SHA-1 hashed locally (one-way, non-reversible).
2. Only the first 5 characters of that hash are sent to HIBP.
3. HIBP returns every breached hash sharing that 5-char prefix (hundreds
   of them) - it cannot tell which one is yours.
4. The tool checks locally whether the full hash is in that list.

The server helps check billions of passwords without ever learning yours.

## What it checks

Strength: length, character variety (upper/lower/digit/symbol), and common
weak passwords.

Breach status: how many times (if any) the password appears in real-world
data breaches.

## Usage

    python3 auditor.py

Then enter a password when prompted. Use test values (e.g. password123),
never a real password you rely on, while experimenting.

## Key lesson

Rule-based strength scoring is not enough. A password like "password123"
passes several rules but has been breached over 2 million times. Combining
strength rules with a breach check gives a far more honest assessment.

## What I learned

- k-anonymity: checking a secret against a remote database without
  revealing it, by sending only an ambiguous fragment of its hash.
- SHA-1 hashing applied to a real privacy-preserving protocol.
- Consuming a REST API (HIBP range endpoint) and parsing its response.
- Using regular expressions for character-class checks.
- Why breach data matters as much as complexity rules.

## Ethics

This tool is for auditing your own passwords and teaching password
security. It is not for testing credentials that are not yours.
