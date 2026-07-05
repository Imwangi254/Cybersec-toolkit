# File Integrity Monitor (FIM)

A Python tool that detects unauthorised changes to important files by
comparing their SHA-256 hashes against a trusted baseline. If a watched
file is modified, deleted, or tampered with, the tool detects it.

This is the core concept behind enterprise tools like Tripwire and AIDE,
built from scratch to learn hashing and integrity monitoring.

## How it works

1. Baseline mode - hashes each watched file and saves the fingerprints
   to baseline.json (the trusted "known-good" snapshot).
2. Check mode - re-hashes each file and compares to the baseline,
   reporting each as OK, MODIFIED, MISSING, or NEW.

Because SHA-256 produces a completely different hash for even a
one-character change (the avalanche effect), any tampering is detectable.

## Usage

Create the baseline (when files are known to be in a good state):
    python3 fim.py baseline

Later, check integrity against that baseline:
    python3 fim.py check

## Watched files

Edit the WATCHED_FILES list at the top of fim.py to choose what to
monitor. Defaults include a test file and common system files
(/etc/hosts, /etc/passwd).

## What I learned

- Cryptographic hashing (SHA-256) and the avalanche effect: a tiny change
  produces a completely different hash, making tampering detectable.
- Reading files as raw bytes and hashing in chunks so any file type and
  size can be handled.
- The concept of a trusted baseline and detecting change over time.
- Storing structured state in JSON and comparing current vs recorded state.
- How this maps to real FIM tools (Tripwire, AIDE) and where it fits in a
  defense strategy (detecting tampering after a breach).

## Known limitations

- The baseline itself must be protected; if an attacker can alter
  baseline.json, they could hide their changes. On a real system the
  baseline should be stored read-only or off-host.
- Detects that a file changed, not what changed or who changed it.
- Runs on-demand; a real deployment would run on a schedule and alert.
