# SSH Log Intrusion Detector

A Python tool that analyses Linux SSH authentication logs to detect
brute-force attacks and possible breaches, with timestamped alerting
and deduplication.

Built as part of my cybersecurity toolkit while learning defensive
security fundamentals (the read -> reason -> report loop that underpins
all detection tools).

## What it detects

- **Brute-force attacks** — 5 or more failed logins from a single IP
  within a 2-minute window (rate-based, so a burst of failures triggers
  it but occasional human typos do not).
- **Possible breaches** — a *successful* login from an IP that also had
  many failed attempts (the signature of a brute-force that worked).

## How it works

1. **Reads** the auth log line by line.
2. **Parses** each failed/accepted login into IP, username, and timestamp.
3. **Reasons** — groups events per IP and applies detection rules,
   including a sliding time window so it measures *rate*, not just count.
4. **Reports** — prints alerts to the screen and writes a timestamped,
   persistent record to `alerts.log`.
5. **Deduplicates** — remembers alerts it has already raised
   (`seen_alerts.txt`) so it does not spam duplicates on repeated runs.

## Usage

```bash
python3 detector.py
```

Alerts are printed to the terminal and appended to `alerts.log`.

## Configuration

Two tunable values at the top of `detector.py`:

- `THRESHOLD` — number of failures that counts as an attack (default 5).
- `WINDOW_SECONDS` — the time window for the brute-force rule (default 120).

Lowering the threshold catches more but risks false positives (alert
fatigue); raising it is quieter but risks missing slow attacks. This
trade-off is a core concept in threat detection.

## Known limitations (deliberate design choices)

- **Deduplication remembers forever.** Once an alert is raised, that exact
  alert is suppressed on all future runs. This keeps `alerts.log` clean,
  but means a returning attacker from a previously-seen IP would not
  re-alert. Acceptable for on-demand use; a scheduled/unattended
  deployment should add a time-based cooldown instead.
- Parses the common `sshd` log format only. Other log formats (journald
  ISO timestamps, etc.) would need parser adjustments.
- Rule-based, so it only catches patterns it was written for. Novel
  attacks would need anomaly-detection (a future enhancement).

## Sample data

`auth.log` is included with a simulated brute-force attack for testing.
Run the tool against it to see the alerts fire.
