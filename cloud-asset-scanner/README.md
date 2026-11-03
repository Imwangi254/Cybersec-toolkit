# Cloud Asset Scanner

A small **attack-surface monitor** for assets you own or are authorized to test.
It discovers live hosts (httpx), scans them for known issues (nuclei), writes a
timestamped report, and can push a summary to a Telegram bot. Run it on a cron
schedule and it becomes a *bot* that watches your own exposure over time.

> **Authorization:** only scan assets you OWN or are EXPLICITLY AUTHORIZED to
> test (your own domains/cloud resources, or a bug-bounty program's in-scope
> targets). Scanning systems without permission is illegal (e.g. Kenya's
> Computer Misuse and Cybercrimes Act). The tool refuses to run until you pass
> `--i-am-authorized`.

## Requirements
- `httpx-toolkit` — `apt install httpx-toolkit` (or `pipx install httpx`)
- `nuclei` — `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
  (run `nuclei -update-templates` once)
- Python 3

## Usage
1. Edit `targets.txt` — one authorized target per line.
2. Run:
   ```bash
   python3 scanner.py --i-am-authorized
   ```
3. Reports land in `reports/` as `scan-<timestamp>.md` and `.json`.

Options:
```bash
python3 scanner.py --i-am-authorized \
    --targets targets.txt \
    --outdir reports \
    --severity medium,high,critical
```

## Optional: Telegram alerts
Copy `run.sh.example` to `run.sh`, add your bot token + chat id (from @BotFather),
and the scanner DMs you a summary after each run. `run.sh` is gitignored so your
token is never committed.

## Make it a bot (run on a schedule)
```bash
crontab -e
# daily at 06:00:
0 6 * * * /home/kali/cloud-asset-scanner/run.sh
```
(On Kali, enable the daemon once: `sudo systemctl enable --now cron`.)

## Pipeline
ls -l ~/ghstage/cloud-asset-scanner
STAGE=~/ghstage/cloud-asset-scanner

printf 'run.sh\ncron.log\nreports/\n' > "$STAGE/.gitignore"

cat > "$STAGE/README.md" << 'EOF'
# Cloud Asset Scanner

Attack-surface monitor for assets you OWN or are AUTHORIZED to test.
Discovers live hosts (httpx), scans them for known issues (nuclei), writes a
timestamped JSON + Markdown report, sends an optional Telegram alert, and is
cron-friendly so it can run as a daily bot.

## Authorization
Only scan assets you own or are explicitly authorized to test. Scanning
without permission is illegal (e.g. Kenya's Computer Misuse and Cybercrimes
Act). The tool refuses to run until you pass --i-am-authorized.

## Requirements
- httpx-toolkit
- nuclei (run once: nuclei -update-templates)
- Python 3

## Usage
    python3 scanner.py --i-am-authorized

Options: --targets targets.txt  --outdir reports  --severity medium,high,critical
Reports land in reports/ as scan-<timestamp>.md and scan-<timestamp>.json

## Telegram alerts (optional)
Copy run.sh.example to run.sh and add your bot token + chat id from @BotFather.
run.sh is gitignored, so the token is never committed.

## Scheduled bot
Enable cron once:  sudo systemctl enable --now cron
Then  crontab -e  and add:  0 6 * * * /home/kali/cloud-asset-scanner/run.sh

## Pipeline
targets.txt -> httpx (live hosts) -> nuclei (known issues) -> report -> Telegram

Author: Peter Mwangi (GitHub: Imwangi254)
