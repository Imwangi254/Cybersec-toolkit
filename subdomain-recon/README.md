# recon.py — Subdomain Enumeration & Live-Host Probing

Chains two ProjectDiscovery tools into one workflow: enumerate a domain's
subdomains with **subfinder**, then probe which are live over HTTP/S with
**httpx**.

Built for the Ah200 recon coursework.

## Requirements

```bash
sudo apt install subfinder httpx-toolkit
sudo apt install python3-requests   # only needed for --notify
```

## Usage

```bash
python3 recon.py -d vulnweb.com                 # basic run
python3 recon.py -d example.com -o results/ex   # custom output prefix
python3 recon.py -d vulnweb.com --notify        # + Telegram summary
```

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Target domain (required) |
| `-o`, `--output` | Output prefix; defaults to the domain name |
| `--notify` | Send a Telegram summary of the results |

## Telegram notifications (optional)

Token and chat ID are read from environment variables, never hardcoded:

```bash
export TELEGRAM_BOT_TOKEN="123456:ABC..."
export TELEGRAM_CHAT_ID="987654321"
python3 recon.py -d vulnweb.com --notify
```

Get the chat ID by messaging your bot, then:
`curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | python3 -m json.tool`
and reading `"chat": { "id": ... }`.

## Note: the "httpx" name collision

Two unrelated tools are called `httpx`: ProjectDiscovery's **prober**
(`httpx-toolkit` on Kali) and the **Python httpx client**, whose CLI may sit
on PATH as bare `httpx`. Kali aliases `httpx` -> `httpx-toolkit` for
interactive shells, but Python's `subprocess`/`which` don't see shell
aliases — they resolve the real binary on PATH. The script therefore prefers
`httpx-toolkit` in its lookup to avoid invoking the wrong tool.

## Disclaimer

For authorized testing and education only. `vulnweb.com` is provided by
Acunetix/Invicti for this purpose. Only scan domains you own or have
permission to test.
