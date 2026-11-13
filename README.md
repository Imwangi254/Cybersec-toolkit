# 🛡️ Threat Intel & Outage Digest — n8n Automation

A self-hosted security automation that aggregates threat-intelligence news and
cloud-outage alerts from multiple sources, de-duplicates them, and delivers a
concise daily digest to Telegram. Built as a hands-on SOAR / security-automation
exercise.

## What it does

Every morning at **07:00**, the workflow:

1. Pulls the latest articles from several security RSS feeds (news + vendor +
   cloud status) in parallel.
2. **Merges** them into a single stream.
3. **De-duplicates** against previously-sent items, so only *new* articles go out.
4. **Limits** to the top N headlines.
5. Sends each as a message to a **Telegram** bot.

The result is a personal "tl;dr sec"–style digest — plus early warning of major
cloud incidents — delivered straight to your phone, fully hands-off.

## Architecture

```
Schedule Trigger (daily 07:00)
        │
        ├─► RSS: The Hacker News ──┐
        ├─► RSS: BleepingComputer ─┤
        ├─► RSS: Krebs on Security ┤
        ├─► RSS: AWS Security Blog ─┤──►  Merge  ──►  Remove Duplicates  ──►  Limit  ──►  Telegram
        ├─► RSS: Azure Status feed ─┤        (append)     (prev. executions)    (top N)      (bot)
        └─► … additional feeds ─────┘
```

- **Merge** (append mode) combines every feed into one list.
- **Remove Duplicates** keys on each article's `link` and remembers what it has
  already sent across runs — no repeats day to day.
- **Limit** caps the volume per run.
- **Telegram** delivers `title + link` per item.

## Sources

| Feed | URL |
|------|-----|
| The Hacker News | `https://feeds.feedburner.com/TheHackersNews` |
| BleepingComputer | `https://www.bleepingcomputer.com/feed/` |
| Krebs on Security | `https://krebsonsecurity.com/feed/` |
| AWS Security Blog | `https://aws.amazon.com/blogs/security/feed/` |
| Azure Status (incidents) | `https://azure.status.microsoft/status/feed/` |

Easily extended — add an `RSS Read` node, wire it to the trigger and Merge,
bump Merge's input count.

## Skills demonstrated

- **SOAR / workflow automation** with n8n (self-hosted via Docker)
- RSS aggregation, data merging, cross-run **de-duplication**
- **Telegram Bot API** integration for alert delivery
- Scheduling / unattended execution
- Threat-intelligence collection & cloud service-health monitoring

## Setup

> No secrets are stored in this repository. You supply your own.

1. Run n8n (Docker):
   ```bash
   docker run -d --name n8n --restart unless-stopped \
     -p 5678:5678 -e GENERIC_TIMEZONE=Africa/Nairobi \
     -v n8n_data:/home/node/.n8n docker.n8n.io/n8nio/n8n
   ```
2. Open `http://localhost:5678` and import `security-digest.workflow.json`
   (⋯ menu → **Import from File**).
3. Create a **Telegram** credential with your bot token (from `@BotFather`).
4. In the **Telegram** node, set **Chat ID** to your own
   (replace the `YOUR_TELEGRAM_CHAT_ID` placeholder).
5. Activate / **Publish** the workflow.

## Notes

- The Telegram bot token lives in n8n's encrypted credential store, **not** in
  the exported workflow. The only value to sanitise before sharing is the
  **Chat ID**.
- The Azure Status feed is empty when healthy and only populates during a broad
  incident — so it acts as an outage early-warning without adding daily noise.

---
*Built as part of hands-on blue-team / cloud-security study.*
