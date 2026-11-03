#!/usr/bin/env python3
"""
Cloud Asset Scanner — a continuous attack-surface monitor for AUTHORIZED targets.

Author: Peter Mwangi (GitHub: Imwangi254)

WHAT IT DOES
  1. Reads targets you OWN or are AUTHORIZED to test        (targets.txt)
  2. Probes which hosts are live + basic tech/title         (httpx)
  3. Scans the live hosts for known issues/misconfigs       (nuclei)
  4. Writes a timestamped report                            (JSON + Markdown)
  5. Optionally pushes a summary to your Telegram bot

AUTHORIZATION  (read this)
  Only scan assets you OWN or are EXPLICITLY AUTHORIZED to test. Scanning
  systems without permission is illegal (e.g. Kenya's Computer Misuse and
  Cybercrimes Act). This tool refuses to run until you pass --i-am-authorized.
"""

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import urllib.request


def which_or_die(tool, install_hint):
    path = shutil.which(tool)
    if not path:
        print(f"[!] Required tool '{tool}' not found on PATH.")
        print(f"    Install it: {install_hint}")
        sys.exit(1)
    return path


def read_targets(path):
    if not os.path.exists(path):
        print(f"[!] Targets file not found: {path}")
        sys.exit(1)
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    if not targets:
        print(f"[!] No targets in {path}. Add at least one authorized target.")
        sys.exit(1)
    return targets


def run(cmd):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        return proc.returncode, proc.stdout
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        print(f"[!] Timed out: {' '.join(cmd)}")
        return 124, ""


def probe_live(httpx_bin, targets, workdir):
    print(f"[*] Probing {len(targets)} target(s) for live hosts...")
    targets_file = os.path.join(workdir, "targets_in.txt")
    with open(targets_file, "w") as f:
        f.write("\n".join(targets) + "\n")
    rc, out = run([httpx_bin, "-l", targets_file, "-json", "-silent",
                   "-title", "-tech-detect", "-status-code"])
    live = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            live.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    print(f"[+] {len(live)} live host(s) found.")
    return live


def scan_vulns(nuclei_bin, live_urls, workdir, severity):
    if not live_urls:
        return []
    print(f"[*] Running nuclei on {len(live_urls)} live host(s) (severity: {severity})...")
    live_file = os.path.join(workdir, "live.txt")
    with open(live_file, "w") as f:
        f.write("\n".join(live_urls) + "\n")
    rc, out = run([nuclei_bin, "-l", live_file, "-severity", severity,
                   "-jsonl", "-silent"])
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    print(f"[+] {len(findings)} finding(s).")
    return findings


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def build_report(live, findings, outdir):
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs(outdir, exist_ok=True)
    json_path = os.path.join(outdir, f"scan-{ts}.json")
    with open(json_path, "w") as f:
        json.dump({"timestamp": ts, "live_hosts": live, "findings": findings}, f, indent=2)
    findings.sort(key=lambda x: SEV_ORDER.get(x.get("info", {}).get("severity", "unknown"), 5))
    lines = [f"# Attack-surface scan — {ts}", ""]
    lines.append(f"- Live hosts: **{len(live)}**")
    lines.append(f"- Findings: **{len(findings)}**")
    lines.append("")
    tally = {}
    for fdg in findings:
        sev = fdg.get("info", {}).get("severity", "unknown")
        tally[sev] = tally.get(sev, 0) + 1
    if tally:
        lines.append("## Findings by severity")
        for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
            if sev in tally:
                lines.append(f"- {sev.capitalize()}: {tally[sev]}")
        lines.append("")
    lines.append("## Live hosts")
    for h in live:
        url = h.get("url", h.get("input", "?"))
        sc = h.get("status_code", h.get("status-code", ""))
        title = h.get("title", "")
        tech = ", ".join(h.get("tech", h.get("technologies", []) or []))
        lines.append(f"- `{url}` ({sc}) {title} {('['+tech+']') if tech else ''}")
    lines.append("")
    if findings:
        lines.append("## Findings")
        for fdg in findings:
            info = fdg.get("info", {})
            sev = info.get("severity", "unknown").upper()
            name = info.get("name", fdg.get("template-id", "finding"))
            matched = fdg.get("matched-at", fdg.get("host", ""))
            lines.append(f"- **[{sev}]** {name} — `{matched}`")
    else:
        lines.append("## Findings\nNo issues matched the selected severity. ✅")
    lines.append("")
    md = "\n".join(lines)
    md_path = os.path.join(outdir, f"scan-{ts}.md")
    with open(md_path, "w") as f:
        f.write(md)
    print(f"[+] Report written:\n    {md_path}\n    {json_path}")
    crit = tally.get("critical", 0)
    high = tally.get("high", 0)
    summary = (f"Scan {ts}\nLive hosts: {len(live)}\n"
               f"Findings: {len(findings)} (critical: {crit}, high: {high})")
    return summary


def notify_telegram(summary):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        return
    import urllib.parse
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode({"chat_id": chat, "text": "[scan] " + summary}).encode()
    try:
        with urllib.request.urlopen(url, data=payload, timeout=15) as r:
            r.read()
        print("[+] Telegram summary sent.")
    except Exception as e:
        print(f"[!] Telegram send failed: {e}")


def main():
    ap = argparse.ArgumentParser(
        description="Cloud Asset Scanner — attack-surface monitor for AUTHORIZED targets.")
    ap.add_argument("-t", "--targets", default="targets.txt")
    ap.add_argument("-o", "--outdir", default="reports")
    ap.add_argument("-s", "--severity", default="low,medium,high,critical")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="confirm you OWN or are AUTHORIZED to test every listed target")
    args = ap.parse_args()
    print(__doc__)
    if not args.i_am_authorized:
        print("[!] Refusing to run without authorization confirmation.")
        print("    Re-run with --i-am-authorized ONLY if you own or are")
        print("    explicitly authorized to test every target in your list.")
        sys.exit(2)
    httpx_bin = which_or_die("httpx-toolkit", "apt install httpx-toolkit (Kali)  OR  pipx install httpx")
    nuclei_bin = which_or_die("nuclei", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    workdir = os.path.join(args.outdir, ".work")
    os.makedirs(workdir, exist_ok=True)
    targets = read_targets(args.targets)
    live = probe_live(httpx_bin, targets, workdir)
    live_urls = [h.get("url") for h in live if h.get("url")]
    findings = scan_vulns(nuclei_bin, live_urls, workdir, args.severity)
    summary = build_report(live, findings, args.outdir)
    notify_telegram(summary)
    print("\n[+] Done.\n" + summary)


if __name__ == "__main__":
    main()
