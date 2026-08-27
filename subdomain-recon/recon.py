#!/usr/bin/env python3
"""
recon.py — Subdomain enumeration + live-host probing
    subfinder  ->  <domain>.txt        (all discovered subdomains)
    httpx      ->  <domain>_live.txt   (only the ones that respond over HTTP/S)
Author: Peter Ndirangu (Imwangi254)  |  AH200 recon assignment
"""
import argparse, os, shutil, subprocess, sys

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

def which_tool(*candidates):
    for name in candidates:
        if shutil.which(name):
            return name
    return None

def run_subfinder(domain, outfile):
    print(f"[*] Enumerating subdomains for {domain} with subfinder ...")
    subfinder = which_tool("subfinder")
    if subfinder is None:
        print("[!] subfinder not found. Install: sudo apt install subfinder")
        sys.exit(1)
    try:
        subprocess.run([subfinder, "-d", domain, "-silent", "-o", outfile],
                       check=True, timeout=600)
    except subprocess.CalledProcessError as e:
        print(f"[!] subfinder error (code {e.returncode}).")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[!] subfinder timed out.")
        sys.exit(1)
    if not os.path.exists(outfile) or os.path.getsize(outfile) == 0:
        print("[!] No subdomains found. Nothing to probe — exiting.")
        sys.exit(0)
    with open(outfile) as f:
        count = sum(1 for line in f if line.strip())
    print(f"[+] Found {count} subdomains -> saved to {outfile}")
    return count

def run_httpx(infile, outfile):
    print("[*] Probing for live hosts with httpx ...")
    httpx = which_tool("httpx-toolkit", "httpx")
    if httpx is None:
        print("[!] httpx not found. Install: sudo apt install httpx-toolkit")
        sys.exit(1)
    try:
        subprocess.run([httpx, "-l", infile, "-silent", "-o", outfile],
                       check=True, timeout=600)
    except subprocess.CalledProcessError as e:
        print(f"[!] httpx error (code {e.returncode}).")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[!] httpx timed out.")
        sys.exit(1)
    live = []
    if os.path.exists(outfile):
        with open(outfile) as f:
            live = [line.strip() for line in f if line.strip()]
    print(f"[+] {len(live)} live hosts -> saved to {outfile}")
    if live:
        print("[*] Sample of live hosts:")
        for host in live[:5]:
            print(f"      - {host}")
        if len(live) > 5:
            print(f"      ... and {len(live) - 5} more")
    return live

def notify_telegram(message):
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        print("[!] Telegram not configured. Skipping notification.")
        return
    try:
        import requests
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        resp = requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": message}, timeout=15)
        if resp.status_code == 200:
            print("[+] Telegram notification sent.")
        else:
            print(f"[!] Telegram responded {resp.status_code}: {resp.text[:120]}")
    except Exception as e:
        print(f"[!] Could not send Telegram notification: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Enumerate subdomains (subfinder) and probe live hosts (httpx).")
    parser.add_argument("-d", "--domain", required=True, help="Target domain, e.g. vulnweb.com")
    parser.add_argument("-o", "--output", help="Output prefix (default: domain name)")
    parser.add_argument("--notify", action="store_true", help="Send a Telegram summary.")
    args = parser.parse_args()
    prefix = args.output if args.output else args.domain
    out_dir = os.path.dirname(prefix)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    all_file = f"{prefix}.txt"
    live_file = f"{prefix}_live.txt"
    print(f"[*] Starting recon on: {args.domain}")
    total = run_subfinder(args.domain, all_file)
    live = run_httpx(all_file, live_file)
    print("[/] Recon complete.")
    print(f"    All subdomains : {all_file}  ({total})")
    print(f"    Live hosts     : {live_file}  ({len(live)})")
    if args.notify:
        summary = (f"Recon finished for {args.domain}\n"
                   f"Subdomains found: {total}\nLive hosts: {len(live)}")
        notify_telegram(summary)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
        sys.exit(130)
