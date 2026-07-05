import hashlib
import os
import json
import sys

WATCHED_FILES = [
    "testfile.txt",
    "/etc/hosts",
    "/etc/passwd",
]

BASELINE_FILE = "baseline.json"

def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def create_baseline():
    baseline = {}
    for path in WATCHED_FILES:
        file_hash = hash_file(path)
        if file_hash:
            baseline[path] = file_hash
            print(f"  [+] Recorded: {path}")
        else:
            print(f"  [skip] Could not read: {path}")
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"\n[*] Baseline saved to {BASELINE_FILE} ({len(baseline)} files)")

def check_integrity():
    if not os.path.exists(BASELINE_FILE):
        print("[!] No baseline found. Run 'python3 fim.py baseline' first.")
        return

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    changes = 0
    for path in WATCHED_FILES:
        current = hash_file(path)
        recorded = baseline.get(path)

        if current is None:
            print(f"  [MISSING] {path} - cannot read (deleted or permission lost!)")
            changes += 1
        elif recorded is None:
            print(f"  [NEW] {path} - not in baseline (run baseline to record it)")
            changes += 1
        elif current == recorded:
            print(f"  [OK] {path}")
        else:
            print(f"  [MODIFIED] {path} - HASH CHANGED, file was tampered with!")
            changes += 1

    print()
    if changes == 0:
        print("[*] All files intact. No changes detected.")
    else:
        print(f"[!] {changes} change(s) detected - investigate immediately.")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"

    if mode == "baseline":
        print("=== File Integrity Monitor: creating baseline ===")
        create_baseline()
    elif mode == "check":
        print("=== File Integrity Monitor: checking integrity ===")
        check_integrity()
    else:
        print("Usage: python3 fim.py [baseline|check]")
