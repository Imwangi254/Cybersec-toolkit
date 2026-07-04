from datetime import datetime
import os

LOG_FILE = "auth.log"
ALERT_FILE = "alerts.log"
SEEN_FILE = "seen_alerts.txt"
THRESHOLD = 5
WINDOW_SECONDS = 120

def parse_time(parts):
    timestr = "2025 " + " ".join(parts[0:3])
    return datetime.strptime(timestr, "%Y %b %d %H:%M:%S")

# load the memory of alerts we've already raised
if os.path.exists(SEEN_FILE):
    with open(SEEN_FILE, "r") as sf:
        seen = set(line.strip() for line in sf)
else:
    seen = set()

def raise_alert(alert_id, message):
    if alert_id in seen:
        return False                       # already reported - stay quiet
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] {message}"
    print(" ", line)
    with open(ALERT_FILE, "a") as af:
        af.write(line + "\n")
    with open(SEEN_FILE, "a") as sf:       # remember we raised this one
        sf.write(alert_id + "\n")
    seen.add(alert_id)
    return True

# --- read the log ---
fails_by_ip = {}
success_by_ip = {}
with open(LOG_FILE, "r") as f:
    for line in f:
        line = line.strip()
        parts = line.split()
        if "Failed password" in line:
            ip = parts[parts.index("from") + 1]
            fails_by_ip.setdefault(ip, []).append(parse_time(parts))
        elif "Accepted password" in line:
            ip = parts[parts.index("from") + 1]
            user = parts[parts.index("for") + 1]
            success_by_ip.setdefault(ip, []).append((parse_time(parts), user))

# --- apply rules ---
print("ALERTS:")
new_alerts = 0

for ip, times in fails_by_ip.items():
    times.sort()
    for i in range(len(times)):
        window = [t for t in times if 0 <= (t - times[i]).total_seconds() <= WINDOW_SECONDS]
        if len(window) >= THRESHOLD:
            span = (window[-1] - window[0]).total_seconds()
            if raise_alert(f"BRUTE-FORCE:{ip}",
                           f"[!] BRUTE-FORCE: {ip} had {len(window)} failures in {int(span)}s"):
                new_alerts += 1
            break

for ip, successes in success_by_ip.items():
    fail_count = len(fails_by_ip.get(ip, []))
    if fail_count >= THRESHOLD:
        for (t, user) in successes:
            if raise_alert(f"BREACH:{ip}:{user}",
                           f"[!!!] POSSIBLE BREACH: {ip} succeeded as '{user}' after {fail_count} failures"):
                new_alerts += 1

if new_alerts == 0:
    print("  (no new alerts)")
else:
    print(f"--- {new_alerts} NEW alert(s) written to {ALERT_FILE}")
