import os
import stat
import subprocess

SENSITIVE_FILES = ["/etc/shadow", "/etc/gshadow"]
SSHD_CONFIG = "/etc/ssh/sshd_config"

RISKY_PORTS = {
    "21": "FTP (plaintext credentials)",
    "23": "Telnet (plaintext)",
    "3306": "MySQL database",
    "5432": "PostgreSQL database",
    "6379": "Redis (often unauthenticated)",
    "27017": "MongoDB database",
}

print("=== Misconfiguration Scanner ===")
print()
findings = 0

# ---- Check 1: sensitive file permissions ----
print("[*] Checking sensitive file permissions...")
for path in SENSITIVE_FILES:
    if not os.path.exists(path):
        continue
    mode = os.stat(path).st_mode
    if bool(mode & stat.S_IROTH):
        print(f"  [!] RISK: {path} is world-readable")
        findings += 1
    else:
        print(f"  [OK] {path} is properly restricted")

# ---- Check 2: SSH root login ----
print()
print("[*] Checking SSH root login policy...")

def get_active_setting(config_path, key):
    if not os.path.exists(config_path):
        return None
    with open(config_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split()
            if parts and parts[0].lower() == key.lower():
                return parts[1] if len(parts) > 1 else ""
    return None

root_login = get_active_setting(SSHD_CONFIG, "PermitRootLogin")
if root_login is None:
    print("  [WARN] PermitRootLogin not explicitly set - relying on default.")
    print("         Recommend 'PermitRootLogin no' for clarity.")
    findings += 1
elif root_login.lower() == "yes":
    print("  [!] RISK: PermitRootLogin is 'yes' - direct root SSH login allowed.")
    findings += 1
else:
    print(f"  [OK] PermitRootLogin is '{root_login}' - restricted.")

# ---- Check 3: services exposed on all interfaces ----
print()
print("[*] Checking for services exposed on all interfaces...")
try:
    output = subprocess.run(["ss", "-tln"], capture_output=True, text=True).stdout
    seen_ports = set()                         # avoid reporting the same port twice
    for line in output.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4:
            continue
        local = cols[3]
        if local.startswith("0.0.0.0:") or local.startswith("*:") or local.startswith("[::]:"):
            port = local.rsplit(":", 1)[-1]
            if port in seen_ports:
                continue                       # already reported this port
            seen_ports.add(port)
            if port in RISKY_PORTS:
                print(f"  [!] RISK: port {port} exposed on all interfaces - {RISKY_PORTS[port]}")
                findings += 1
            elif port == "22":
                print(f"  [INFO] SSH (port 22) exposed - expected, ensure it is hardened.")
            else:
                print(f"  [INFO] port {port} exposed on all interfaces - review if intended.")
except FileNotFoundError:
    print("  [SKIP] 'ss' command not available.")

# ---- Summary ----
print()
if findings == 0:
    print("[*] No issues found.")
else:
    print(f"[*] {findings} issue(s)/warning(s) found.")
