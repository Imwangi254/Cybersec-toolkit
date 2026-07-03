import requests

domain = input("Enter the domain to enumerate (e.g. example.com): ")

url = "https://crt.sh/?q=" + domain + "&output=json"

try:
    response = requests.get(url, timeout=30)
except requests.exceptions.RequestException as error:
    print("[!] Request to crt.sh failed for", domain)
    print("[!] Reason:", error)
    exit()

try:
    data = response.json()
except Exception:
    print("[!] Could not read data from crt.sh (it may be down or returned no results).")
    exit()

subdomains = set()

for entry in data:
    names = entry["name_value"].split("\n")
    for name in names:
        name = name.strip()
        if " " in name:
            continue
        if "*" in name:
            continue
        if "@" in name:
            continue
        if name == domain:
            continue
        if name.endswith("." + domain):
            subdomains.add(name)

print("-" * 40)
print("Subdomains found for:", domain)
print("-" * 40)

if subdomains:
    for sub in sorted(subdomains):
        print(sub)
else:
    print("(no subdomains found)")

print("-" * 40)
print("Total unique subdomains:", len(subdomains))
