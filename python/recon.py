import requests
import whois

def grab_headers(domain):
    print("=" * 50)
    print("HTTP HEADERS")
    print("=" * 50)
    url = "https://" + domain
    try:
        response = requests.get(url, timeout=15)
    except requests.exceptions.RequestException as error:
        print("[!] Could not connect to", url)
        print("[!] Reason:", error)
        return
    if "Server" in response.headers:
        print("[i] Server software:", response.headers["Server"])
    security_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]
    for header in security_headers:
        if header not in response.headers:
            print("[-] Missing security header:", header)

def whois_lookup(domain):
    print("=" * 50)
    print("WHOIS")
    print("=" * 50)
    try:
        result = whois.whois(domain)
    except Exception as error:
        print("[!] WHOIS lookup failed:", error)
        return
    if result.registrar is None and result.creation_date is None:
        print("[!] No WHOIS record found for", domain)
        return
    print("Registrar:", result.registrar)
    print("Creation date:", result.creation_date)
    print("Expiration date:", result.expiration_date)
    if result.name_servers:
        print("Name servers:")
        for ns in result.name_servers:
            print("  -", ns)

def find_subdomains(domain):
    print("=" * 50)
    print("SUBDOMAINS")
    print("=" * 50)
    url = "https://crt.sh/?q=" + domain + "&output=json"
    try:
        response = requests.get(url, timeout=30)
    except requests.exceptions.RequestException as error:
        print("[!] Request to crt.sh failed:", error)
        return
    try:
        data = response.json()
    except Exception:
        print("[!] Could not read data from crt.sh (down or no results).")
        return
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
    if subdomains:
        for sub in sorted(subdomains):
            print(sub)
        print("Total unique subdomains:", len(subdomains))
    else:
        print("(no subdomains found)")

# --- main ---
domain = input("Enter the domain to recon (e.g. example.com): ")
grab_headers(domain)
whois_lookup(domain)
find_subdomains(domain)
