import requests
import sys

def lookup_ip(ip):
    """Query ip-api.com for geolocation and network info about an IP."""
    url = f"http://ip-api.com/json/{ip}"
    try:
        r = requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return

    # parse the JSON response into a Python dictionary
    data = r.json()

    # the API tells us success or failure in the 'status' field
    if data.get("status") != "success":
        print(f"[!] Lookup failed: {data.get('message', 'unknown error')}")
        return

    # pull out the fields we care about
    print(f"\n=== IP Intelligence: {data.get('query')} ===")
    print(f"  Country:  {data.get('country')} ({data.get('countryCode')})")
    print(f"  Region:   {data.get('regionName')}")
    print(f"  City:     {data.get('city')}")
    print(f"  ISP:      {data.get('isp')}")
    print(f"  Org:      {data.get('org')}")
    print(f"  Network:  {data.get('as')}")
    print(f"  Coords:   {data.get('lat')}, {data.get('lon')}")

    # a simple security note: hosting/cloud ISPs are common attack sources
    isp = (data.get("isp") or "").lower()
    hosting_keywords = ["hosting", "cloud", "server", "vps", "digital ocean", "ovh", "amazon", "google"]
    if any(k in isp for k in hosting_keywords):
        print("  [i] Note: hosting/cloud provider - common source of automated attacks")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 iplookup.py <ip_address>")
        print("Example: python3 iplookup.py 8.8.8.8")
        sys.exit(1)

    lookup_ip(sys.argv[1])
