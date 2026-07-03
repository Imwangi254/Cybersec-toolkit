import requests

url = input("Enter the URL to scan (e.g. https://example.com): ")

try:
    response = requests.get(url)
except requests.exceptions.RequestException as error:
    print("[!] Could not connect to", url)
    print("[!] Reason:", error)
    exit()

print("-" * 40)
print("Headers for:", url)
print("-" * 40)

for name, value in response.headers.items():
    print(name, ":", value)

print("-" * 40)
print("Findings:")

if "Server" in response.headers:
    print("[i] Server software:", response.headers["Server"])

security_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]

for header in security_headers:
    if header not in response.headers:
        print("[-] Missing security header:", header)
