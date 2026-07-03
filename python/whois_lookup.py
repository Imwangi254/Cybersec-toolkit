import whois

domain = input("Enter the domain to look up (e.g. example.com): ")

try:
    result = whois.whois(domain)
except Exception as error:
    print("[!] WHOIS lookup failed for", domain)
    print("[!] Reason:", error)
    exit()

if result.registrar is None and result.creation_date is None:
    print("[!] No WHOIS record found for", domain)
    print("[!] The domain may not exist or has no public registration data.")
    exit()

print("-" * 40)
print("WHOIS Report for:", domain)
print("-" * 40)

print("Registrar:", result.registrar)
print("Creation date:", result.creation_date)
print("Expiration date:", result.expiration_date)
print("Updated date:", result.updated_date)

print("-" * 40)
print("Name servers:")
if result.name_servers:
    for ns in result.name_servers:
        print("  -", ns)
else:
    print("  (none found)")

print("-" * 40)
print("Findings:")

if result.emails:
    print("[i] Registrant emails exposed:", result.emails)
else:
    print("[i] Registrant contact info is redacted or private")
