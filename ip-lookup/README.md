# IP Intelligence Lookup

A Python tool that looks up geolocation and network ownership information
for an IP address by calling the free ip-api.com REST API. Built to learn
how to consume a REST API and parse JSON, and useful for enriching IPs
flagged by other tools (e.g. attacker IPs from the log detector).

## What it does

- Takes an IP address as input.
- Sends a GET request to the ip-api.com REST API.
- Parses the JSON response.
- Reports country, region, city, ISP, organisation, network (ASN), and
  coordinates.
- Flags IPs owned by hosting/cloud providers, which are common sources of
  automated attacks.

## Usage

    python3 iplookup.py <ip_address>

Example:

    python3 iplookup.py 8.8.8.8

## How it works (the REST API cycle)

1. Build the endpoint URL with the IP as a parameter.
2. Send an HTTP GET request.
3. The API returns structured data as JSON.
4. Parse the JSON into a dictionary and read the fields.
5. Check the status field to handle failures gracefully.

## Security use case

Pairs naturally with the log detector: when the detector flags an IP as an
attacker, this tool enriches it with location and ownership context - the
kind of threat-intelligence lookup a SOC analyst performs routinely.

## What I learned

- What a REST API is and how to consume one (endpoint, GET request, response).
- Parsing JSON responses into usable data with requests and .json().
- Reading a status field to distinguish success from failure.
- No API key needed here, but where a key is required it must never be
  committed to version control.
- Enriching raw indicators (an IP) into actionable intelligence.

## Note

ip-api.com is free and requires no API key, but rate-limits unauthenticated
requests. For heavy use it offers a paid, keyed tier.
