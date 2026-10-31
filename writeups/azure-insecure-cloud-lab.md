# Insecure Azure Environment — Cloud Security Assessment

> Hands-on lab: deploy a deliberately insecure Azure environment, identify and
> analyze three findings (Identity, Data, Network), and document remediation and
> prioritization. All data is fabricated; environment was torn down after evaluation.

**Author:** Peter Mwangi (GitHub: Imwangi254)
**Context:** Cloud Security
**Date:** October 2026
**Cloud:** Microsoft Azure · Region: Korea South

---

## Environment deployed (8 components)

| Component | Resource |
|-----------|----------|
| User | lab user (subscription owner) |
| Azure Tenant | Default Directory (Entra ID) |
| Subscription | Azure subscription 1 |
| Resource Group | rg-insecure-lab |
| Virtual Network | vnet-koreasouth-1 |
| Subnet | snet-koreasouth-1 (172.16.0.0/24) |
| Virtual Machine | vm-insecure (Ubuntu 24.04, public IP, password auth, system-assigned managed identity) |
| Storage Account | stinsecurelab (container: public-data) |

## Tooling note

ScoutSuite is multi-cloud. It ran successfully against AWS in a prior lab, but on
this Azure environment (`scout azure --cli`) it could not authenticate; Prowler was
blocked requesting a Microsoft Graph token (`AADSTS530035 — security defaults`); and
Microsoft Defender for Cloud initially showed "limited information". Root cause: a
personal (consumer) Azure account lacks Entra ID directory permissions. Granting the
user **Security Reader** (chosen over Security Admin, to follow least privilege)
restored Defender's visibility, which then flagged the resources. Findings were
identified by deliberate configuration + manual verification (portal + an anonymous
incognito retrieval test), and corroborated by Defender for Cloud.

## Findings

### 1. Over-privileged managed identity (IDENTITY)
- **What:** The VM's system-assigned managed identity holds the **Owner** role on `rg-insecure-lab`.
- **Exploitability:** Not reachable directly from the internet — reached *through the VM* if SSH is open (depends on Finding 2).
- **Blast radius:** Control of the whole resource group — delete/change everything, read storage keys, inject scripts, spin up VMs to mine crypto on the account's bill (denial-of-wallet).
- **Remediation:** Give the identity a small, scoped role instead of Owner.

### 2. SSH open to the internet (NETWORK)
- **What:** NSG allows inbound TCP 22 from 0.0.0.0/0 to a VM with a public IP and password auth.
- **Exploitability:** Easy — internet-facing SSH is scanned/brute-forced constantly; no key, no MFA.
- **Blast radius:** Attacker breaks into the VM, then reaches the metadata service to acquire the Owner identity → control of the whole resource group (chains into Finding 1).
- **Remediation:** Restrict port 22 to a known admin IP (or remove the public IP / use Bastion) and use SSH keys.

### 3. Public anonymous storage (DATA)
- **What:** Storage account allows public network access from all networks, anonymous blob access, and HTTPS-only is off; container `public-data` allows anonymous read.
- **Exploitability:** Very easy — copy the blob URL and read it, no login (proven via incognito).
- **Blast radius:** Anyone can read/download every file in the container; HTTP allowed means data can be intercepted in transit.
- **Remediation:** Disable anonymous access and public network access (default Deny), enforce HTTPS-only.

## Prioritization

| Rank | Finding | Reasoning |
|------|---------|-----------|
| P1 | 2 — SSH open (Network) | The front door; closing it breaks the attack chain and buys time to fix the rest. |
| P2 | 3 — Public blob (Data) | Data is leaking right now with zero attacker effort. |
| P3 | 1 — Owner identity (Identity) | Worst blast radius, but only reachable after the VM is breached — and only after removing any miners/malware already deployed. |

**Attack chain:** `Open SSH (F2) → break into VM → steal Owner identity (F1) → control the whole resource group`. The small door (SSH) unlocks the worst outcome, so it is fixed first.

## Key lessons
1. A finding's danger is not just its own blast radius but *what it chains to*.
2. Tooling behaves differently by account type — personal Azure tenants lack the directory permissions scanners expect.
3. Least privilege applies everywhere — including choosing **Security Reader** over Security Admin for my own access.

---

*Diagram: see `azure-insecure-cloud-lab-architecture.png` in this folder.*
