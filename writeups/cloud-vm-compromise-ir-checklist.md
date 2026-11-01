# Incident Response Playbook — Compromised Cloud VM & Identity

> Scenario: an internet-facing VM is breached via an open SSH port (22). The attacker reaches the instance metadata service, steals the VM's over-privileged managed identity (Owner on the resource group), and uses it to deploy rogue VMs for crypto-mining and/or inject malware.
>
> **Key principle:** closing port 22 only stops *new* entry. The attacker already holds the stolen identity — eradication is what actually removes them.
>
> Follows the NIST / SANS IR lifecycle: **Detect → Contain → Eradicate → Recover → Learn.**
> Author: Peter Mwangi (GitHub: Imwangi254)

---

## 0. Declare the incident & preserve evidence (first 15 minutes)
- [ ] Declare an incident; start a time-stamped incident log.
- [ ] **Snapshot the compromised VM's disk BEFORE changing anything** (forensic evidence).
- [ ] Capture running processes, network connections, logged-in users.
- [ ] Do **not** power off or wipe yet — preserve volatile evidence and the audit trail.

## 1. Contain — the identity first, then the network
- [ ] **Remove the Owner role assignment** from the VM's managed identity.
- [ ] **Disable the managed identity** (short-lived tokens then expire).
- [ ] **Rotate every secret in the blast radius:** storage keys, access keys, SAS tokens, service-principal secrets, VM passwords.
- [ ] **Revoke active sessions;** reset any touched user accounts.
- [ ] **Isolate the VM** (NSG deny-all in *and out*) so it can't reach the mining pool / C2 — cut **outbound**, not just port 22.

## 2. Eradicate — hunt everything the attacker left (check ALL regions)
- [ ] Find and isolate **rogue VMs** (snapshot, then remove).
- [ ] **Kill mining processes / malware** on the original host.
- [ ] Hunt persistence backdoors:
  - [ ] New users / SSH keys / local admins
  - [ ] New IAM/RBAC **role assignments**
  - [ ] New **service principals / app registrations**
  - [ ] Scheduled tasks, cron, startup/user-data scripts
  - [ ] Modified NSG/firewall rules, new public IPs
  - [ ] New Automation accounts, Functions, runbooks, storage
- [ ] Remove every attacker-created artifact.

## 3. Investigate — scope & impact
- [ ] Review the **cloud audit log** (Azure Activity Log / AWS CloudTrail).
- [ ] Review **sign-in logs**, **flow logs**, Defender / GuardDuty alerts.
- [ ] Build a **timeline**: entry → escalation → actions → impact.
- [ ] **Check for data exfiltration** (esp. public storage). Real data out = **breach** → notification obligations (Kenya DPA / GDPR).
- [ ] **Check billing** across all regions (denial-of-wallet); set a spend limit.

## 4. Recover — rebuild, don't just clean
- [ ] **Destroy and redeploy the VM from a known-good image** — never trust a compromised host.
- [ ] Restore data only from **pre-compromise backups**.
- [ ] Bring services back **with hardening applied** and extra monitoring.
- [ ] Re-enable access gradually; watch for re-compromise.

## 5. Root-cause fixes
- [ ] **Entry:** restrict SSH to a known admin IP / Bastion / VPN; keys not passwords; MFA.
- [ ] **Escalation:** replace the VM's **Owner** role with a least-privilege scoped role.
- [ ] Enforce **IMDSv2** so a future foothold can't trivially read the metadata service.
- [ ] Lock down storage: no public access, HTTPS-only, default-deny networking.

## 6. Detect better next time
- [ ] Alert on new role assignments & service principals.
- [ ] Alert on impossible-travel / anomalous sign-ins.
- [ ] Enable crypto-mining & threat detection (Defender / GuardDuty).
- [ ] Alert on cost spikes and resources in unused regions.
- [ ] Multi-region, tamper-evident audit logging on.

## 7. Post-incident
- [ ] Write the incident report (timeline, scope, impact, actions, root cause).
- [ ] Blameless lessons-learned review.
- [ ] Update playbook and detection rules.
- [ ] Notify stakeholders / legal / affected parties as required.

---

**One-line summary:** Closing port 22 stops new entry. Revoking the stolen identity, hunting rogue resources and backdoors, rebuilding compromised hosts, and checking for data theft across the whole environment is what actually removes the attacker.
