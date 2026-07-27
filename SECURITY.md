# Security Policy

AgentGate is a security tool, so we hold our own project to the standard we
help others meet. If you find a vulnerability, we want to hear about it.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, report privately via one of:

- GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository (preferred), or
- email **security@your-domain.example** with details.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal proof-of-concept is ideal),
- affected version(s) or commit,
- any suggested remediation.

## What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity rating within 10 business days.
- Coordinated disclosure: we'll agree a timeline with you, fix the issue, and
  credit you in the release notes unless you prefer to remain anonymous.

## Scope

In scope: the AgentGate library and its official adapters.

Out of scope: vulnerabilities in third-party dependencies (report those
upstream), and issues that require an already-compromised host.

## A note on what AgentGate is and isn't

AgentGate reduces the blast radius of AI agents by authorizing and logging their
actions. It is a control layer, **not** a guarantee. It should be deployed as
one part of defense in depth — alongside least-privilege credentials, network
controls, and monitoring — never as a sole safeguard. Treat any policy as
bypassable until proven otherwise, and design your credentials and blast radius
accordingly.
