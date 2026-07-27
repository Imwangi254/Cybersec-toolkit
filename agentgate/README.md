# AgentGate

**A safety gatekeeper for AI assistants.**

People are building AI "agents" — AI that doesn't just chat, but actually *does* things: sends emails, deletes files, moves money, changes settings. That's powerful, but risky. If the AI makes a mistake or gets tricked by an attacker, it could do real damage — and you might not even know what it did.

AgentGate sits between the AI and everything it can touch, like a security guard at a door. Every time the AI tries to *do* something, AgentGate checks:

1. **Are you allowed to do this?** The AI can only use tools on an approved list — anything else is blocked.
2. **Is this risky?** Dangerous actions (like deleting data or sending money) pause and wait for a human to approve.
3. **Is it recorded?** Every action is written to a tamper-proof logbook, so you can always see exactly what the AI did — and no one can secretly edit the record.

Think of how a bank won't let one teller move millions alone: big transfers need a manager's sign-off, and everything is logged. AgentGate gives AI agents those same guardrails.

---

## How it works (the technical version)

An authorization + audit control plane for AI agent actions. It enforces which actions are allowed, with what data, under whose authority — with a tamper-evident audit log.

- Framework-agnostic core (Action, Broker, Decision, Policy)
- OWASP-LLM-mapped policies: tool allowlist, data egress, human approval
- Hash-chained provenance log
- Adapters: plain `@guard` decorator + LangChain wrapper

## Usage

    pip install -e '.[dev]'
    python examples/plain_example.py
    pytest -q

## What I learned

- Authorization vs authentication: this answers "what is this agent allowed to do" — the same question IAM asks of users in the cloud
- Default-deny as a security posture: an allowlist is safer than a blocklist because the unknown case is blocked, not permitted
- Tamper-evident logging with hash chaining: each log entry embeds the hash of the one before it, so editing the past breaks the chain
- Designing a neutral core with pluggable adapters, so the tool isn't locked to one AI framework
- Least privilege the hard way: pushing this repo, a scoped token refused to write CI files without the right permission — the exact principle AgentGate enforces on agents, enforced on me
