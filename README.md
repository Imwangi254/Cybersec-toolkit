| `agentgate/` | Python | Authorization + audit control plane that vets and logs every action an AI agent takes |
## agentgate

An authorization and audit control plane for AI agents. It sits between an agent and the tools it can call, and decides — per action — whether that action is allowed, needs a human's approval, or should be blocked, writing every decision to a tamper-evident log. Where the recon and scanner tools ask "is this system exposed?", AgentGate asks "should this agent be allowed to do this at all?"

### What it does
- Intercepts every tool call an agent wants to make and evaluates it against a set of policies before it runs
- Ships three policies, each mapped to a named OWASP LLM risk:
  - **Tool allowlist** (default-deny): only explicitly permitted tools may run — blocks over-permissioned agents
  - **Data egress**: blocks actions whose arguments carry emails, secrets, or card-like numbers
  - **Human approval**: high-impact actions (delete, transfer, deploy) pause for a person to approve
- Combines policy verdicts with "most restrictive wins", so a single deny blocks the action
- Records every decision in a SHA-256 hash-chained provenance log that can be verified for tampering
- Framework-agnostic core with adapters: a plain `@guard` decorator for any Python function, and a LangChain tool wrapper

### Usage
cd agentgate
pip install -e '.[dev]'
python examples/plain_example.py
pytest -q

### What I learned
- Authorization vs authentication: this tool answers "what is this agent *allowed to do*", the same question IAM asks of users in the cloud
- Default-deny as a security posture — allowlisting is safer than blocklisting because the unknown case is blocked, not permitted
- Tamper-evident logging with hash chaining: each log entry embeds the hash of the previous one, so any edit to the past breaks the chain
- Designing a neutral core with pluggable adapters, so the tool isn't locked to one AI framework
- Least privilege in practice, the hard way: pushing this repo, a scoped access token *refused* to write CI workflow files without the right permission — the exact principle AgentGate enforces on agents, enforced on me
