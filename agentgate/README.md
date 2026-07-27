# AgentGate

An authorization + audit control plane for AI agent actions. Sits between an AI
agent and the tools/data it can touch, and enforces which actions are allowed,
with what data, under whose authority — with a tamper-evident audit log.

- Framework-agnostic core (Action, Broker, Decision, Policy)
- OWASP-LLM-mapped policies: tool allowlist, data egress, human approval
- Hash-chained provenance log
- Adapters: plain `@guard` decorator + LangChain wrapper

Run the demo:

    pip install -e '.[dev]'
    python examples/plain_example.py
    pytest -q
