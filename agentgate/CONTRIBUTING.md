# Contributing to AgentGate

Thanks for your interest. This is an early-stage project; the fastest way to
help is to try it against a real agent and tell us where it falls short.

## Development setup

```bash
git clone https://github.com/your-org/agentgate
cd agentgate
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,langchain]'
pytest -q
```

Run the examples to see it end to end:

```bash
python examples/plain_example.py
python examples/langchain_example.py
```

## Before you open a PR

- `pytest -q` passes.
- `ruff check .` and `ruff format .` are clean.
- New behavior has a test. Security logic without a test won't be merged.
- Keep the **core dependency-free.** Anything heavier goes behind an optional
  extra in `pyproject.toml` (like the `langchain` extra) and imports lazily.

## The two most useful kinds of contribution

### Add a policy

Subclass `Policy`, implement `evaluate(action) -> Decision`, and map it to a
named OWASP LLM risk in the README table. Keep policies pure and side-effect
free — they vote, they don't act.

```python
from agentgate.policy import Policy
from agentgate.decision import Decision

class RateLimitPolicy(Policy):
    name = "rate_limit"
    def evaluate(self, action):
        ...
        return Decision.deny("too many calls this minute", self.name)
```

### Add an adapter

Adapters live in `agentgate/integrations/`. An adapter's only job is to turn a
framework's tool call into an `Action`, route it through `Broker.enforce` (or
`Broker.check`), and translate a denial into whatever that framework expects.
Import the framework lazily so it stays an optional extra. See
`integrations/langchain.py` as the reference implementation.

## Design principles

1. **The core is neutral.** It knows nothing about any model or framework.
2. **Fail closed.** When in doubt, deny. An unavailable approver means denial.
3. **Everything is logged.** No decision escapes the provenance log.
4. **Legible to security buyers.** Controls map to named, recognized risks.

## Reporting security issues

Do **not** use the public issue tracker. See [SECURITY.md](SECURITY.md).
