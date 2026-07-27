"""Policies: pluggable rules that vote on a proposed Action.

Each policy looks at an Action and returns a Decision. The Broker collects
all decisions and takes the most restrictive one. This is deliberately simple
and pure-Python so the skeleton has no external policy-engine dependency; in a
real deployment you'd back this with OPA/Rego or Cedar for the heavy policies
while keeping this same interface.

The three starter policies map directly to named OWASP LLM risks so the wedge
is legible to a security buyer:

    ToolAllowlistPolicy  -> LLM06 Excessive Agency / unauthorized tool use
    DataEgressPolicy     -> sensitive-data exfiltration
    ApprovalPolicy       -> human-in-the-loop for high-impact actions
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from re import Pattern

from .action import Action
from .decision import Decision


class Policy:
    """Base class. Subclass and implement ``evaluate``."""

    name: str = "policy"

    def evaluate(self, action: Action) -> Decision:  # pragma: no cover - abstract
        raise NotImplementedError


class ToolAllowlistPolicy(Policy):
    """Only permit tools that are explicitly allowlisted for the agent.

    Default-deny: if a tool is not on the list, it is blocked. This is the
    single most valuable control for over-permissioned agents.
    """

    name = "tool_allowlist"

    def __init__(self, allowed_tools: Iterable[str]):
        self._allowed = set(allowed_tools)

    def evaluate(self, action: Action) -> Decision:
        if action.tool in self._allowed:
            return Decision.allow(f"tool '{action.tool}' is allowlisted", self.name)
        return Decision.deny(f"tool '{action.tool}' is not on the allowlist", self.name)


class DataEgressPolicy(Policy):
    """Block actions whose arguments contain sensitive data patterns.

    Ships with a few sane defaults (emails, obvious secrets, long digit runs
    that look like card/account numbers). Extend ``patterns`` for your domain.
    """

    name = "data_egress"

    _DEFAULTS: dict[str, str] = {
        "email": r"[\w.+-]+@[\w-]+\.[\w.-]+",
        "credit_card_like": r"\b(?:\d[ -]?){13,19}\b",
        "secret_key": r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*\S+",
    }

    def __init__(self, patterns: dict[str, str] | None = None):
        raw = patterns if patterns is not None else self._DEFAULTS
        self._patterns: dict[str, Pattern[str]] = {
            label: re.compile(rx) for label, rx in raw.items()
        }

    def evaluate(self, action: Action) -> Decision:
        blob = " ".join(str(v) for v in action.args.values())
        for label, rx in self._patterns.items():
            if rx.search(blob):
                return Decision.deny(f"argument matched sensitive pattern '{label}'", self.name)
        return Decision.allow("no sensitive data detected in arguments", self.name)


class ApprovalPolicy(Policy):
    """Require a human's approval for high-impact tools.

    ``predicate`` decides whether an action is high-impact. By default we treat
    any tool whose name matches a set of dangerous verbs as high-impact.
    """

    name = "approval"

    _DANGEROUS = re.compile(r"(?i)(delete|drop|transfer|pay|deploy|revoke|shutdown|wire)")

    def __init__(self, predicate: Callable[[Action], bool] | None = None):
        self._predicate = predicate or (lambda a: bool(self._DANGEROUS.search(a.tool)))

    def evaluate(self, action: Action) -> Decision:
        if self._predicate(action):
            return Decision.require_approval(
                f"tool '{action.tool}' is high-impact and needs human approval",
                self.name,
            )
        return Decision.allow("action is not high-impact", self.name)
