"""The Broker: the heart of AgentGate.

Given a proposed Action it:
  1. asks every policy to vote,
  2. combines votes with "most restrictive wins",
  3. if approval is required, asks the ApprovalHandler,
  4. records the final decision in the tamper-evident ProvenanceLog,
  5. returns the final Decision.

Everything else in the library is an adapter that turns some framework's tool
call into an Action and routes it through ``Broker.check``.
"""

from __future__ import annotations

from collections.abc import Sequence

from .action import Action
from .approval import ApprovalHandler, AutoDenyApprovalHandler
from .decision import Decision, Effect
from .policy import Policy
from .provenance import ProvenanceLog


class ActionDenied(Exception):
    """Raised when a guarded tool is called but the broker denies it."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"[{decision.policy}] {decision.reason}")


class Broker:
    def __init__(
        self,
        policies: Sequence[Policy],
        approval_handler: ApprovalHandler | None = None,
        provenance: ProvenanceLog | None = None,
    ):
        self._policies = list(policies)
        self._approvals = approval_handler or AutoDenyApprovalHandler()
        self._log = provenance or ProvenanceLog()

    @property
    def log(self) -> ProvenanceLog:
        return self._log

    def check(self, action: Action) -> Decision:
        """Evaluate an action and return the final, logged decision."""
        decisions = [p.evaluate(action) for p in self._policies] or [
            Decision.allow("no policies configured", "broker")
        ]
        # Most restrictive wins: pick the decision with the highest effect.
        final = max(decisions, key=lambda d: d.effect)

        # Resolve approval into a concrete allow/deny via the handler.
        if final.effect is Effect.REQUIRE_APPROVAL:
            granted = self._approvals.request(action, final.reason)
            final = (
                Decision.allow(f"human-approved: {final.reason}", final.policy)
                if granted
                else Decision.deny(f"human-denied: {final.reason}", final.policy)
            )

        self._log.record(action, final)
        return final

    def enforce(self, action: Action) -> None:
        """Like ``check`` but raises ``ActionDenied`` if not allowed."""
        decision = self.check(action)
        if not decision.allowed:
            raise ActionDenied(decision)
