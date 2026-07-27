"""Approval handlers: what to do when a policy says REQUIRE_APPROVAL.

The handler is pluggable so the same broker works in a notebook (prompt on the
CLI), in CI (auto-deny), or in production (send to Slack / a web approval queue
and block until a human clicks approve). Implement ``request`` to integrate.
"""

from __future__ import annotations

from typing import Protocol

from .action import Action


class ApprovalHandler(Protocol):
    def request(self, action: Action, reason: str) -> bool:
        """Return True to allow the action, False to deny it."""
        ...


class AutoDenyApprovalHandler:
    """Safe default for non-interactive contexts (CI, tests, servers).

    If no human is available to approve, the action is denied. Fail closed.
    """

    def request(self, action: Action, reason: str) -> bool:
        return False


class CLIApprovalHandler:
    """Prompt on the terminal. Useful for local development and demos."""

    def request(self, action: Action, reason: str) -> bool:
        print(f"\n[AgentGate] APPROVAL NEEDED: {action.summary()}")
        print(f"            reason: {reason}")
        answer = input("            approve this action? [y/N] ").strip().lower()
        return answer in {"y", "yes"}
