"""Decisions: the verdict returned for a proposed Action.

Three effects, in increasing order of permissiveness they DENY:
    DENY            -> block outright.
    REQUIRE_APPROVAL-> pause and ask a human before proceeding.
    ALLOW           -> let it run.

The Broker combines many policy decisions into one final decision using a
"most restrictive wins" rule, so a single DENY is enough to block an action.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Effect(enum.IntEnum):
    # Ordered so that max() picks the most restrictive effect.
    ALLOW = 0
    REQUIRE_APPROVAL = 1
    DENY = 2


@dataclass(frozen=True)
class Decision:
    effect: Effect
    reason: str
    policy: str = "unspecified"

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    @property
    def denied(self) -> bool:
        return self.effect is Effect.DENY

    @property
    def needs_approval(self) -> bool:
        return self.effect is Effect.REQUIRE_APPROVAL

    @classmethod
    def allow(cls, reason: str = "permitted", policy: str = "unspecified") -> Decision:
        return cls(Effect.ALLOW, reason, policy)

    @classmethod
    def deny(cls, reason: str, policy: str = "unspecified") -> Decision:
        return cls(Effect.DENY, reason, policy)

    @classmethod
    def require_approval(cls, reason: str, policy: str = "unspecified") -> Decision:
        return cls(Effect.REQUIRE_APPROVAL, reason, policy)
