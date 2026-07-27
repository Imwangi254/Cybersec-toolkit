"""The unit of everything AgentGate evaluates: an intended Action.

An Action is a *proposed* tool call an agent wants to make. It has not
happened yet. The Broker inspects it, policies vote on it, and only if the
final decision is ALLOW does the underlying tool actually run.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Action:
    """A proposed action an agent wants to take.

    Attributes:
        tool: Name of the tool/function the agent wants to invoke.
        args: Arguments the agent wants to pass to it.
        agent_id: Which agent (or agent run) is requesting this. Used for
            per-agent policy and for attribution in the audit log.
        principal: On whose authority the agent is acting (e.g. the end user
            or service account). Central to "under whose authority?".
        metadata: Free-form context (session id, environment, risk tags...).
        id: Unique id for this action, used to correlate the request with its
            decision and its provenance record.
        ts: Unix timestamp when the action was proposed.
    """

    tool: str
    args: Mapping[str, Any] = field(default_factory=dict)
    agent_id: str = "default"
    principal: str = "unknown"
    metadata: Mapping[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ts: float = field(default_factory=time.time)

    def summary(self) -> str:
        return f"{self.agent_id} -> {self.tool}({', '.join(self.args)})"
