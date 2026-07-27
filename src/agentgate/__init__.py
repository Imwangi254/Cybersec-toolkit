"""AgentGate — an authorization + audit control plane for AI agent actions.

Quickstart:

    from agentgate import Broker, ToolAllowlistPolicy, ApprovalPolicy
    from agentgate.integrations.plain import guard

    broker = Broker([
        ToolAllowlistPolicy(allowed_tools={"search", "read_file"}),
        ApprovalPolicy(),  # high-impact tools need a human
    ])

    @guard(broker)
    def search(query): ...

The core is framework-agnostic; adapters in ``agentgate.integrations`` plug it
into specific agent frameworks (e.g. LangChain).
"""

from .action import Action
from .approval import ApprovalHandler, AutoDenyApprovalHandler, CLIApprovalHandler
from .broker import ActionDenied, Broker
from .decision import Decision, Effect
from .policy import (
    ApprovalPolicy,
    DataEgressPolicy,
    Policy,
    ToolAllowlistPolicy,
)
from .provenance import ProvenanceLog

__version__ = "0.0.1"

__all__ = [
    "Action",
    "Broker",
    "ActionDenied",
    "Decision",
    "Effect",
    "Policy",
    "ToolAllowlistPolicy",
    "DataEgressPolicy",
    "ApprovalPolicy",
    "ProvenanceLog",
    "ApprovalHandler",
    "AutoDenyApprovalHandler",
    "CLIApprovalHandler",
]
