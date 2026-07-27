from agentgate import (
    Action,
    ApprovalPolicy,
    Broker,
    DataEgressPolicy,
    Effect,
    ProvenanceLog,
    ToolAllowlistPolicy,
)
from agentgate.approval import AutoDenyApprovalHandler


def make_broker(**kw):
    return Broker(
        policies=[
            ToolAllowlistPolicy(allowed_tools={"search", "delete_thing"}),
            DataEgressPolicy(),
            ApprovalPolicy(),
        ],
        approval_handler=AutoDenyApprovalHandler(),
        provenance=ProvenanceLog(),
        **kw,
    )


def test_allowlisted_tool_is_allowed():
    b = make_broker()
    d = b.check(Action(tool="search", args={"q": "hi"}))
    assert d.allowed


def test_unlisted_tool_is_denied():
    b = make_broker()
    d = b.check(Action(tool="rm_rf", args={}))
    assert d.denied
    assert d.policy == "tool_allowlist"


def test_data_egress_blocks_email():
    b = make_broker()
    d = b.check(Action(tool="search", args={"q": "mail me at a@b.com"}))
    assert d.denied
    assert d.policy == "data_egress"


def test_high_impact_requires_approval_then_auto_denied():
    b = make_broker()  # AutoDeny -> approval turns into deny
    d = b.check(Action(tool="delete_thing", args={"id": "1"}))
    assert d.denied
    assert "human-denied" in d.reason


def test_most_restrictive_wins():
    # non-allowlisted AND high-impact: deny should beat require_approval
    b = make_broker()
    d = b.check(Action(tool="delete_secret", args={}))
    assert d.effect is Effect.DENY


def test_provenance_chain_is_verifiable():
    b = make_broker()
    b.check(Action(tool="search", args={"q": "a"}))
    b.check(Action(tool="nope", args={}))
    assert len(b.log) == 2
    assert b.log.verify() is True


def test_provenance_tamper_is_detected():
    b = make_broker()
    b.check(Action(tool="search", args={"q": "a"}))
    b.check(Action(tool="search", args={"q": "b"}))
    # Tamper with a past entry's reason without recomputing the hash chain.
    list(b.log)[0].reason = "edited after the fact"
    assert b.log.verify() is False
