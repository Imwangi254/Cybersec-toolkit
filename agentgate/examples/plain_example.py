"""Run me:  python examples/plain_example.py

Demonstrates AgentGate guarding plain Python tools with no agent framework:
  - an allowlisted tool runs,
  - a non-allowlisted tool is blocked,
  - a tool carrying sensitive data is blocked,
  - a high-impact tool triggers human approval,
  - and the whole thing produces a verifiable audit trail.
"""

from agentgate import (
    ApprovalPolicy,
    Broker,
    DataEgressPolicy,
    ToolAllowlistPolicy,
)
from agentgate.approval import AutoDenyApprovalHandler
from agentgate.broker import ActionDenied
from agentgate.integrations.plain import guard

# In a demo we auto-deny approvals so it runs non-interactively. Swap in
# CLIApprovalHandler() to approve/deny live at the terminal.
broker = Broker(
    policies=[
        ToolAllowlistPolicy(allowed_tools={"search_web", "read_doc", "delete_record"}),
        DataEgressPolicy(),
        ApprovalPolicy(),  # 'delete_record' matches the high-impact verbs
    ],
    approval_handler=AutoDenyApprovalHandler(),
)


@guard(broker, principal="user:alice")
def search_web(query: str) -> str:
    return f"results for {query!r}"


@guard(broker, principal="user:alice")
def read_doc(doc_id: str) -> str:
    return f"contents of {doc_id}"


@guard(broker, principal="user:alice")
def exfiltrate(note: str) -> str:  # not allowlisted -> always denied
    return "sent"


@guard(broker, principal="user:alice")
def delete_record(record_id: str) -> str:  # high-impact -> needs approval
    return f"deleted {record_id}"


def try_call(label: str, fn, *args):
    try:
        print(f"[OK]    {label}: {fn(*args)}")
    except ActionDenied as e:
        print(f"[BLOCK] {label}: {e}")


if __name__ == "__main__":
    try_call("allowlisted search", search_web, "quarterly report")
    try_call("read a doc", read_doc, "doc-42")
    try_call("non-allowlisted tool", exfiltrate, "secret plan")
    try_call("egress: doc id is an email", read_doc, "alice@example.com")
    try_call("high-impact delete (auto-denied)", delete_record, "rec-9")

    print(f"\nAudit log: {len(broker.log)} entries, chain intact = {broker.log.verify()}")
    for entry in broker.log:
        print(f"  - {entry.effect:16} {entry.summary:32} :: {entry.reason}")
