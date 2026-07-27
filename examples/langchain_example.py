"""Run me:  pip install 'agentgate[langchain]' && python examples/langchain_example.py

Wraps ordinary LangChain tools with AgentGate so every tool call an agent
makes is authorized and logged. Denied calls return a model-readable refusal
string, so the agent keeps running and simply can't perform the blocked action.

This example only builds the guarded tools and exercises them directly (no LLM
key needed). Hand the guarded tools to any LangChain/LangGraph agent exactly as
you would the originals.
"""

from agentgate import ApprovalPolicy, Broker, ToolAllowlistPolicy
from agentgate.approval import AutoDenyApprovalHandler


def main() -> None:
    try:
        from langchain_core.tools import tool
    except ImportError:
        print(
            "This example needs langchain-core.\n"
            "Install it with:  pip install 'agentgate[langchain]'"
        )
        return

    from agentgate.integrations.langchain import guard_langchain_tool

    @tool
    def search(query: str) -> str:
        """Search the web for a query."""
        return f"results for {query!r}"

    @tool
    def wire_transfer(amount: str, to: str) -> str:
        """Wire money to a recipient."""
        return f"wired {amount} to {to}"

    broker = Broker(
        policies=[
            ToolAllowlistPolicy(allowed_tools={"search", "wire_transfer"}),
            ApprovalPolicy(),  # 'wire_transfer' is high-impact
        ],
        approval_handler=AutoDenyApprovalHandler(),
    )

    guarded_search = guard_langchain_tool(search, broker, principal="user:bob")
    guarded_wire = guard_langchain_tool(wire_transfer, broker, principal="user:bob")

    print("search ->", guarded_search.invoke({"query": "AI agent security"}))
    print("wire   ->", guarded_wire.invoke({"amount": "5000", "to": "acct-777"}))
    print(f"\nAudit log: {len(broker.log)} entries, chain intact = {broker.log.verify()}")


if __name__ == "__main__":
    main()
