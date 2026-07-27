"""LangChain / LangGraph integration.

``guard_langchain_tool`` takes an existing LangChain ``BaseTool`` and returns a
wrapped tool that routes every invocation through an AgentGate ``Broker`` first.
If the broker denies the action, the tool returns a refusal string to the agent
instead of executing — so the agent sees a clean, model-readable denial rather
than crashing the run.

LangChain is an optional dependency: importing this module does not require it,
but calling ``guard_langchain_tool`` does. This keeps the core install slim.
"""

from __future__ import annotations

from typing import Any

from ..action import Action
from ..broker import ActionDenied, Broker


def guard_langchain_tool(
    tool: Any,
    broker: Broker,
    *,
    agent_id: str = "default",
    principal: str = "unknown",
) -> Any:
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise ImportError(
            "guard_langchain_tool requires langchain-core. "
            "Install with: pip install 'agentgate[langchain]'"
        ) from exc

    original_run = tool.func if hasattr(tool, "func") else tool._run

    def guarded(*args: Any, **kwargs: Any) -> Any:
        action = Action(
            tool=tool.name,
            args={**{f"arg{i}": a for i, a in enumerate(args)}, **kwargs},
            agent_id=agent_id,
            principal=principal,
        )
        try:
            broker.enforce(action)
        except ActionDenied as denied:
            # Return a model-readable refusal instead of raising into the agent.
            return f"ACTION BLOCKED by AgentGate: {denied}"
        return original_run(*args, **kwargs)

    return StructuredTool.from_function(
        func=guarded,
        name=tool.name,
        description=tool.description,
        args_schema=getattr(tool, "args_schema", None),
    )
