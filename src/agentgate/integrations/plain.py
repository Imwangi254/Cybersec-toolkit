"""Framework-agnostic integration: guard any plain Python callable.

This is the "adopt in five lines, no framework required" path. Wrap a tool
function and the broker vets every call before the real function runs.

    broker = Broker([...])

    @guard(broker)
    def transfer_funds(amount, to):
        ...

Calling ``transfer_funds(...)`` now routes through the broker first and raises
``ActionDenied`` if the action isn't permitted.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from ..action import Action
from ..broker import Broker


def guard(
    broker: Broker,
    *,
    tool_name: str | None = None,
    agent_id: str = "default",
    principal: str = "unknown",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        name = tool_name or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            action = Action(
                tool=name,
                args={**{f"arg{i}": a for i, a in enumerate(args)}, **kwargs},
                agent_id=agent_id,
                principal=principal,
            )
            broker.enforce(action)  # raises ActionDenied if blocked
            return fn(*args, **kwargs)

        return wrapper

    return decorator
