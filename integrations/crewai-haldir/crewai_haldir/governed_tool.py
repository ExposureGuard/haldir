"""Wrap a CrewAI tool so every call is governed by Haldir."""

from __future__ import annotations

from typing import Any, Callable, Optional, Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from sdk.client import HaldirClient, HaldirPermissionError


class GovernedTool(BaseTool):
    """A CrewAI tool wrapped with Haldir enforcement.

    Every invocation:
      1. Checks scope against the Haldir session (pre-execution)
      2. Records the call and cost to the audit trail (post-execution)
      3. Raises HaldirPermissionError if the session is revoked or out-of-scope

    The wrapped tool keeps its original ``args_schema`` so agents see the same
    parameters they would see on the raw tool.
    """

    inner_tool: Any = Field(default=None, exclude=True)
    client: Any = Field(default=None, exclude=True)
    session_id: str = Field(default="", exclude=True)
    required_scope: str = Field(default="execute", exclude=True)
    cost_usd: float = Field(default=0.0, exclude=True)
    cost_fn: Optional[Callable[[Any], float]] = Field(default=None, exclude=True)

    model_config = {"arbitrary_types_allowed": True}

    @classmethod
    def wrap(
        cls,
        tool: BaseTool,
        client: HaldirClient,
        session_id: str,
        required_scope: str = "execute",
        cost_usd: float = 0.0,
        cost_fn: Optional[Callable[[Any], float]] = None,
    ) -> "GovernedTool":
        """Wrap an existing CrewAI tool with Haldir governance.

        Args:
            tool: Any CrewAI tool (subclass of BaseTool).
            client: Haldir client for this session.
            session_id: The Haldir session ID governing this tool.
            required_scope: Scope needed to invoke this tool (default "execute").
            cost_usd: Fixed cost per call. Ignored if cost_fn is given.
            cost_fn: Callable(result) -> float for variable-cost tools.
        """
        kwargs: dict[str, Any] = {
            "name": tool.name,
            "description": tool.description,
            "inner_tool": tool,
            "client": client,
            "session_id": session_id,
            "required_scope": required_scope,
            "cost_usd": cost_usd,
            "cost_fn": cost_fn,
        }
        inner_schema: Optional[Type[BaseModel]] = getattr(tool, "args_schema", None)
        if inner_schema is not None:
            kwargs["args_schema"] = inner_schema
        return cls(**kwargs)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        perm = self.client.check_permission(self.session_id, self.required_scope)
        if not perm.get("allowed", False):
            raise HaldirPermissionError(
                f"Tool '{self.name}' blocked: session lacks scope '{self.required_scope}' "
                f"or has been revoked.",
                status_code=403,
            )

        try:
            result = self.inner_tool._run(*args, **kwargs)
        except Exception as e:
            self.client.log_action(
                session_id=self.session_id,
                tool=self.name,
                action="error",
                details={"error": str(e)},
            )
            raise

        cost = self.cost_fn(result) if self.cost_fn else self.cost_usd
        self.client.log_action(
            session_id=self.session_id,
            tool=self.name,
            action="execute",
            cost_usd=cost,
        )

        return result
