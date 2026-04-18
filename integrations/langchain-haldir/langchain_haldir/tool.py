"""
GovernedTool — wrap any LangChain BaseTool with Haldir enforcement.

Unlike the callback (observability), this wrapper *actively blocks* tool
invocation when the Haldir session is revoked, out of budget, or missing
the required scope. Use this for hard enforcement.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import BaseTool
from pydantic import ConfigDict

from sdk.client import HaldirPermissionError


class GovernedTool(BaseTool):
    """Drop-in wrapper that enforces Haldir checks around any BaseTool."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    wrapped_tool: Any = None
    client: Any = None
    session_id: str = ""
    required_scope: str = "read"
    cost_usd: float = 0.0

    @classmethod
    def from_tool(
        cls,
        tool: Any,
        client: Any,
        session_id: str,
        required_scope: str = "read",
        cost_usd: float = 0.0,
    ) -> "GovernedTool":
        kwargs: dict[str, Any] = {
            "name": tool.name,
            "description": tool.description,
            "wrapped_tool": tool,
            "client": client,
            "session_id": session_id,
            "required_scope": required_scope,
            "cost_usd": cost_usd,
        }
        args_schema = getattr(tool, "args_schema", None)
        if args_schema is not None:
            kwargs["args_schema"] = args_schema
        return cls(**kwargs)

    def _check(self) -> None:
        result = self.client.check_permission(self.session_id, self.required_scope)
        if not result.get("allowed"):
            raise HaldirPermissionError(
                f"Haldir denied tool '{self.name}' — session lacks scope '{self.required_scope}'",
                status_code=403,
            )

    def _log(self, action: str, details: dict, cost_usd: float = 0.0) -> None:
        try:
            self.client.log_action(
                session_id=self.session_id,
                tool=self.name,
                action=action,
                cost_usd=cost_usd,
                details=details,
            )
        except Exception:
            pass

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        self._check()
        try:
            output = self.wrapped_tool._run(*args, **kwargs)
            self._log(
                "tool_call",
                {"input": str(kwargs or args)[:500], "output": str(output)[:500]},
                cost_usd=self.cost_usd,
            )
            return output
        except Exception as e:
            self._log("tool_error", {"input": str(kwargs or args)[:500], "error": str(e)[:500]})
            raise

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        self._check()
        try:
            output = await self.wrapped_tool._arun(*args, **kwargs)
            self._log(
                "tool_call",
                {"input": str(kwargs or args)[:500], "output": str(output)[:500]},
                cost_usd=self.cost_usd,
            )
            return output
        except Exception as e:
            self._log("tool_error", {"input": str(kwargs or args)[:500], "error": str(e)[:500]})
            raise
