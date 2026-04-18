"""Wrap a LlamaIndex tool so every call is governed by Haldir.

LlamaIndex `BaseTool` exposes both synchronous (`__call__`, `call`) and
asynchronous (`acall`) entry points, and a `metadata` property that
carries name + description + fn_schema. We wrap all three entry points
and mirror the metadata surface so the governed tool drops into any
LlamaIndex agent (ReAct, OpenAIAgent, FnCallingAgent) without changes.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

try:
    from llama_index.core.tools import BaseTool, ToolOutput
except ImportError:  # pragma: no cover
    BaseTool = object  # type: ignore[assignment,misc]
    ToolOutput = None  # type: ignore[assignment]

from sdk.client import HaldirClient, HaldirPermissionError


class GovernedTool:
    """Wrapper around a LlamaIndex `BaseTool` that enforces Haldir checks.

    Every invocation:
      1. Checks scope against the Haldir session (pre-execution)
      2. Records the call + cost to the audit trail (post-execution)
      3. Raises `HaldirPermissionError` if the session is revoked or
         out-of-scope — halts the agent loop at the tool-call boundary

    Presents the same `metadata` / `__call__` / `call` / `acall` surface
    as the inner tool, so LlamaIndex agents treat it as native.
    """

    def __init__(
        self,
        inner_tool: Any,
        client: HaldirClient,
        session_id: str,
        required_scope: str = "execute",
        cost_usd: float = 0.0,
        cost_fn: Optional[Callable[[Any], float]] = None,
    ):
        self._inner = inner_tool
        self._client = client
        self._session_id = session_id
        self._required_scope = required_scope
        self._cost_usd = cost_usd
        self._cost_fn = cost_fn

    # ── Metadata LlamaIndex reads ──

    @property
    def metadata(self) -> Any:
        return self._inner.metadata

    @property
    def fn_schema(self) -> Any:
        return getattr(self._inner, "fn_schema", None)

    @property
    def fn(self) -> Any:
        return getattr(self._inner, "fn", None)

    # ── Entry points ──

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._check_permission()
        try:
            result = self._inner(*args, **kwargs)
        except Exception as e:
            self._log_error(str(e))
            raise
        self._log_success(result)
        return result

    def call(self, *args: Any, **kwargs: Any) -> Any:
        self._check_permission()
        try:
            result = self._inner.call(*args, **kwargs)
        except Exception as e:
            self._log_error(str(e))
            raise
        self._log_success(result)
        return result

    async def acall(self, *args: Any, **kwargs: Any) -> Any:
        self._check_permission()
        try:
            result = await self._inner.acall(*args, **kwargs)
        except Exception as e:
            self._log_error(str(e))
            raise
        self._log_success(result)
        return result

    # ── Internal helpers ──

    def _check_permission(self) -> None:
        perm = self._client.check_permission(self._session_id, self._required_scope)
        if not perm.get("allowed", False):
            name = getattr(self.metadata, "name", "unknown") if self.metadata else "unknown"
            raise HaldirPermissionError(
                f"Tool '{name}' blocked: session lacks scope "
                f"'{self._required_scope}' or has been revoked.",
                status_code=403,
            )

    def _tool_name(self) -> str:
        return getattr(self.metadata, "name", "unknown") if self.metadata else "unknown"

    def _log_success(self, result: Any) -> None:
        cost = self._cost_fn(result) if self._cost_fn else self._cost_usd
        self._client.log_action(
            session_id=self._session_id,
            tool=self._tool_name(),
            action="execute",
            cost_usd=cost,
        )

    def _log_error(self, message: str) -> None:
        self._client.log_action(
            session_id=self._session_id,
            tool=self._tool_name(),
            action="error",
            details={"error": message},
        )


def govern_tool(
    tool: Any,
    client: HaldirClient,
    session_id: str,
    required_scope: str = "execute",
    cost_usd: float = 0.0,
    cost_fn: Optional[Callable[[Any], float]] = None,
) -> GovernedTool:
    """Factory — wrap any LlamaIndex BaseTool with Haldir governance.

    Works with `FunctionTool`, `QueryEngineTool`, `RetrieverTool`, and
    any custom `BaseTool` subclass.

    Args:
        tool: LlamaIndex BaseTool (FunctionTool, QueryEngineTool, etc.)
        client: Haldir client.
        session_id: The Haldir session ID governing this tool.
        required_scope: Scope needed to invoke this tool (default "execute").
        cost_usd: Fixed cost per call. Ignored if cost_fn is given.
        cost_fn: Callable(result) -> float for variable-cost tools.
    """
    return GovernedTool(
        inner_tool=tool,
        client=client,
        session_id=session_id,
        required_scope=required_scope,
        cost_usd=cost_usd,
        cost_fn=cost_fn,
    )
