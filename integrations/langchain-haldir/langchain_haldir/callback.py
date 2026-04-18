"""
HaldirCallbackHandler — observability callback for LangChain agents.

Logs every tool invocation to Haldir's hash-chained audit trail. Optionally
enforces scope checks before each tool call and raises HaldirPermissionError
to abort the agent loop if the session is revoked or denied.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler

from sdk.client import HaldirClient, HaldirPermissionError


class HaldirCallbackHandler(BaseCallbackHandler):
    """LangChain callback that wires tool invocations through Haldir.

    Args:
        client: Authenticated HaldirClient.
        session_id: Active Haldir session this agent is running under.
        scope_map: Optional dict mapping tool names to required scopes.
            Tools not in the map use ``default_scope``.
        default_scope: Scope to check when a tool isn't in ``scope_map``.
        enforce: If True, deny tool execution on scope failure. If False,
            log only (observability mode).
        cost_fn: Optional callable ``(tool_name, input_str, output) -> float``
            that returns a per-call cost in USD. Defaults to 0.0.
    """

    def __init__(
        self,
        client: HaldirClient,
        session_id: str,
        scope_map: dict[str, str] | None = None,
        default_scope: str = "read",
        enforce: bool = True,
        cost_fn: Any = None,
    ) -> None:
        self.client = client
        self.session_id = session_id
        self.scope_map = scope_map or {}
        self.default_scope = default_scope
        self.enforce = enforce
        self.cost_fn = cost_fn
        self._inputs: dict[UUID, tuple[str, str]] = {}

    def _scope_for(self, tool_name: str) -> str:
        return self.scope_map.get(tool_name, self.default_scope)

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown")
        self._inputs[run_id] = (tool_name, input_str)

        if not self.enforce:
            return

        scope = self._scope_for(tool_name)
        result = self.client.check_permission(self.session_id, scope)
        if not result.get("allowed"):
            raise HaldirPermissionError(
                f"Haldir denied tool '{tool_name}' — session lacks scope '{scope}'",
                status_code=403,
            )

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name, input_str = self._inputs.pop(run_id, ("unknown", ""))
        cost = 0.0
        if self.cost_fn is not None:
            try:
                cost = float(self.cost_fn(tool_name, input_str, output))
            except Exception:
                cost = 0.0

        self.client.log_action(
            session_id=self.session_id,
            tool=tool_name,
            action="tool_call",
            cost_usd=cost,
            details={"input": input_str[:500], "output": str(output)[:500]},
        )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name, input_str = self._inputs.pop(run_id, ("unknown", ""))
        self.client.log_action(
            session_id=self.session_id,
            tool=tool_name,
            action="tool_error",
            cost_usd=0.0,
            details={"input": input_str[:500], "error": str(error)[:500]},
        )
