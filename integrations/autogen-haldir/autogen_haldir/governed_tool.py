"""Wrap an AutoGen tool so every call is governed by Haldir.

Works with AutoGen 0.4+ (agentchat / core). The wrapper is transport-aware
at the `run_json` boundary so it composes cleanly with AutoGen's async
runtime while still letting us check scopes and log synchronously against
Haldir's REST API.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

try:
    from autogen_core.tools import BaseTool
except ImportError:  # pragma: no cover - fallback for older autogen
    BaseTool = object  # type: ignore[assignment,misc]

from sdk.client import HaldirClient, HaldirPermissionError


class GovernedFunctionTool:
    """A wrapper that delegates to an inner AutoGen tool after a Haldir check.

    Presents the same surface as the inner tool (name, description, schema,
    run_json) so AutoGen treats it like a native tool. The governance hooks
    are invisible to the agent loop.

    Every invocation:
      1. Checks scope against the Haldir session (pre-execution)
      2. Records the call + cost to the audit trail (post-execution)
      3. Raises `HaldirPermissionError` if the session is revoked or
         out-of-scope — this propagates out of the AutoGen runtime and
         halts the current tool-call step.
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

    # ── Surface that AutoGen expects to be present on a tool ──

    @property
    def name(self) -> str:
        return self._inner.name

    @property
    def description(self) -> str:
        return self._inner.description

    @property
    def schema(self) -> Any:
        # AutoGen's core BaseTool exposes a `schema` for the tool's JSON arg schema.
        return getattr(self._inner, "schema", None)

    def args_type(self) -> Any:
        if hasattr(self._inner, "args_type"):
            return self._inner.args_type()
        return None

    def return_type(self) -> Any:
        if hasattr(self._inner, "return_type"):
            return self._inner.return_type()
        return None

    def return_value_as_string(self, value: Any) -> str:
        if hasattr(self._inner, "return_value_as_string"):
            return self._inner.return_value_as_string(value)
        return str(value)

    # ── The governance-enforcing core ──

    async def run_json(self, args: Any, cancellation_token: Any = None) -> Any:
        """AutoGen calls this on every tool invocation."""
        self._check_permission()
        try:
            result = await self._inner.run_json(args, cancellation_token)
        except Exception as e:
            self._log_error(str(e))
            raise
        self._log_success(result)
        return result

    # Also expose `run` for callers using the typed path
    async def run(self, args: Any, cancellation_token: Any = None) -> Any:
        self._check_permission()
        try:
            result = await self._inner.run(args, cancellation_token)
        except Exception as e:
            self._log_error(str(e))
            raise
        self._log_success(result)
        return result

    # ── Internal helpers ──

    def _check_permission(self) -> None:
        perm = self._client.check_permission(self._session_id, self._required_scope)
        if not perm.get("allowed", False):
            raise HaldirPermissionError(
                f"Tool '{self.name}' blocked: session lacks scope "
                f"'{self._required_scope}' or has been revoked.",
                status_code=403,
            )

    def _log_success(self, result: Any) -> None:
        cost = self._cost_fn(result) if self._cost_fn else self._cost_usd
        self._client.log_action(
            session_id=self._session_id,
            tool=self.name,
            action="execute",
            cost_usd=cost,
        )

    def _log_error(self, message: str) -> None:
        self._client.log_action(
            session_id=self._session_id,
            tool=self.name,
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
) -> GovernedFunctionTool:
    """Factory — wrap any AutoGen tool with Haldir governance.

    Args:
        tool: AutoGen BaseTool or FunctionTool instance.
        client: Haldir client.
        session_id: The Haldir session ID governing this tool.
        required_scope: Scope needed to invoke this tool (default "execute").
        cost_usd: Fixed cost per call. Ignored if cost_fn is given.
        cost_fn: Callable(result) -> float for variable-cost tools.
    """
    return GovernedFunctionTool(
        inner_tool=tool,
        client=client,
        session_id=session_id,
        required_scope=required_scope,
        cost_usd=cost_usd,
        cost_fn=cost_fn,
    )
