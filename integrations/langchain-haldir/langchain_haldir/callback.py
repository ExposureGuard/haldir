"""
HaldirCallbackHandler — observability + governance for LangChain agents.

What it does on each LangChain lifecycle event:

  on_tool_start  — check scope, abort the agent loop on denial, cache
                   input for the audit row
  on_tool_end    — write a `tool_call` audit entry with input/output
                   + cost_usd (from cost_fn if configured)
  on_tool_error  — write a `tool_error` audit entry
  on_llm_end     — extract token usage, convert to USD via the
                   pricing table, write an `llm_call` audit entry
                   — this is where the real spend tracking happens
  on_agent_finish— fetch the current Signed Tree Head and stamp it
                   onto the agent's return_values under `_haldir_sth`
                   so the caller can pin it for offline verification

Designed to be paired with HaldirSession so the whole lifecycle is
two lines of code in the caller. But the class still works standalone
for users who've already mint their own session.
"""

from __future__ import annotations

import os
from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult
from langchain_core.agents import AgentFinish

from sdk.client import HaldirClient, HaldirPermissionError

from . import pricing


class HaldirCallbackHandler(BaseCallbackHandler):
    """LangChain callback that wires agent lifecycle into Haldir.

    Args:
        client: Authenticated HaldirClient.
        session_id: Active Haldir session this agent runs under.
        scope_map: Optional dict mapping tool names to required scopes.
            Tools not in the map use ``default_scope``.
        default_scope: Scope checked when a tool isn't in ``scope_map``.
        enforce: If True, deny tool execution on scope failure. If
            False, log only (pure observability mode).
        cost_fn: Optional callable
            ``(tool_name, input_str, output) -> float`` returning
            per-tool USD cost. LLM token cost is tracked separately
            via the pricing table.
        track_llm_cost: If True (default), on_llm_end will compute
            token cost from the pricing table and write an audit
            entry with cost_usd. Turn off when the caller is doing
            their own cost accounting.
        stamp_sth: If True (default), on_agent_finish fetches the
            current STH and attaches it to return_values under
            "_haldir_sth". Lets the caller pin the tree head for
            later offline verification without a separate call.
    """

    def __init__(
        self,
        client: HaldirClient,
        session_id: str,
        scope_map: dict[str, str] | None = None,
        default_scope: str = "read",
        enforce: bool = True,
        cost_fn: Any = None,
        track_llm_cost: bool = True,
        stamp_sth: bool = True,
    ) -> None:
        self.client = client
        self.session_id = session_id
        self.scope_map = scope_map or {}
        self.default_scope = default_scope
        self.enforce = enforce
        self.cost_fn = cost_fn
        self.track_llm_cost = track_llm_cost
        self.stamp_sth = stamp_sth
        self._inputs: dict[UUID, tuple[str, str]] = {}
        self._llm_meta: dict[UUID, dict[str, Any]] = {}

    # ── Zero-config convenience ─────────────────────────────────────

    @classmethod
    def from_env(
        cls,
        session_id: str,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        **kwargs: Any,
    ) -> "HaldirCallbackHandler":
        """Build a handler from HALDIR_API_KEY / HALDIR_BASE_URL
        without the caller constructing a HaldirClient manually.

        For the full zero-config path that ALSO mints + revokes the
        session, use HaldirSession.for_agent(...) instead.
        """
        api_key = api_key or os.environ.get("HALDIR_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError(
                "HaldirCallbackHandler.from_env requires HALDIR_API_KEY "
                "to be set (or pass api_key=... explicitly)."
            )
        base_url = base_url or os.environ.get(
            "HALDIR_BASE_URL", "https://haldir.xyz",
        )
        return cls(
            client=HaldirClient(api_key=api_key, base_url=base_url),
            session_id=session_id,
            **kwargs,
        )

    # ── Scope resolution ───────────────────────────────────────────

    def _scope_for(self, tool_name: str) -> str:
        return self.scope_map.get(tool_name, self.default_scope)

    # ── Tool lifecycle ─────────────────────────────────────────────

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
        self._safe_log(
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
        self._safe_log(
            tool=tool_name,
            action="tool_error",
            cost_usd=0.0,
            details={"input": input_str[:500], "error": str(error)[:500]},
        )

    # ── LLM lifecycle — this is where most spend lives ──────────────

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        # Cache the model identifier LangChain reports — on_llm_end
        # often doesn't carry it in a uniform place across providers.
        model = (
            serialized.get("kwargs", {}).get("model")
            or serialized.get("kwargs", {}).get("model_name")
            or serialized.get("name", "unknown-llm")
        )
        self._llm_meta[run_id] = {"model": model}

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Extract token usage, convert to USD via pricing table,
        write a llm_call audit row. No-op if track_llm_cost=False."""
        if not self.track_llm_cost:
            self._llm_meta.pop(run_id, None)
            return

        meta = self._llm_meta.pop(run_id, {})
        model = meta.get("model", "unknown-llm")

        # LangChain's usage-reporting shape varies across providers;
        # try the three places token counts canonically live.
        usage = self._extract_token_usage(response)
        prompt_tokens = int(usage.get("prompt_tokens", 0))
        completion_tokens = int(usage.get("completion_tokens", 0))

        cost = pricing.cost_usd(model, prompt_tokens, completion_tokens)

        self._safe_log(
            tool=f"llm:{model}",
            action="llm_call",
            cost_usd=cost,
            details={
                "model":             str(model),
                "prompt_tokens":     prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens":      prompt_tokens + completion_tokens,
            },
        )

    @staticmethod
    def _extract_token_usage(response: LLMResult) -> dict[str, int]:
        """LangChain providers report usage in at least three shapes:

          1. response.llm_output["token_usage"] (OpenAI, Anthropic via
             their LC providers)
          2. generation.generation_info["token_usage"]
          3. generation.message.usage_metadata (new LC core pattern)

        Try each in order; fall through to empty dict if nothing hits.
        """
        if response.llm_output:
            tu = response.llm_output.get("token_usage")
            if tu:
                return {
                    "prompt_tokens":     tu.get("prompt_tokens", 0),
                    "completion_tokens": tu.get("completion_tokens", 0),
                }
        # Walk the generations for the newer patterns.
        for gen_batch in response.generations:
            for gen in gen_batch:
                info = getattr(gen, "generation_info", None) or {}
                tu = info.get("token_usage")
                if tu:
                    return {
                        "prompt_tokens":     tu.get("prompt_tokens", 0),
                        "completion_tokens": tu.get("completion_tokens", 0),
                    }
                msg = getattr(gen, "message", None)
                usage_md = getattr(msg, "usage_metadata", None) if msg else None
                if usage_md:
                    return {
                        "prompt_tokens":     usage_md.get("input_tokens", 0),
                        "completion_tokens": usage_md.get("output_tokens", 0),
                    }
        return {"prompt_tokens": 0, "completion_tokens": 0}

    # ── Agent lifecycle — STH stamping ─────────────────────────────

    def on_agent_finish(
        self,
        finish: AgentFinish,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Stamp the current Signed Tree Head onto the agent's result.

        The STH returned here is the one that COVERS every audit entry
        this agent wrote during the run. A customer archiving the
        run's output can later verify offline that every tool call +
        LLM call was in the log at the moment the agent finished —
        and if the log is ever rewritten, the pinned STH won't
        match."""
        if not self.stamp_sth:
            return
        try:
            sth = self.client.get_tree_head()
            finish.return_values["_haldir_sth"] = sth
        except Exception:
            # Never break the agent's return path over an STH fetch.
            pass

    # ── Private helpers ────────────────────────────────────────────

    def _safe_log(
        self,
        *,
        tool: str,
        action: str,
        cost_usd: float,
        details: dict[str, Any],
    ) -> None:
        """Best-effort audit-log write. Exceptions here are swallowed
        because the caller is in the middle of a LangChain run — we
        don't want an audit-log network blip to crash the user's
        agent mid-execution."""
        try:
            self.client.log_action(
                session_id=self.session_id,
                tool=tool,
                action=action,
                cost_usd=cost_usd,
                details=details,
            )
        except Exception:
            pass
