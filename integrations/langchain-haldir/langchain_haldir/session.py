"""
HaldirSession — context manager for Haldir-governed LangChain runs.

The point of this module is to deliver on the two-line promise:

    from langchain_haldir import HaldirSession

    with HaldirSession.for_agent("research-bot") as haldir:
        executor = AgentExecutor(..., callbacks=[haldir.handler])
        result = executor.invoke({...})
        # STH for the whole run is in result["_haldir_sth"].
    # Session auto-revoked on exit. Audit trail sealed.

Compared to the manual path (`create_session()` + build handler +
remember to revoke), this is:

  - 1 import, 1 `with`, 1 `callbacks=[...]` line → 3 LOC instead of
    the previous ~12.
  - Auto-revoke on scope exit, including on exception. No "my agent
    crashed and left a dangling session with a 1-hour TTL"
    failure mode.
  - Reads HALDIR_API_KEY + HALDIR_BASE_URL from env if not passed
    — matches the ergonomics every LangChain integration with
    OPENAI_API_KEY / ANTHROPIC_API_KEY uses.

The class is a thin wrapper around the existing sdk client + the
HaldirCallbackHandler. It holds the session_id privately and exposes
only what the caller actually needs (the handler, the spend summary,
a `refresh_sth()` helper).
"""

from __future__ import annotations

import os
from types import TracebackType
from typing import Any

from sdk.client import HaldirClient

from .callback import HaldirCallbackHandler


class HaldirSession:
    """Haldir session + callback + audit lifecycle, bound to a
    `with`-statement scope.

    Usage — zero config (reads from env)::

        with HaldirSession.for_agent("my-bot") as s:
            executor = AgentExecutor(..., callbacks=[s.handler])
            result = executor.invoke({"input": "..."})
            print(result["_haldir_sth"]["root_hash"])

    Usage — explicit::

        with HaldirSession(
            api_key="hld_...",
            agent_id="refund-bot",
            scopes=["stripe:refund"],
            spend_limit=50.0,
            base_url="https://haldir.xyz",
        ) as s:
            ...
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        agent_id: str,
        scopes: list[str] | None = None,
        ttl: int = 3600,
        spend_limit: float | None = None,
        # Handler config (forwarded):
        scope_map: dict[str, str] | None = None,
        default_scope: str = "read",
        enforce: bool = True,
        track_llm_cost: bool = True,
        stamp_sth: bool = True,
    ) -> None:
        api_key  = api_key  or os.environ.get("HALDIR_API_KEY", "").strip()
        base_url = base_url or os.environ.get(
            "HALDIR_BASE_URL", "https://haldir.xyz",
        )
        if not api_key:
            raise RuntimeError(
                "HaldirSession requires an API key. Pass `api_key=...` "
                "or set HALDIR_API_KEY in the environment."
            )

        self._agent_id      = agent_id
        self._scopes        = scopes
        self._ttl           = ttl
        self._spend_limit   = spend_limit
        self._scope_map     = scope_map or {}
        self._default_scope = default_scope
        self._enforce       = enforce
        self._track_llm_cost = track_llm_cost
        self._stamp_sth     = stamp_sth

        self.client = HaldirClient(api_key=api_key, base_url=base_url)
        self.session_id: str | None = None
        self.handler: HaldirCallbackHandler | None = None

    # ── Class-method shortcut for the hot-path zero-config case ──

    @classmethod
    def for_agent(
        cls,
        agent_id: str,
        *,
        scopes: list[str] | None = None,
        spend_limit: float | None = None,
        **kwargs: Any,
    ) -> "HaldirSession":
        """Shortest possible entry point. Uses HALDIR_API_KEY +
        HALDIR_BASE_URL from env. Equivalent to
        `HaldirSession(api_key=os.environ["HALDIR_API_KEY"],
                        agent_id=agent_id, ...)` but less boilerplate."""
        return cls(
            agent_id=agent_id,
            scopes=scopes,
            spend_limit=spend_limit,
            **kwargs,
        )

    # ── Context manager protocol ──────────────────────────────────

    def __enter__(self) -> "HaldirSession":
        session = self.client.create_session(
            self._agent_id,
            scopes=self._scopes,
            ttl=self._ttl,
            spend_limit=self._spend_limit,
        )
        self.session_id = session["session_id"]
        self.handler = HaldirCallbackHandler(
            client=self.client,
            session_id=self.session_id,
            scope_map=self._scope_map,
            default_scope=self._default_scope,
            enforce=self._enforce,
            track_llm_cost=self._track_llm_cost,
            stamp_sth=self._stamp_sth,
        )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Always revoke the session on scope exit, even on exception.

        A transient network error revoking the session MUST NOT
        suppress the user's exception — we catch + log + re-raise the
        original. Leaving a dangling session with a 1-hour TTL is an
        acceptable worst case; masking the real error is not."""
        if self.session_id is None:
            return
        try:
            self.client.revoke_session(self.session_id)
        except Exception:
            pass  # best-effort; user's exception wins
        finally:
            self.session_id = None
            self.handler = None

    # ── Ergonomic helpers used from inside the `with` block ─────

    def spend_summary(self) -> dict[str, Any]:
        """Current spend on this session. Useful for mid-run budget
        dashboards (e.g. 'we've used 62% of our $5 cap so far')."""
        if not self.session_id:
            return {"total_usd": 0.0, "action_count": 0}
        return self.client.get_spend(session_id=self.session_id)

    def audit_trail(self, limit: int = 100) -> dict[str, Any]:
        """All audit entries written under this session so far."""
        if not self.session_id:
            return {"entries": [], "count": 0}
        return self.client.get_audit_trail(
            session_id=self.session_id, limit=limit,
        )

    def current_sth(self) -> dict[str, Any]:
        """Fetch the tenant's current Signed Tree Head. Returns the
        full response from GET /v1/audit/tree-head — tree_size +
        root_hash + signature + key_id. Auditors pin this to verify
        later that no history was rewritten."""
        return self.client.get_tree_head()
