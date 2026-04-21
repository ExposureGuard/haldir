"""
HaldirSession for LlamaIndex — context manager that auto-mints +
auto-revokes a Haldir session around an agent / query-engine run.

The two-line promise::

    from llamaindex_haldir import HaldirSession, govern_tool

    with HaldirSession.for_agent("li-research",
                                  scopes=["read", "search"],
                                  spend_limit=5.0) as haldir:
        governed = govern_tool(raw_tool, haldir.client, haldir.session_id,
                                required_scope="search")
        agent = ReActAgent.from_tools([governed], llm=...)
        result = haldir.stamp_sth(agent.chat("..."))

Why this module exists:

  LlamaIndex doesn't have a single BaseCallbackHandler primitive like
  LangChain does — it uses an instrumentation / event-handler system
  that's more fine-grained but harder to wire zero-config. So the
  integration lives at the TOOL level (govern_tool / GovernedTool)
  and the SESSION level (this module). The session handles lifecycle
  + ergonomics; GovernedTool handles the per-call scope check + audit
  write.

  The shape mirrors crewai-haldir.HaldirSession exactly — same ctor,
  same context-manager contract, same stamp_sth helper — so an
  operator running Haldir across both frameworks can transfer the
  mental model verbatim.
"""

from __future__ import annotations

import os
from types import TracebackType
from typing import Any

from sdk.client import HaldirClient


class HaldirSession:
    """Haldir session lifecycle scoped to a LlamaIndex run.

    Usage::

        with HaldirSession.for_agent("my-index") as haldir:
            governed = govern_tool(raw, haldir.client, haldir.session_id,
                                    required_scope="search", cost_usd=0.01)
            agent = ReActAgent.from_tools([governed], llm=OpenAI(...))
            resp = haldir.stamp_sth(agent.chat("..."))

    ``resp`` carries `_haldir_sth` (as dict key or object attribute)
    with the tenant's current Signed Tree Head.
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
        self._agent_id    = agent_id
        self._scopes      = scopes
        self._ttl         = ttl
        self._spend_limit = spend_limit
        self.client = HaldirClient(api_key=api_key, base_url=base_url)
        self.session_id: str | None = None

    @classmethod
    def for_agent(
        cls,
        agent_id: str,
        *,
        scopes: list[str] | None = None,
        spend_limit: float | None = None,
        **kwargs: Any,
    ) -> "HaldirSession":
        """Shortest entry point. Reads HALDIR_API_KEY + HALDIR_BASE_URL
        from env."""
        return cls(
            agent_id=agent_id,
            scopes=scopes,
            spend_limit=spend_limit,
            **kwargs,
        )

    # ── Context-manager protocol ────────────────────────────────────

    def __enter__(self) -> "HaldirSession":
        session = self.client.create_session(
            self._agent_id,
            scopes=self._scopes,
            ttl=self._ttl,
            spend_limit=self._spend_limit,
        )
        self.session_id = session["session_id"]
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Always revoke on scope exit, even on exception. A revoke
        failure MUST NOT mask the user's exception."""
        if self.session_id is None:
            return
        try:
            self.client.revoke_session(self.session_id)
        except Exception:
            pass
        finally:
            self.session_id = None

    # ── Ergonomic helpers ────────────────────────────────────────────

    def spend_summary(self) -> dict[str, Any]:
        """Current spend on this session."""
        if not self.session_id:
            return {"total_usd": 0.0, "action_count": 0}
        return self.client.get_spend(session_id=self.session_id)

    def audit_trail(self, limit: int = 100) -> dict[str, Any]:
        """Every audit entry written under this session."""
        if not self.session_id:
            return {"entries": [], "count": 0}
        return self.client.get_audit_trail(
            session_id=self.session_id, limit=limit,
        )

    def current_sth(self) -> dict[str, Any]:
        """Fetch the tenant's current Signed Tree Head. Pin it for
        later offline verification."""
        return self.client.get_tree_head()

    def stamp_sth(self, result: Any) -> Any:
        """Attach the current STH to a LlamaIndex response object.

        LlamaIndex's `.chat(...)` returns an `AgentChatResponse` — a
        regular Python object with `.response`, `.sources`, etc. We
        set `_haldir_sth` as an attribute so the caller can pull it
        off without restructuring their pipeline.

        Behaviour depending on result shape:
          - dict: writes result["_haldir_sth"] = sth
          - object with __dict__: sets result._haldir_sth = sth
          - anything else: wraps into a new dict
              {"output": result, "_haldir_sth": sth}

        Network errors fetching the STH never break the caller's
        output path — we return the original result unmodified if
        the fetch fails."""
        try:
            sth = self.current_sth()
        except Exception:
            return result
        if isinstance(result, dict):
            result["_haldir_sth"] = sth
            return result
        if hasattr(result, "__dict__"):
            try:
                setattr(result, "_haldir_sth", sth)
                return result
            except Exception:
                pass
        return {"output": result, "_haldir_sth": sth}


# ── Legacy helper ─────────────────────────────────────────────────

def create_session(
    api_key: str,
    agent_id: str,
    scopes: list[str] | None = None,
    ttl: int | None = None,
    spend_limit: float | None = None,
    base_url: str = "https://haldir.xyz",
) -> tuple[HaldirClient, str]:
    """Legacy helper — returns (client, session_id). New code should
    prefer HaldirSession. Kept for back-compat with v0.1 callers."""
    client = HaldirClient(api_key=api_key, base_url=base_url)
    session = client.create_session(
        agent_id=agent_id,
        scopes=scopes or ["read"],
        ttl=ttl,
        spend_limit=spend_limit,
    )
    return client, session["session_id"]
