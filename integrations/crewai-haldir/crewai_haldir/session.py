"""
HaldirSession for CrewAI — context manager that auto-mints + auto-revokes.

The two-line promise::

    from crewai_haldir import HaldirSession

    with HaldirSession.for_agent("research-crew",
                                  scopes=["read", "search"],
                                  spend_limit=10.0) as haldir:
        # Use haldir.client + haldir.session_id to wrap your
        # CrewAI tools with GovernedTool.wrap(...). Session is
        # auto-revoked on scope exit, even on exception.
        ...
        # After crew.kickoff(), stamp the run's output with the
        # current STH so an auditor can verify later:
        #   result = haldir.stamp_sth(crew.kickoff())

Why it exists:

  CrewAI doesn't have a single BaseCallbackHandler primitive the way
  LangChain does, so the integration lives at the TOOL level
  (GovernedTool.wrap) and the SESSION level (this module). The
  session handles lifecycle + ergonomics; GovernedTool handles the
  per-call scope check + audit write.
"""

from __future__ import annotations

import os
from types import TracebackType
from typing import Any

from sdk.client import HaldirClient


class HaldirSession:
    """Haldir session lifecycle scoped to a CrewAI run.

    Usage::

        with HaldirSession.for_agent("my-crew") as haldir:
            search_tool = GovernedTool.wrap(
                SerperDevTool(),
                client=haldir.client,
                session_id=haldir.session_id,
                required_scope="search",
                cost_usd=0.01,
            )
            crew = Crew(agents=[...], tasks=[...])
            result = haldir.stamp_sth(crew.kickoff())

    ``result`` now carries an `_haldir_sth` attribute (if it's a dict or
    has ``__dict__``) with the tenant's current Signed Tree Head.
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
        """Attach the current STH to a CrewAI run result so an auditor
        can pin it.

        Behaviour depends on the shape `crew.kickoff()` returned:

          - dict: writes result["_haldir_sth"] = sth
          - object with __dict__: sets result._haldir_sth = sth
          - anything else: wraps into a new dict
              {"output": result, "_haldir_sth": sth}

        Returns the (possibly-wrapped) result unchanged in identity
        whenever possible. Network errors fetching the STH never
        break the caller's output path — we return the original
        result unmodified if the fetch fails."""
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
