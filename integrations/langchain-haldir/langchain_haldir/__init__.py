"""
langchain-haldir — governance layer for LangChain agents.

Two-line adoption::

    from langchain_haldir import HaldirSession

    with HaldirSession.for_agent("my-bot") as haldir:
        executor = AgentExecutor(..., callbacks=[haldir.handler])
        result = executor.invoke({"input": "..."})
    # Session auto-revoked. Every tool + LLM call audited.
    # STH in result["_haldir_sth"] — pin it for offline verification.

Advanced / explicit path::

    from langchain_haldir import HaldirCallbackHandler, GovernedTool, HaldirSecrets

Audit trails, spend caps (including LLM token cost), secrets vault,
instant revocation, and RFC 6962 tree-head stamping at run end —
wired into any LangChain agent or tool.
"""

from __future__ import annotations

from typing import Any

from sdk.client import HaldirClient

from .callback import HaldirCallbackHandler
from .session import HaldirSession
from .tool import GovernedTool
from .secrets import HaldirSecrets

__version__ = "0.2.0"

__all__ = [
    "HaldirSession",
    "HaldirCallbackHandler",
    "GovernedTool",
    "HaldirSecrets",
    "create_session",
]


def create_session(
    api_key: str,
    agent_id: str,
    scopes: list[str] | None = None,
    ttl: int = 3600,
    spend_limit: float | None = None,
    base_url: str = "https://haldir.xyz",
) -> tuple[HaldirClient, str]:
    """Convenience: create a Haldir session, return (client, session_id).

    Usage::

        client, session_id = create_session(
            api_key="hld_xxx",
            agent_id="my-langchain-agent",
            scopes=["read", "search", "spend"],
            spend_limit=50.0,
        )
        cb = HaldirCallbackHandler(client, session_id)
        executor = AgentExecutor(..., callbacks=[cb])
    """
    client = HaldirClient(api_key=api_key, base_url=base_url)
    session = client.create_session(
        agent_id,
        scopes=scopes,
        ttl=ttl,
        spend_limit=spend_limit,
    )
    return client, session["session_id"]
