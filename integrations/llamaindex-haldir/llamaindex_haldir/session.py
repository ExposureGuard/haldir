"""Helper to create a Haldir session tied to a LlamaIndex run."""

from __future__ import annotations

from typing import Optional

from sdk.client import HaldirClient


def create_session(
    api_key: str,
    agent_id: str,
    scopes: Optional[list[str]] = None,
    ttl: Optional[int] = None,
    spend_limit: Optional[float] = None,
    base_url: str = "https://haldir.xyz",
) -> tuple[HaldirClient, str]:
    """Create a Haldir client and a scoped session in one step.

    Returns:
        (client, session_id). Pass both into `govern_tool` and `HaldirSecrets`
        so they enforce and log against the same session.
    """
    client = HaldirClient(api_key=api_key, base_url=base_url)
    session = client.create_session(
        agent_id=agent_id,
        scopes=scopes or ["read"],
        ttl=ttl,
        spend_limit=spend_limit,
    )
    return client, session["session_id"]
