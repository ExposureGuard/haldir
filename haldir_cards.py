"""Capability cards — an agent made discoverable, by its owner, deliberately.

The register answers "which agents do we run". A card answers "which of them
are we willing to be found by". It is the first part of Haldir that faces
outward, so the rules that keep it honest are stated here rather than
discovered later:

1. **Opt-in per agent, and withdrawal means deletion.** Publishing names one
   agent; unpublishing deletes the row. "Hidden" and "gone" are different
   promises to an operator, and only one of them is worth making.
2. **Capability-only. Never operational data.** A card carries what the owner
   wrote about what an agent *does* — never sessions, spend, actions, flags,
   the tenant id, or the agent's internal id. `public_cards()` is the only
   projection that leaves the building, and it is built by naming the fields
   it includes rather than by removing the ones it does not: a column added
   to the table later cannot leak by default.
3. **Published, not verified.** Haldir does not check that a card is true, and
   the index says so. A directory that implies endorsement turns someone
   else's overstatement into our misrepresentation.
4. **An agent must exist to be published.** A card is only issuable for an
   agent present in the register — derived from activity or registration — so
   a listing always refers to an agent this deployment has actually seen.

The table is created by `migrations/010_agent_cards.sql`; this module creates
it too, because stores in this codebase own their schema and a test asserts
the two definitions agree rather than trusting that they do.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any
from urllib.parse import urlsplit

# Bounds, not suggestions: a card is public text someone else renders.
MAX_DISPLAY_NAME = 120
MAX_DESCRIPTION = 500
MAX_CAPABILITIES = 12
MAX_CAPABILITY_LEN = 64
MAX_CONTACT_URL = 300

_DDL = """
    CREATE TABLE IF NOT EXISTS agent_cards (
        card_id       TEXT PRIMARY KEY,
        tenant_id     TEXT NOT NULL,
        agent_id      TEXT NOT NULL,
        display_name  TEXT NOT NULL DEFAULT '',
        description   TEXT NOT NULL DEFAULT '',
        capabilities  TEXT NOT NULL DEFAULT '[]',
        contact_url   TEXT NOT NULL DEFAULT '',
        published_at  REAL NOT NULL,
        updated_at    REAL NOT NULL,
        UNIQUE (tenant_id, agent_id)
    )
"""


class CardValidationError(ValueError):
    """A card the operator asked for that cannot be published as described."""


def _get_db(db_path: str) -> Any:
    from haldir_db import get_db
    conn = get_db(db_path)
    conn.execute(_DDL)
    return conn


def _clean_capabilities(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [c.strip() for c in raw.split(",")]
    if not isinstance(raw, list):
        raise CardValidationError("capabilities must be a list of short strings")
    if len(raw) > MAX_CAPABILITIES:
        raise CardValidationError(f"at most {MAX_CAPABILITIES} capabilities")
    out: list[str] = []
    for item in raw:
        text = str(item).strip()
        if not text:
            continue
        if len(text) > MAX_CAPABILITY_LEN:
            raise CardValidationError(
                f"a capability is longer than {MAX_CAPABILITY_LEN} characters"
            )
        out.append(text)
    return out


def _clean_contact(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if len(url) > MAX_CONTACT_URL:
        raise CardValidationError("contact_url is too long")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        # Displayed, not fetched — so this is not an SSRF guard. It is a
        # phishing guard: a public directory rendering `javascript:` or a
        # `file:` path is a link someone else's users click.
        raise CardValidationError("contact_url must be an http(s) URL")
    return url


def publish(
    db_path: str,
    tenant_id: str,
    agent_id: str,
    *,
    display_name: str,
    description: str = "",
    capabilities: Any = None,
    contact_url: str = "",
) -> dict[str, Any]:
    """Publish or update this tenant's card for one agent.

    Raises `CardValidationError` on anything the directory should not carry.
    The caller is responsible for checking the agent exists in the register —
    the API route does, so a card cannot refer to an agent nobody has seen.
    """
    display_name = (display_name or "").strip()
    description = (description or "").strip()
    if not display_name:
        raise CardValidationError("display_name is required")
    if len(display_name) > MAX_DISPLAY_NAME:
        raise CardValidationError(f"display_name is longer than {MAX_DISPLAY_NAME} characters")
    if len(description) > MAX_DESCRIPTION:
        raise CardValidationError(f"description is longer than {MAX_DESCRIPTION} characters")
    caps = _clean_capabilities(capabilities)
    contact = _clean_contact(contact_url)

    now = time.time()
    conn = _get_db(db_path)
    try:
        existing = conn.execute(
            "SELECT card_id, published_at FROM agent_cards "
            "WHERE tenant_id = ? AND agent_id = ?",
            (tenant_id, agent_id),
        ).fetchone()
        if existing:
            card_id = str(existing["card_id"])
            published_at = float(existing["published_at"])
            conn.execute(
                "UPDATE agent_cards SET display_name = ?, description = ?, "
                "capabilities = ?, contact_url = ?, updated_at = ? "
                "WHERE card_id = ?",
                (display_name, description, json.dumps(caps), contact, now, card_id),
            )
        else:
            card_id = "card_" + secrets.token_urlsafe(16)
            published_at = now
            conn.execute(
                "INSERT INTO agent_cards (card_id, tenant_id, agent_id, display_name, "
                "description, capabilities, contact_url, published_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (card_id, tenant_id, agent_id, display_name, description,
                 json.dumps(caps), contact, published_at, now),
            )
        conn.commit()
    finally:
        conn.close()

    return {
        "card_id":      card_id,
        "agent_id":     agent_id,
        "display_name": display_name,
        "description":  description,
        "capabilities": caps,
        "contact_url":  contact,
        "published_at": published_at,
        "updated_at":   now,
        "updated":      bool(existing),
    }


def unpublish(db_path: str, tenant_id: str, agent_id: str) -> bool:
    """Withdraw a card. True when one was removed.

    Deletes rather than flags: the operator's promise is that they can take it
    back, and a row that still exists cannot honour that.
    """
    conn = _get_db(db_path)
    try:
        row = conn.execute(
            "SELECT card_id FROM agent_cards WHERE tenant_id = ? AND agent_id = ?",
            (tenant_id, agent_id),
        ).fetchone()
        if not row:
            return False
        conn.execute("DELETE FROM agent_cards WHERE card_id = ?", (row["card_id"],))
        conn.commit()
    finally:
        conn.close()
    return True


def get_card(db_path: str, tenant_id: str, agent_id: str) -> dict[str, Any] | None:
    """The owner's view of their own card."""
    conn = _get_db(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM agent_cards WHERE tenant_id = ? AND agent_id = ?",
            (tenant_id, agent_id),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {
        "card_id":      row["card_id"],
        "agent_id":     row["agent_id"],
        "display_name": row["display_name"],
        "description":  row["description"],
        "capabilities": _parse(row["capabilities"]),
        "contact_url":  row["contact_url"],
        "published_at": float(row["published_at"]),
        "updated_at":   float(row["updated_at"]),
    }


def card_ids_for_tenant(db_path: str, tenant_id: str) -> dict[str, str]:
    """`agent_id -> card_id` for a tenant, so the register can mark which of
    an operator's agents are discoverable without a query per agent."""
    conn = _get_db(db_path)
    try:
        rows = conn.execute(
            "SELECT agent_id, card_id FROM agent_cards WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
    finally:
        conn.close()
    return {str(r["agent_id"]): str(r["card_id"]) for r in rows}


def public_cards(db_path: str) -> list[dict[str, Any]]:
    """The projection that leaves the building.

    Built by naming what it includes. If a column is added to the table, it
    does not appear here until someone adds it deliberately — the alternative
    (copy the row, then delete the private fields) is one forgotten deletion
    away from publishing operational data.
    """
    conn = _get_db(db_path)
    try:
        rows = conn.execute(
            "SELECT card_id, display_name, description, capabilities, "
            "contact_url, published_at, updated_at "
            "FROM agent_cards ORDER BY display_name COLLATE NOCASE"
        ).fetchall()
    finally:
        conn.close()
    return [
        {
            "card_id":      r["card_id"],
            "display_name": r["display_name"],
            "description":  r["description"],
            "capabilities": _parse(r["capabilities"]),
            "contact_url":  r["contact_url"],
            "published_at": float(r["published_at"]),
            "updated_at":   float(r["updated_at"]),
        }
        for r in rows
    ]


def _parse(raw: Any) -> list[str]:
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return [str(v) for v in value] if isinstance(value, list) else []
