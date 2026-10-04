"""The agent register — every agent that has acted in this tenant.

Why this exists
---------------
`agents` has been written on every session creation since migration 001
(`Gate.register_agent`, reached from `POST /v1/sessions` and the delegation
path) and **nothing has ever read it**. Meanwhile `sessions`, `audit_log`,
`approval_requests` and the delegation tree all carry `agent_id`. So the
register already existed as state; this module is the surface.

It is also the artifact the assurance story rests on. The question an auditor,
a customer or a regulator asks is *"show me your register of AI systems"* —
which agents exist, what each is allowed to do, what each actually did, and
which of them can spawn others. This answers it from what the product already
recorded.

Two deliberate choices:

  * **Derived from activity, not just registration.** An agent that acted but
    was never explicitly registered — an old row, a session minted straight
    through the Gate — still belongs in a register. An incomplete register is
    worse than none, because it reads as complete.

  * **Pure SQL aggregates, one tenant.** Five grouped queries regardless of
    how many agents, sessions or audit rows a tenant has accumulated. No
    N+1, no Flask, no globals — trivial to unit-test.
"""

from __future__ import annotations

import json
import time
from typing import Any

# Active means the same thing here as it does in `haldir_admin._sessions`:
# not revoked, and not past a TTL that was set. `expires_at = 0` is "no
# expiry", which is why it is spelled out rather than implied.
_ACTIVE = "revoked = 0 AND (expires_at = 0 OR expires_at > ?)"


def _rows(conn: Any, sql: str, params: tuple) -> list[Any]:
    # `conn.execute` is Any (sqlite3 and the psycopg2 wrapper disagree on its
    # return type), so the list is named and returned through a typed binding
    # rather than returned directly — `warn_return_any` is on for this module.
    rows: list[Any] = conn.execute(sql, params).fetchall()
    return rows


def _by_agent(conn: Any, sql: str, params: tuple) -> dict[str, Any]:
    """Run a `... GROUP BY agent_id` query and index the rows by agent."""
    out: dict[str, Any] = {}
    for row in _rows(conn, sql, params):
        out[str(row["agent_id"])] = row
    return out


def _delegation_edges(conn: Any, tenant_id: str) -> dict[str, set[str]]:
    """parent agent -> the agents it spawned.

    `parent_session_id` arrives by ALTER (haldir_db), so a database that has
    not migrated returns no edges rather than raising — the same defensive
    read the Gate does for the column.
    """
    edges: dict[str, set[str]] = {}
    try:
        rows = _rows(
            conn,
            "SELECT parent.agent_id AS parent_agent, child.agent_id AS child_agent "
            "FROM sessions AS child "
            "JOIN sessions AS parent ON child.parent_session_id = parent.session_id "
            "WHERE child.tenant_id = ? AND child.parent_session_id != '' "
            "GROUP BY parent.agent_id, child.agent_id",
            (tenant_id,),
        )
    except Exception:
        return edges
    for row in rows:
        edges.setdefault(str(row["parent_agent"]), set()).add(str(row["child_agent"]))
    return edges


def build_register(
    db_path: str,
    tenant_id: str,
    *,
    agent_id: str | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """The register for one tenant. Pass `agent_id` for a single entry.

    Returns `{"summary": {...}, "agents": [...]}`, most recently active first.
    """
    from haldir_db import get_db

    now = now if now is not None else time.time()
    conn = get_db(db_path)
    try:
        where_agent = " AND agent_id = ?" if agent_id else ""
        agent_params: tuple = (tenant_id, agent_id) if agent_id else (tenant_id,)

        policies = _by_agent(
            conn,
            "SELECT agent_id, default_scopes, max_spend, metadata, created_at "
            "FROM agents WHERE tenant_id = ?" + where_agent,
            agent_params,
        )
        session_rows = _by_agent(
            conn,
            "SELECT agent_id, COUNT(*) AS total, "
            "  SUM(CASE WHEN " + _ACTIVE + " THEN 1 ELSE 0 END) AS active, "
            "  SUM(CASE WHEN revoked != 0 THEN 1 ELSE 0 END) AS revoked, "
            "  SUM(spend_limit) AS limit_total, SUM(spent) AS spent_total, "
            "  MIN(created_at) AS first_seen, MAX(created_at) AS last_session_at "
            "FROM sessions WHERE tenant_id = ?" + where_agent +
            " GROUP BY agent_id",
            (now, tenant_id) + ((agent_id,) if agent_id else ()),
        )
        activity_rows = _by_agent(
            conn,
            "SELECT agent_id, COUNT(*) AS actions, SUM(cost_usd) AS cost_usd, "
            "  SUM(flagged) AS flagged, MAX(timestamp) AS last_action_at "
            "FROM audit_log WHERE tenant_id = ?" + where_agent +
            " GROUP BY agent_id",
            agent_params,
        )
        approval_rows = _by_agent(
            conn,
            "SELECT agent_id, COUNT(*) AS requested, "
            "  SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending "
            "FROM approval_requests WHERE tenant_id = ?" + where_agent +
            " GROUP BY agent_id",
            agent_params,
        )
        edges = _delegation_edges(conn, tenant_id)
    finally:
        conn.close()

    # Registered, or merely present: both belong in a register.
    known = set(policies) | set(session_rows) | set(activity_rows)
    if agent_id:
        known &= {agent_id}

    entries: list[dict[str, Any]] = []
    for name in known:
        policy = policies.get(name)
        sessions = session_rows.get(name)
        activity = activity_rows.get(name)
        approvals = approval_rows.get(name)

        default_scopes: list[str] = []
        if policy is not None:
            try:
                default_scopes = json.loads(policy["default_scopes"] or "[]")
            except (TypeError, ValueError):
                default_scopes = []
        metadata: dict[str, Any] = {}
        if policy is not None:
            try:
                metadata = json.loads(policy["metadata"] or "{}")
            except (TypeError, ValueError):
                metadata = {}

        first_seen = sessions["first_seen"] if sessions else None
        last_session_at = sessions["last_session_at"] if sessions else None
        last_action_at = activity["last_action_at"] if activity else None
        last_seen = max(
            (t for t in (last_session_at, last_action_at) if t is not None),
            default=None,
        )

        entries.append({
            "agent_id": name,
            "registered": policy is not None,
            "registered_at": float(policy["created_at"]) if policy is not None else None,
            "default_scopes": default_scopes,
            "max_spend": float(policy["max_spend"]) if policy is not None else 0.0,
            "metadata": metadata,
            "first_seen": float(first_seen) if first_seen is not None else None,
            "last_seen": float(last_seen) if last_seen is not None else None,
            "sessions": {
                "total": int(sessions["total"]) if sessions else 0,
                "active": int(sessions["active"] or 0) if sessions else 0,
                "revoked": int(sessions["revoked"] or 0) if sessions else 0,
            },
            "spend": {
                "session_limits_usd": round(float(sessions["limit_total"] or 0.0), 6) if sessions else 0.0,
                "spent_usd": round(float(sessions["spent_total"] or 0.0), 6) if sessions else 0.0,
            },
            "activity": {
                "actions": int(activity["actions"]) if activity else 0,
                "cost_usd": round(float(activity["cost_usd"] or 0.0), 6) if activity else 0.0,
                "flagged": int(activity["flagged"] or 0) if activity else 0,
                "last_action_at": float(last_action_at) if last_action_at is not None else None,
            },
            "approvals": {
                "requested": int(approvals["requested"]) if approvals else 0,
                "pending": int(approvals["pending"] or 0) if approvals else 0,
            },
            "delegates_to": sorted(edges.get(name, ())),
            "spawned_by": sorted(
                parent for parent, children in edges.items() if name in children
            ),
        })

    entries.sort(key=lambda e: (e["last_seen"] or 0.0, e["agent_id"]), reverse=True)

    summary = {
        "agents": len(entries),
        "agents_active": sum(1 for e in entries if e["sessions"]["active"] > 0),
        "agents_flagged": sum(1 for e in entries if e["activity"]["flagged"] > 0),
        "actions": sum(e["activity"]["actions"] for e in entries),
        # Two numbers, because they answer different questions and can
        # disagree. `session_spend_usd` is what the Gate metered against spend
        # caps; `audited_cost_usd` is what the append-only log recorded per
        # action. A payment moves both; a tool call that only logs a cost moves
        # the second. Reporting one as "spend" would quietly pick a side.
        "session_spend_usd": round(sum(e["spend"]["spent_usd"] for e in entries), 6),
        "audited_cost_usd": round(sum(e["activity"]["cost_usd"] for e in entries), 6),
        "flagged_actions": sum(e["activity"]["flagged"] for e in entries),
        "delegation_edges": sum(len(e["delegates_to"]) for e in entries),
    }
    return {
        "tenant_id": tenant_id,
        "generated_at": now,
        "summary": summary,
        "agents": entries,
    }
