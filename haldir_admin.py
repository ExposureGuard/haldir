"""
Haldir tenant admin overview — one endpoint, everything an operator
needs to know about their tenant's state.

Why one endpoint instead of N:

  - Buyers' first integration after auth is "show me the dashboard."
    They don't want to fan out to /sessions, /audit, /webhooks,
    /usage and merge the responses themselves.
  - Demos are easier when one curl prints the whole story.
  - The fields below map 1:1 to the boxes a sane operations dashboard
    would render — call shape == screen shape.

The module is pure functions over a DB path + tenant id + the metric
registry. No Flask. The HTTP wrapper lives in api.py and adds nothing
beyond auth + tenant resolution.

Returned shape (build_overview):

    {
      "tenant_id":   "...",
      "tier":        "free" | "pro" | "enterprise",
      "generated_at": "2026-04-19T...Z",
      "usage": {
          "actions_this_month":    int,
          "actions_limit":         int,
          "actions_pct_used":      float,    # 0.0..1.0
          "spend_usd_this_month":  float,
      },
      "sessions": {
          "active_count":  int,
          "agents_active": int,
          "agents_limit":  int,
      },
      "vault": {
          "secrets_count":         int,
          "secret_access_count":   int,      # cumulative this month
      },
      "audit": {
          "total_entries":  int,
          "flagged_7d":     int,
          "last_entry_at":  str | None,      # ISO 8601 UTC
          "chain_verified": bool,
      },
      "webhooks": {
          "registered_count":         int,
          "deliveries_24h":           int,
          "delivery_success_rate_24h": float,  # 0.0..1.0; 1.0 if 0 deliveries
          "failed_24h":               int,
      },
      "approvals": {
          "pending_count": int,
      },
      "health": {
          "status":     "ok" | "degraded" | "down",
          "components": [...],
      },
    }

Every count is bounded by SQL — no result set is unrolled into Python
lists for counting. Adds one cheap query per pillar, never N+1.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any


# Default tier ceilings, mirroring api.py:TIER_LIMITS. Duplicated as a
# fallback so this module can run in tests without importing api (which
# pulls in the whole Flask app). Callers that care about the live tier
# table pass it as `tier_limits=`.
_DEFAULT_TIER_LIMITS = {
    "free":       {"agents": 1,        "actions_per_month": 1_000},
    "pro":        {"agents": 10,       "actions_per_month": 50_000},
    "enterprise": {"agents": 999_999,  "actions_per_month": 999_999_999},
}


def build_overview(
    db_path: str,
    tenant_id: str,
    *,
    watch: Any = None,
    tier_limits: dict[str, dict[str, int]] | None = None,
    health_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compose the dashboard payload. Every section is computed from
    SQL aggregates so a tenant with millions of rows still resolves in
    a handful of milliseconds."""
    from haldir_db import get_db
    limits = tier_limits or _DEFAULT_TIER_LIMITS

    tier = _tier(db_path, tenant_id)
    tier_caps = limits.get(tier, limits["free"])

    return {
        "tenant_id":    tenant_id,
        "tier":         tier,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "usage":        _usage(db_path, tenant_id, tier_caps),
        "sessions":     _sessions(db_path, tenant_id, tier_caps),
        "vault":        _vault(db_path, tenant_id),
        "audit":        _audit(db_path, tenant_id, watch=watch),
        "webhooks":     _webhooks(db_path, tenant_id),
        "approvals":    _approvals(db_path, tenant_id),
        "compliance":   _compliance(db_path, tenant_id),
        "health":       _health(health_snapshot),
    }


# ── Section computers ────────────────────────────────────────────────

def _tier(db_path: str, tenant_id: str) -> str:
    """Subscription tier from the subscriptions table; default 'free'."""
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        row = conn.execute(
            "SELECT tier, status FROM subscriptions WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
    except Exception:
        row = None
    finally:
        conn.close()
    if row and row["status"] == "active":
        return row["tier"] or "free"
    return "free"


def _usage(db_path: str, tenant_id: str, tier_caps: dict[str, int]) -> dict[str, Any]:
    from haldir_db import get_db
    month = time.strftime("%Y-%m", time.gmtime())
    conn = get_db(db_path)
    try:
        row = conn.execute(
            "SELECT action_count, total_spend_usd FROM usage "
            "WHERE tenant_id = ? AND month = ?",
            (tenant_id, month),
        ).fetchone()
    except Exception:
        row = None
    finally:
        conn.close()
    actions = int(row["action_count"]) if row else 0
    spend = float(row["total_spend_usd"]) if row else 0.0
    cap = int(tier_caps.get("actions_per_month", 0))
    pct = (actions / cap) if cap else 0.0
    return {
        "actions_this_month":   actions,
        "actions_limit":        cap,
        "actions_pct_used":     round(pct, 4),
        "spend_usd_this_month": round(spend, 2),
    }


def _sessions(db_path: str, tenant_id: str, tier_caps: dict[str, int]) -> dict[str, Any]:
    from haldir_db import get_db
    now = time.time()
    conn = get_db(db_path)
    try:
        active_row = conn.execute(
            "SELECT COUNT(*) FROM sessions "
            "WHERE tenant_id = ? AND revoked = 0 "
            "AND (expires_at = 0 OR expires_at > ?)",
            (tenant_id, now),
        ).fetchone()
        agents_row = conn.execute(
            "SELECT COUNT(DISTINCT agent_id) FROM sessions "
            "WHERE tenant_id = ? AND revoked = 0 "
            "AND (expires_at = 0 OR expires_at > ?)",
            (tenant_id, now),
        ).fetchone()
    finally:
        conn.close()
    return {
        "active_count":  int(active_row[0]) if active_row else 0,
        "agents_active": int(agents_row[0]) if agents_row else 0,
        "agents_limit":  int(tier_caps.get("agents", 0)),
    }


def _vault(db_path: str, tenant_id: str) -> dict[str, Any]:
    from haldir_db import get_db
    month = time.strftime("%Y-%m", time.gmtime())
    conn = get_db(db_path)
    try:
        sec_row = conn.execute(
            "SELECT COUNT(*) FROM secrets WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        # secret_access_count lives on the usage table.
        try:
            usage_row = conn.execute(
                "SELECT secret_access_count FROM usage "
                "WHERE tenant_id = ? AND month = ?",
                (tenant_id, month),
            ).fetchone()
        except Exception:
            usage_row = None
    finally:
        conn.close()
    return {
        "secrets_count":       int(sec_row[0]) if sec_row else 0,
        "secret_access_count": int(usage_row["secret_access_count"]) if usage_row else 0,
    }


def _audit(db_path: str, tenant_id: str, *, watch: Any = None) -> dict[str, Any]:
    from haldir_db import get_db
    now = time.time()
    week_ago = now - 7 * 24 * 3600
    conn = get_db(db_path)
    try:
        total_row = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        flagged_row = conn.execute(
            "SELECT COUNT(*) FROM audit_log "
            "WHERE tenant_id = ? AND flagged = 1 AND timestamp >= ?",
            (tenant_id, week_ago),
        ).fetchone()
        last_row = conn.execute(
            "SELECT MAX(timestamp) FROM audit_log WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
    finally:
        conn.close()
    last_ts = last_row[0] if last_row else None
    last_iso = (
        datetime.fromtimestamp(float(last_ts), tz=timezone.utc).isoformat(timespec="seconds")
        if last_ts else None
    )
    chain_verified = True
    if watch is not None:
        try:
            result = watch.verify_chain(tenant_id=tenant_id)
            chain_verified = bool(result.get("verified", True))
        except Exception:
            chain_verified = False
    return {
        "total_entries":  int(total_row[0]) if total_row else 0,
        "flagged_7d":     int(flagged_row[0]) if flagged_row else 0,
        "last_entry_at":  last_iso,
        "chain_verified": chain_verified,
    }


def _webhooks(db_path: str, tenant_id: str) -> dict[str, Any]:
    from haldir_db import get_db
    cutoff = time.time() - 24 * 3600
    conn = get_db(db_path)
    try:
        reg_row = conn.execute(
            "SELECT COUNT(*) FROM webhooks WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        # 2xx = success; rely on status_code column, not the
        # webhooks.fire_count counter (per-endpoint, not per-event).
        try:
            total_row = conn.execute(
                "SELECT COUNT(*) FROM webhook_deliveries "
                "WHERE tenant_id = ? AND created_at >= ?",
                (tenant_id, cutoff),
            ).fetchone()
            success_row = conn.execute(
                "SELECT COUNT(*) FROM webhook_deliveries "
                "WHERE tenant_id = ? AND created_at >= ? "
                "AND status_code >= 200 AND status_code < 300",
                (tenant_id, cutoff),
            ).fetchone()
        except Exception:
            total_row = None
            success_row = None
    finally:
        conn.close()
    total = int(total_row[0]) if total_row else 0
    success = int(success_row[0]) if success_row else 0
    rate = (success / total) if total else 1.0
    return {
        "registered_count":          int(reg_row[0]) if reg_row else 0,
        "deliveries_24h":            total,
        "delivery_success_rate_24h": round(rate, 4),
        "failed_24h":                total - success,
    }


def _approvals(db_path: str, tenant_id: str) -> dict[str, Any]:
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM approval_requests "
            "WHERE tenant_id = ? AND status = 'pending'",
            (tenant_id,),
        ).fetchone()
    except Exception:
        row = None
    finally:
        conn.close()
    return {"pending_count": int(row[0]) if row else 0}


def _compliance(db_path: str, tenant_id: str) -> dict[str, Any]:
    """Surface the recurring evidence-pack schedules so an operator
    can see at-a-glance that compliance is on autopilot. Counts +
    next-due summary; the full per-schedule list lives at
    /v1/compliance/schedules."""
    try:
        import haldir_compliance_scheduler as sched
        rows = sched.list_schedules(db_path, tenant_id)
    except Exception:
        rows = []
    active = [r for r in rows if r["active"]]
    next_due_ts = min((r["next_due"] for r in active), default=None)
    next_due_iso = (
        datetime.fromtimestamp(float(next_due_ts), tz=timezone.utc)
                .isoformat(timespec="seconds")
        if next_due_ts else None
    )
    return {
        "schedules_count":  len(rows),
        "active_count":     len(active),
        "next_due_at":      next_due_iso,
        "last_run_status":  (
            max(rows, key=lambda r: r["last_run_at"])["last_status"]
            if rows else ""
        ),
    }


def _health(snapshot: dict[str, Any] | None) -> dict[str, Any]:
    """Embed the system health from haldir_status (if the caller passed
    it through). Trims the components to (name, state, message) so the
    dashboard payload doesn't double-include everything the /status
    page already exposes."""
    if not snapshot:
        return {"status": "ok", "components": []}
    return {
        "status": snapshot.get("status", "ok"),
        "components": [
            {"name": c.get("name"), "state": c.get("state"),
             "message": c.get("message")}
            for c in snapshot.get("components", [])
        ],
    }
