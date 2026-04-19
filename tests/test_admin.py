"""
Tests for haldir_admin — the tenant-admin dashboard endpoint.

Scope:
  - build_overview returns the documented sections, all present
  - Each section's numbers reflect actual DB state (mint a session,
    log an audit row, register a webhook → the counts move)
  - GET /v1/admin/overview proxies build_overview correctly + auth
  - Tier defaulting (no subscription row → "free")
  - Webhook 24h success rate is 1.0 when no deliveries yet (not 0/0)
  - Tenant isolation: rows from another tenant don't bleed in

Run: python -m pytest tests/test_admin.py -v
"""

from __future__ import annotations

import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import api  # noqa: E402
import haldir_admin  # noqa: E402


@pytest.fixture(autouse=True)
def _lift_agent_cap(monkeypatch) -> None:
    """Free tier caps agents at 1; this suite mints multiple. Lift it
    so tests can exercise multi-agent paths."""
    import copy
    patched = copy.deepcopy(api.TIER_LIMITS)
    patched["free"]["agents"] = 999
    monkeypatch.setattr(api, "TIER_LIMITS", patched)


def _tenant(bootstrap_key: str) -> str:
    kh = hashlib.sha256(bootstrap_key.encode()).hexdigest()
    from haldir_db import get_db
    conn = get_db(api.DB_PATH)
    row = conn.execute(
        "SELECT tenant_id FROM api_keys WHERE key_hash = ?", (kh,),
    ).fetchone()
    conn.close()
    return row["tenant_id"]


# ── Shape ──────────────────────────────────────────────────────────────

def test_overview_has_every_documented_section(haldir_client, bootstrap_key) -> None:
    tenant = _tenant(bootstrap_key)
    out = haldir_admin.build_overview(api.DB_PATH, tenant, watch=api.watch,
                                      tier_limits=api.TIER_LIMITS)
    expected = {
        "tenant_id", "tier", "generated_at",
        "usage", "sessions", "vault", "audit",
        "webhooks", "approvals", "compliance", "health",
    }
    assert set(out.keys()) >= expected
    # Compliance section shape — surfaces recurring schedules.
    assert {"schedules_count", "active_count",
            "next_due_at", "last_run_status"} <= set(out["compliance"])
    # Section subkeys.
    assert {"actions_this_month", "actions_limit",
            "actions_pct_used", "spend_usd_this_month"} <= set(out["usage"])
    assert {"active_count", "agents_active", "agents_limit"} <= set(out["sessions"])
    assert {"secrets_count", "secret_access_count"} <= set(out["vault"])
    assert {"total_entries", "flagged_7d",
            "last_entry_at", "chain_verified"} <= set(out["audit"])
    assert {"registered_count", "deliveries_24h",
            "delivery_success_rate_24h", "failed_24h"} <= set(out["webhooks"])
    assert "pending_count" in out["approvals"]


def test_tier_defaults_to_free_with_no_subscription_row(haldir_client, bootstrap_key) -> None:
    tenant = _tenant(bootstrap_key)
    out = haldir_admin.build_overview(api.DB_PATH, tenant)
    assert out["tier"] == "free"


# ── Numbers move with state ────────────────────────────────────────────

def test_session_creation_increments_active_count(haldir_client, bootstrap_key) -> None:
    tenant = _tenant(bootstrap_key)
    before = haldir_admin.build_overview(api.DB_PATH, tenant)["sessions"]["active_count"]

    r = haldir_client.post(
        "/v1/sessions",
        json={"agent_id": "admin-test-agent", "scopes": ["read", "execute"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 201

    after = haldir_admin.build_overview(api.DB_PATH, tenant)["sessions"]["active_count"]
    assert after == before + 1


def test_audit_log_entry_moves_total_and_last_entry_at(haldir_client, bootstrap_key) -> None:
    tenant = _tenant(bootstrap_key)
    # Spawn a session for the audit row to attach to.
    s = haldir_client.post(
        "/v1/sessions",
        json={"agent_id": "audit-stamp-agent", "scopes": ["read", "execute"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    ).get_json()
    sid = s["session_id"]

    before = haldir_admin.build_overview(api.DB_PATH, tenant)["audit"]
    haldir_client.post(
        "/v1/audit",
        json={"session_id": sid, "tool": "stripe", "action": "ping",
              "cost_usd": 0.0},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    after = haldir_admin.build_overview(api.DB_PATH, tenant)["audit"]
    assert after["total_entries"] >= before["total_entries"] + 1
    assert after["last_entry_at"] is not None


# ── Webhook success rate edge case ────────────────────────────────────

def test_webhook_success_rate_is_one_when_no_deliveries(haldir_client, bootstrap_key) -> None:
    """0/0 should not return 0.0 (looks like a 100% failure rate); the
    sane convention is 1.0 — there's no failure data to refute the
    'fully healthy' assumption yet."""
    tenant = _tenant(bootstrap_key)
    out = haldir_admin.build_overview(api.DB_PATH, tenant)
    if out["webhooks"]["deliveries_24h"] == 0:
        assert out["webhooks"]["delivery_success_rate_24h"] == 1.0


# ── Tenant isolation ──────────────────────────────────────────────────

def test_unknown_tenant_returns_zero_counts() -> None:
    """A made-up tenant id should pass through to a clean zero-state
    overview — no exceptions, no leakage from real tenants."""
    out = haldir_admin.build_overview(api.DB_PATH, "no-such-tenant-xyz")
    assert out["sessions"]["active_count"] == 0
    assert out["usage"]["actions_this_month"] == 0
    assert out["audit"]["total_entries"] == 0
    assert out["webhooks"]["registered_count"] == 0
    assert out["approvals"]["pending_count"] == 0


# ── HTTP route ────────────────────────────────────────────────────────

def test_admin_overview_endpoint_returns_payload(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(
        "/v1/admin/overview",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    body = r.get_json()
    for key in ("tenant_id", "tier", "usage", "sessions", "vault",
                "audit", "webhooks", "approvals", "health"):
        assert key in body
    # Health is computed from haldir_status, which always returns at
    # least the four canonical components.
    assert isinstance(body["health"]["components"], list)


def test_admin_overview_requires_auth(haldir_client) -> None:
    r = haldir_client.get("/v1/admin/overview")
    assert r.status_code in (401, 403)
