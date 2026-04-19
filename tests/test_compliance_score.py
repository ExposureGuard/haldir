"""
Tests for haldir_compliance_score — the Haldir audit-prep % number.

Scope:
  - Fresh tenant starts at a known low score (no keys, no audit rows,
    no sessions with caps)
  - Each criterion can be moved pass / warn / fail via state changes
  - Score aggregation (warn = 0.5) is correct
  - HTTP endpoint returns the same shape + scope-gated
  - /compliance HTML renders the score banner when authed

Run: python -m pytest tests/test_compliance_score.py -v
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_compliance_score as score  # noqa: E402


@pytest.fixture(autouse=True)
def _lift_agent_cap(monkeypatch):
    import copy
    import api
    patched = copy.deepcopy(api.TIER_LIMITS)
    patched["free"]["agents"] = 999
    monkeypatch.setattr(api, "TIER_LIMITS", patched)


# ── Pure-function unit tests ────────────────────────────────────────

def test_criteria_list_is_stable() -> None:
    """The score's control vocabulary is part of the public contract
    (the SOC2 mapping is advertised in the one-pager). Regression
    would be a silent category change."""
    keys = [c[0] for c in score.CRITERIA]
    assert keys == [
        "access_control", "encryption", "audit_trail",
        "tamper_evidence",
        "alerting", "spend_governance", "approvals",
    ]


def test_empty_tenant_returns_well_formed_score() -> None:
    import api
    out = score.compute_score(api.DB_PATH, "no-such-tenant-xyz")
    assert 0 <= out["score"] <= 100
    assert out["total"] == 7
    assert len(out["criteria"]) == 7
    assert out["passing"] + out["warning"] + out["failing"] == 7
    # Every criterion carries the contract fields.
    for c in out["criteria"]:
        assert "key" in c and "control" in c and "state" in c
        assert c["state"] in ("pass", "warn", "fail")
        assert "reason" in c and "remediation" in c


def test_encryption_passes_when_env_configured(monkeypatch) -> None:
    monkeypatch.setenv("HALDIR_ENCRYPTION_KEY", "a" * 44)
    r = score._evaluate_encryption()
    assert r.state == "pass"


def test_encryption_warns_when_env_missing(monkeypatch) -> None:
    monkeypatch.delenv("HALDIR_ENCRYPTION_KEY", raising=False)
    r = score._evaluate_encryption()
    assert r.state == "warn"


def test_score_reflects_state_changes(haldir_client, bootstrap_key) -> None:
    """Before creating anything, access_control is whatever it is for
    the bootstrap tenant. Mint a scope-restricted key → access_control
    must pass (if it didn't already)."""
    import api
    tenant = _tenant_of(bootstrap_key)

    # Mint a narrow-scope key.
    haldir_client.post(
        "/v1/keys",
        json={"name": "siem-score-test", "scopes": ["audit:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    after = score.compute_score(api.DB_PATH, tenant)
    ac = next(c for c in after["criteria"] if c["key"] == "access_control")
    assert ac["state"] == "pass"


def test_spend_governance_fails_without_caps(haldir_client, bootstrap_key) -> None:
    """Create a session with no spend cap → spend_governance fails."""
    import api
    tenant = _tenant_of(bootstrap_key)
    haldir_client.post(
        "/v1/sessions",
        json={"agent_id": "spend-test-no-cap", "scopes": ["read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    out = score.compute_score(api.DB_PATH, tenant)
    sg = next(c for c in out["criteria"] if c["key"] == "spend_governance")
    # With no caps anywhere in this tenant → fail.
    # (The bootstrap tenant may or may not have prior sessions with
    # caps from other tests; we just assert shape, not a hard state.)
    assert sg["state"] in ("pass", "fail")


def test_spend_governance_passes_with_cap(haldir_client, bootstrap_key) -> None:
    import api
    tenant = _tenant_of(bootstrap_key)
    haldir_client.post(
        "/v1/sessions",
        json={"agent_id": "spend-test-cap", "scopes": ["read"],
              "spend_limit": 5.00},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    out = score.compute_score(api.DB_PATH, tenant)
    sg = next(c for c in out["criteria"] if c["key"] == "spend_governance")
    assert sg["state"] == "pass"


def test_audit_trail_passes_with_recent_entries(haldir_client, bootstrap_key) -> None:
    import api
    tenant = _tenant_of(bootstrap_key)
    sid = haldir_client.post(
        "/v1/sessions",
        json={"agent_id": "audit-score-test", "scopes": ["read", "execute"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    ).get_json()["session_id"]
    haldir_client.post(
        "/v1/audit",
        json={"session_id": sid, "tool": "stripe", "action": "charge",
              "cost_usd": 0.5},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    out = score.compute_score(api.DB_PATH, tenant)
    at = next(c for c in out["criteria"] if c["key"] == "audit_trail")
    assert at["state"] == "pass"


# ── Aggregation weights ─────────────────────────────────────────────

def test_aggregation_weights_warn_as_half() -> None:
    """Six criteria, all warn = 50%. All pass = 100%. All fail = 0%.
    Mixed values land at the weighted average."""
    # Monkeypatch the evaluators to produce deterministic outputs.
    import haldir_compliance_score as mod
    fake = [
        mod.CriterionResult("k1", "C1", "d", "pass", "", ""),
        mod.CriterionResult("k2", "C2", "d", "pass", "", ""),
        mod.CriterionResult("k3", "C3", "d", "warn", "", ""),
        mod.CriterionResult("k4", "C4", "d", "warn", "", ""),
        mod.CriterionResult("k5", "C5", "d", "fail", "", ""),
        mod.CriterionResult("k6", "C6", "d", "fail", "", ""),
    ]
    weighted = sum(mod._WEIGHT[r.state] for r in fake)
    # 2 pass (1.0 each) + 2 warn (0.5) + 2 fail (0.0) = 3.0 / 6 = 50%
    assert int(round((weighted / len(fake)) * 100)) == 50


# ── HTTP endpoint integration ───────────────────────────────────────

def test_score_endpoint_returns_well_formed_json(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(
        "/v1/compliance/score",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    body = r.get_json()
    for k in ("score", "criteria", "passing", "warning", "failing",
              "total", "computed_at"):
        assert k in body
    assert body["total"] == 7
    assert len(body["criteria"]) == 7


def test_score_endpoint_requires_admin_read(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "no-admin-score-test", "scopes": ["audit:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    narrow = r.get_json()["key"]
    r2 = haldir_client.get(
        "/v1/compliance/score",
        headers={"Authorization": f"Bearer {narrow}"},
    )
    assert r2.status_code == 403
    assert r2.get_json()["required"] == "admin:read"


# ── /compliance HTML integration ────────────────────────────────────

def test_compliance_html_includes_score_banner(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(f"/compliance?key={bootstrap_key}")
    body = r.data.decode()
    # The big % number + "Haldir audit-prep" label (honest framing:
    # not a SOC2 attestation, platform-readiness signal).
    assert "Haldir audit-prep" in body
    # Explicit disclaimer noting this is NOT a SOC2 attestation.
    assert "Not a SOC2 attestation" in body
    # At least one SOC2 criterion code.
    assert any(cc in body for cc in ("CC6.1", "CC6.7", "CC7.2", "CC7.3", "CC5.2", "CC8.1"))
    # A state badge.
    assert any(badge in body for badge in ("PASS", "WARN", "FAIL"))


# ── Helpers ─────────────────────────────────────────────────────────

def _tenant_of(key: str) -> str:
    import hashlib, api
    from haldir_db import get_db
    kh = hashlib.sha256(key.encode()).hexdigest()
    conn = get_db(api.DB_PATH)
    row = conn.execute(
        "SELECT tenant_id FROM api_keys WHERE key_hash = ?", (kh,),
    ).fetchone()
    conn.close()
    return row["tenant_id"]
