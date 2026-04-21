"""
Tests for the self-published STH log + anti-equivocation verifier.

Why this matters: the STH log is the answer to "who watches the
watchman?" If Haldir ever rewrites the audit log to fit a current
narrative, an auditor with a previously-pinned STH can prove it
catastrophically — the recorded row at that tree_size won't match
their pin. These tests pin the contract that makes that work.

Scope:
  - record() is idempotent on (tenant, tree_size); duplicate calls
    don't write duplicate rows.
  - get_tree_head auto-records: calling it produces a sth_log row.
  - list() returns ascending by tree_size; since= is exclusive lower
    bound; limit is honored.
  - count(), latest(), earliest() return what they say.
  - verify_against_pinned():
      • match → verified=True
      • same size, different root → verified=False, reason=equivocation
      • size below earliest → not_in_log + helpful note
      • size above latest → not_in_log + helpful note
  - Endpoints: /v1/audit/sth-log + /v1/audit/sth-log/verify.
  - Tenant isolation: tenant A's log never leaks into tenant B's view.

Run: python -m pytest tests/test_sth_log.py -v
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_sth_log  # noqa: E402


def _isolated_db(tmp_path) -> str:
    import haldir_migrate
    db = str(tmp_path / "sth_log.db")
    haldir_migrate.apply_pending(db)
    return db


def _fake_sth(tree_size: int, root_hex: str = "ab" * 32, *,
              algorithm: str = "Ed25519-over-canonical-sth",
              signature: str = "00" * 64,
              signed_at: int = 1_700_000_000,
              key_id: str = "deadbeefcafebabe",
              public_key: str = "cd" * 32) -> dict:
    return {
        "tree_size":  tree_size,
        "root_hash":  root_hex,
        "algorithm":  algorithm,
        "signature":  signature,
        "signed_at":  signed_at,
        "key_id":     key_id,
        "public_key": public_key,
    }


# ── record() ────────────────────────────────────────────────────────

def test_record_writes_a_new_row(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    inserted = haldir_sth_log.record(db, "tnt-A", _fake_sth(1))
    assert inserted is True
    assert haldir_sth_log.count(db, "tnt-A") == 1


def test_record_is_idempotent_on_tenant_and_size(tmp_path) -> None:
    """Repeated record() for the same (tenant, tree_size) MUST NOT
    create duplicates — the DB-level PK enforces this and our wrapper
    surfaces the no-op as `False`."""
    db = _isolated_db(tmp_path)
    sth = _fake_sth(7)
    assert haldir_sth_log.record(db, "tnt-B", sth) is True
    # Repeat exactly.
    assert haldir_sth_log.record(db, "tnt-B", sth) is False
    # Repeat with DIFFERENT root — still no-op (first observation
    # is canonical; the second is provable equivocation but recorded
    # as such by the verifier, not by overwriting).
    sth_alt = _fake_sth(7, root_hex="cd" * 32)
    assert haldir_sth_log.record(db, "tnt-B", sth_alt) is False
    assert haldir_sth_log.count(db, "tnt-B") == 1


def test_record_is_tenant_scoped(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    haldir_sth_log.record(db, "tnt-X", _fake_sth(1))
    haldir_sth_log.record(db, "tnt-Y", _fake_sth(1))
    assert haldir_sth_log.count(db, "tnt-X") == 1
    assert haldir_sth_log.count(db, "tnt-Y") == 1


# ── list() / earliest() / latest() ─────────────────────────────────

def test_list_returns_ascending_by_tree_size(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    for size in (5, 1, 3, 2, 4):
        haldir_sth_log.record(db, "tnt-L", _fake_sth(size))
    rows = haldir_sth_log.list(db, "tnt-L")
    assert [r["tree_size"] for r in rows] == [1, 2, 3, 4, 5]


def test_list_since_is_exclusive_lower_bound(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    for size in range(1, 6):
        haldir_sth_log.record(db, "tnt-S", _fake_sth(size))
    rows = haldir_sth_log.list(db, "tnt-S", since_tree_size=2)
    assert [r["tree_size"] for r in rows] == [3, 4, 5]


def test_list_limit_caps_results(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    for size in range(1, 11):
        haldir_sth_log.record(db, "tnt-Lim", _fake_sth(size))
    rows = haldir_sth_log.list(db, "tnt-Lim", limit=3)
    assert len(rows) == 3


def test_earliest_and_latest_match_extremes(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    for size in (10, 1, 5):
        haldir_sth_log.record(db, "tnt-E", _fake_sth(size))
    assert haldir_sth_log.earliest(db, "tnt-E")["tree_size"] == 1
    assert haldir_sth_log.latest(db, "tnt-E")["tree_size"] == 10


def test_empty_log_returns_none_extremes(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    assert haldir_sth_log.earliest(db, "no-such-tenant") is None
    assert haldir_sth_log.latest(db, "no-such-tenant") is None
    assert haldir_sth_log.count(db, "no-such-tenant") == 0


# ── verify_against_pinned() ────────────────────────────────────────

def test_verify_match_returns_verified_true(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    sth = _fake_sth(3, root_hex="ab" * 32)
    haldir_sth_log.record(db, "tnt-V", sth)
    out = haldir_sth_log.verify_against_pinned(db, "tnt-V", 3, "ab" * 32)
    assert out["verified"] is True
    assert out["reason"] == "match"


def test_verify_equivocation_returns_both_roots(tmp_path) -> None:
    """The killer property: if an auditor's pinned root differs from
    what we recorded, the response gives them BOTH roots so they can
    publish proof of misbehaviour."""
    db = _isolated_db(tmp_path)
    haldir_sth_log.record(db, "tnt-Eq", _fake_sth(7, root_hex="aa" * 32))
    out = haldir_sth_log.verify_against_pinned(
        db, "tnt-Eq", 7, "ff" * 32,
    )
    assert out["verified"] is False
    assert out["reason"] == "equivocation"
    assert out["pinned_root_hash"]   == "ff" * 32
    assert out["recorded_root_hash"] == "aa" * 32


def test_verify_size_below_earliest_returns_not_in_log(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    haldir_sth_log.record(db, "tnt-Below", _fake_sth(10))
    haldir_sth_log.record(db, "tnt-Below", _fake_sth(20))
    out = haldir_sth_log.verify_against_pinned(
        db, "tnt-Below", 1, "00" * 32,
    )
    assert out["verified"] is False
    assert out["reason"] == "not_in_log"
    assert "predates" in out["note"]


def test_verify_size_above_latest_returns_not_in_log(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    haldir_sth_log.record(db, "tnt-Above", _fake_sth(5))
    out = haldir_sth_log.verify_against_pinned(
        db, "tnt-Above", 99, "ab" * 32,
    )
    assert out["verified"] is False
    assert out["reason"] == "not_in_log"
    assert "ahead" in out["note"] or "forgery" in out["note"]


def test_verify_empty_log_returns_helpful_message(tmp_path) -> None:
    db = _isolated_db(tmp_path)
    out = haldir_sth_log.verify_against_pinned(
        db, "no-tenant", 1, "ab" * 32,
    )
    assert out["verified"] is False
    assert "empty" in out["note"]


# ── get_tree_head auto-records ─────────────────────────────────────

def test_get_tree_head_auto_records_to_log(tmp_path) -> None:
    """Side-effect test: every successful get_tree_head call must
    produce a corresponding sth_log row with the same tree_size +
    root_hash. This is the integration that makes the whole anti-
    equivocation story actually load-bearing in production."""
    db = _isolated_db(tmp_path)
    # Insert one audit row so the tree has a leaf.
    from haldir_db import get_db
    conn = get_db(db)
    conn.execute(
        "INSERT INTO audit_log (entry_id, tenant_id, session_id, agent_id, "
        "action, tool, details, cost_usd, timestamp, flagged, prev_hash, "
        "entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?)",
        ("e-1", "tnt-Auto", "s", "a", "act", "tool", "{}", 0.0, 100.0, "h"),
    )
    conn.commit()
    conn.close()

    import haldir_audit_tree
    sth = haldir_audit_tree.get_tree_head(db, "tnt-Auto")

    rows = haldir_sth_log.list(db, "tnt-Auto")
    assert len(rows) == 1
    assert rows[0]["tree_size"] == sth["tree_size"]
    assert rows[0]["root_hash"] == sth["root_hash"]


def test_get_tree_head_dedupes_repeated_calls(tmp_path) -> None:
    """Repeated get_tree_head calls at the same tree size must not
    bloat the log — idempotency is what makes this storage-cheap."""
    db = _isolated_db(tmp_path)
    from haldir_db import get_db
    conn = get_db(db)
    conn.execute(
        "INSERT INTO audit_log (entry_id, tenant_id, session_id, agent_id, "
        "action, tool, details, cost_usd, timestamp, flagged, prev_hash, "
        "entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?)",
        ("e-1", "tnt-Dup", "s", "a", "act", "tool", "{}", 0.0, 100.0, "h"),
    )
    conn.commit()
    conn.close()

    import haldir_audit_tree
    for _ in range(5):
        haldir_audit_tree.get_tree_head(db, "tnt-Dup")
    assert haldir_sth_log.count(db, "tnt-Dup") == 1


# ── Endpoints ─────────────────────────────────────────────────────

def test_endpoint_sth_log_returns_log_for_tenant(haldir_client, bootstrap_key) -> None:
    """Smoke the HTTP route. Uses the shared bootstrap key — the
    bootstrap tenant has accumulated some tree-head calls during the
    test session, so the log is non-empty by the time we check."""
    # Force at least one tree-head call on the bootstrap tenant.
    import haldir_audit_tree, api
    tenant = _tenant_of(bootstrap_key)
    haldir_audit_tree.get_tree_head(api.DB_PATH, tenant)

    r = haldir_client.get(
        "/v1/audit/sth-log",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert "sths" in body
    assert "count" in body
    assert "earliest" in body
    assert "latest" in body
    assert body["count"] >= 1


def test_endpoint_verify_match(haldir_client, bootstrap_key) -> None:
    import haldir_audit_tree, api
    tenant = _tenant_of(bootstrap_key)
    sth = haldir_audit_tree.get_tree_head(api.DB_PATH, tenant)
    r = haldir_client.get(
        "/v1/audit/sth-log/verify",
        query_string={"pinned_size": sth["tree_size"],
                      "pinned_root": sth["root_hash"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["verified"] is True
    assert body["reason"] == "match"


def test_endpoint_verify_equivocation_path(haldir_client, bootstrap_key) -> None:
    import haldir_audit_tree, api
    tenant = _tenant_of(bootstrap_key)
    sth = haldir_audit_tree.get_tree_head(api.DB_PATH, tenant)
    r = haldir_client.get(
        "/v1/audit/sth-log/verify",
        query_string={"pinned_size": sth["tree_size"],
                      "pinned_root": "ff" * 32},  # tampered
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    body = r.get_json()
    assert body["verified"] is False
    assert body["reason"] == "equivocation"
    assert body["recorded_root_hash"] == sth["root_hash"]


def test_endpoint_verify_missing_args_returns_400(haldir_client, bootstrap_key) -> None:
    r = haldir_client.get(
        "/v1/audit/sth-log/verify",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 400


def test_endpoints_require_audit_read_scope(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "no-audit-sthlog", "scopes": ["sessions:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    narrow = r.get_json()["key"]
    r2 = haldir_client.get(
        "/v1/audit/sth-log",
        headers={"Authorization": f"Bearer {narrow}"},
    )
    assert r2.status_code == 403


# ── Helpers ────────────────────────────────────────────────────────

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
