"""
Tests for audit retention and prune checkpoints.

Two things have to be true at once, and they pull against each other:

  1. A prune must actually delete. Otherwise retention is theatre and a
     tenant with a data-deletion obligation still cannot meet it.

  2. A pruned log must still verify, and must still detect tampering in
     whatever is left. Otherwise pruning converts a working audit trail into
     a broken one — strictly worse than never pruning at all.

These pin both, plus the refusals: a prune that cannot produce a signed
commitment to what it removes must not run.

Run: python -m pytest tests/test_retention.py -v
"""

from __future__ import annotations

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import haldir_retention  # noqa: E402
from haldir_watch import AuditEntry, Watch  # noqa: E402


@pytest.fixture
def db(tmp_path):
    # Migrations as well as init_db: the tree head path touches tables that
    # only a migration creates (sth_log, sth_mirror_receipts), and without
    # them the prune still works but logs a mirror failure on every call.
    import haldir_migrate
    from haldir_db import init_db
    path = str(tmp_path / "retention.db")
    init_db(path)
    haldir_migrate.apply_pending(path)

    # Clear this tenant's rows.
    #
    # On SQLite the path above is a fresh temp file, so every test starts from
    # nothing. On Postgres DATABASE_URL wins and the path is ignored, so every
    # test in the run shares one database — and the tests below all use the
    # tenant "t1", which then accumulates rows from everything that ran
    # before them. A prune that should delete 3 entries deleted 5, because two
    # of them belonged to the previous test.
    #
    # Deleting the tenant's rows here restores the isolation the assertions
    # assume, without changing what any of them assert.
    _clear_tenant(path, "t1")
    return path


def _clear_tenant(db_path: str, tenant: str) -> None:
    """Remove a tenant's audit rows, checkpoints and tree heads."""
    from haldir_db import get_db

    conn = get_db(db_path)
    try:
        for table, column in (
            ("audit_log", "tenant_id"),
            ("audit_checkpoints", "tenant_id"),
            ("audit_retention", "tenant_id"),
            ("sth_log", "tenant_id"),
        ):
            try:
                conn.execute(f"DELETE FROM {table} WHERE {column} = ?", (tenant,))  # noqa: S608 — table names are literals above
            except Exception:
                conn.rollback()  # table absent on a build without that migration
        conn.commit()
    finally:
        conn.close()


def append(db: str, tenant: str, ts: float, action: str = "act") -> AuditEntry:
    """Append an audit entry at a chosen timestamp, chained correctly.

    log_action stamps time.time(), so backdating after the fact would break
    the hash (timestamp is part of it). Building the entry here is what lets
    a test have genuinely old rows with an intact chain.
    """
    from haldir_db import get_db
    conn = get_db(db)
    last = conn.execute(
        "SELECT entry_hash FROM audit_log WHERE tenant_id = ? "
        "ORDER BY timestamp DESC LIMIT 1", (tenant,)
    ).fetchone()
    prev = last["entry_hash"] if last else ""

    entry = AuditEntry(entry_id=f"e_{tenant}_{ts}", session_id="s",
                       agent_id="a", action=action, timestamp=ts, prev_hash=prev)
    entry.entry_hash = entry.compute_hash()
    conn.execute(
        "INSERT INTO audit_log (entry_id, tenant_id, session_id, agent_id, action, "
        "tool, details, cost_usd, timestamp, flagged, flag_reason, prev_hash, "
        "entry_hash, hash_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (entry.entry_id, tenant, entry.session_id, entry.agent_id, entry.action,
         entry.tool, "{}", 0.0, entry.timestamp, 0, "", entry.prev_hash,
         entry.entry_hash, entry.hash_version),
    )
    conn.commit()
    conn.close()
    return entry


DAY = 86400


# ── Policy ───────────────────────────────────────────────────────────

def test_default_policy_keeps_forever(db) -> None:
    p = haldir_retention.get_policy(db, "t1")
    assert p["retain_days"] == 0
    assert p["configured"] is False


def test_policy_round_trips(db) -> None:
    haldir_retention.set_policy(db, "t1", 90, updated_by="hld_abc")
    p = haldir_retention.get_policy(db, "t1")
    assert p["retain_days"] == 90
    assert p["updated_by"] == "hld_abc"
    assert p["configured"] is True


def test_setting_zero_turns_pruning_off(db) -> None:
    haldir_retention.set_policy(db, "t1", 90)
    haldir_retention.set_policy(db, "t1", 0)
    assert haldir_retention.get_policy(db, "t1")["retain_days"] == 0
    assert haldir_retention.prune(db, "t1")["pruned"] is False


def test_negative_window_is_rejected(db) -> None:
    with pytest.raises(ValueError):
        haldir_retention.set_policy(db, "t1", -1)


# ── Preview ──────────────────────────────────────────────────────────

def test_preview_counts_without_deleting(db) -> None:
    now = time.time()
    append(db, "t1", now - 200 * DAY)
    append(db, "t1", now - 100 * DAY)
    append(db, "t1", now - 1 * DAY)

    out = haldir_retention.preview(db, "t1", retain_days=90)
    assert out["would_delete"] == 2
    assert haldir_retention.latest_checkpoint(db, "t1") is None

    from haldir_db import get_db
    conn = get_db(db)
    n = conn.execute("SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?", ("t1",)).fetchone()[0]
    conn.close()
    assert n == 3, "preview must not delete anything"


# ── The prune ────────────────────────────────────────────────────────

def test_prune_deletes_and_records_a_checkpoint(db) -> None:
    now = time.time()
    for age in (200, 150, 100, 10, 1):
        append(db, "t1", now - age * DAY)

    out = haldir_retention.prune(db, "t1", retain_days=90, actor="hld_ops")
    assert out["pruned"] is True
    assert out["entries_deleted"] == 3
    assert out["root_hash"], "the prune must carry a commitment"
    assert out["tree_size"] == 5, "the tree head covers the log BEFORE the delete"

    ck = haldir_retention.latest_checkpoint(db, "t1")
    assert ck["entries_deleted"] == 3
    assert ck["last_pruned_entry_hash"], "the boundary link must be recorded"
    assert ck["created_by"] == "hld_ops"


def test_prune_is_a_noop_when_nothing_is_old_enough(db) -> None:
    append(db, "t1", time.time() - 1 * DAY)
    out = haldir_retention.prune(db, "t1", retain_days=90)
    assert out["pruned"] is False
    assert out["entries_deleted"] == 0
    assert haldir_retention.latest_checkpoint(db, "t1") is None


def test_prune_uses_the_stored_policy_when_not_given_one(db) -> None:
    append(db, "t1", time.time() - 200 * DAY)
    append(db, "t1", time.time() - 1 * DAY)
    haldir_retention.set_policy(db, "t1", 90)
    assert haldir_retention.prune(db, "t1")["entries_deleted"] == 1


def test_prune_refuses_without_a_tree_head(db, monkeypatch) -> None:
    """No commitment, no deletion.

    Deleting audit data with nothing to say what was there is precisely the
    silent removal this feature exists to make impossible.
    """
    append(db, "t1", time.time() - 200 * DAY)
    append(db, "t1", time.time() - 1 * DAY)

    import haldir_audit_tree
    def boom(*a, **k):
        raise RuntimeError("signing key unavailable")
    monkeypatch.setattr(haldir_audit_tree, "get_tree_head", boom)

    out = haldir_retention.prune(db, "t1", retain_days=90)
    assert out["pruned"] is False
    assert "tree head" in out["reason"]

    from haldir_db import get_db
    conn = get_db(db)
    n = conn.execute("SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?", ("t1",)).fetchone()[0]
    conn.close()
    assert n == 2, "nothing may be deleted when the commitment cannot be made"


# ── The property that makes this safe ────────────────────────────────

def test_chain_still_verifies_after_a_prune(db) -> None:
    """The whole point. Without the checkpoint, this fails."""
    now = time.time()
    for age in (300, 250, 200, 100, 50, 1):
        append(db, "t1", now - age * DAY)

    w = Watch(db_path=db)
    assert w.verify_chain(tenant_id="t1")["verified"] is True

    haldir_retention.prune(db, "t1", retain_days=90)

    result = Watch(db_path=db).verify_chain(tenant_id="t1")
    assert result["verified"] is True, result
    # Ages 300/250/200/100 are all older than the 90-day window; 50 and 1 survive.
    assert result["entries_checked"] == 2
    # And it says so, rather than leaving the auditor to notice a shorter log.
    assert result["pruned"]["entries_deleted"] == 4
    assert result["pruned"]["root_hash"]


def test_a_pruned_log_still_detects_tampering(db) -> None:
    """The checkpoint must not become a blind spot.

    Starting verification from the checkpoint hash is only safe if the
    surviving entries are still fully checked. If it let anything through,
    pruning would be a way to launder a modified log.
    """
    now = time.time()
    for age in (300, 200, 100, 50, 1):
        append(db, "t1", now - age * DAY)

    haldir_retention.prune(db, "t1", retain_days=90)
    assert Watch(db_path=db).verify_chain(tenant_id="t1")["verified"] is True

    # Rewrite a surviving entry's action without recomputing its hash.
    from haldir_db import get_db
    conn = get_db(db)
    conn.execute("UPDATE audit_log SET action = 'exfiltrate' WHERE tenant_id = ? "
                 "ORDER BY timestamp ASC LIMIT 1", ("t1",))
    conn.commit()
    conn.close()

    result = Watch(db_path=db).verify_chain(tenant_id="t1")
    assert result["verified"] is False
    assert "modified" in result["error"].lower()


def test_checkpoints_are_listed_newest_first(db) -> None:
    now = time.time()
    for age in (400, 300, 200, 100, 1):
        append(db, "t1", now - age * DAY)

    haldir_retention.prune(db, "t1", retain_days=350)
    haldir_retention.prune(db, "t1", retain_days=250)
    history = haldir_retention.list_checkpoints(db, "t1")
    assert len(history) == 2
    assert history[0]["created_at"] >= history[1]["created_at"]
    assert [h["entries_deleted"] for h in history] == [1, 1]


# ── HTTP surface ─────────────────────────────────────────────────────

def test_retention_endpoints(haldir_client, bootstrap_key, fresh_counter) -> None:
    h = {"Authorization": f"Bearer {bootstrap_key}"}

    r = haldir_client.get("/v1/audit/retention", headers=h)
    assert r.status_code == 200, r.data
    assert "retain_days" in r.get_json()
    assert "preview" in r.get_json(), "the caller should not have to prune to find out"

    r = haldir_client.put("/v1/audit/retention", json={"retain_days": 365},
                          headers=h)
    assert r.status_code == 200, r.data
    assert r.get_json()["retain_days"] == 365

    # Negative windows are rejected by validation rather than accepted and
    # treated as "delete everything".
    r = haldir_client.put("/v1/audit/retention", json={"retain_days": -1},
                          headers=h)
    assert r.status_code == 400


def test_prune_requires_explicit_confirmation(haldir_client, bootstrap_key, fresh_counter) -> None:
    """Destructive and not reversible, so a bare POST must not do it."""
    h = {"Authorization": f"Bearer {bootstrap_key}"}
    haldir_client.put("/v1/audit/retention", json={"retain_days": 90}, headers=h)

    r = haldir_client.post("/v1/audit/retention/prune", json={"confirm": False},
                           headers=h)
    assert r.status_code == 400
    assert "confirm" in r.get_json()["error"].lower()

    # And a bare POST with no body at all takes the same path, rather than
    # failing schema validation with a message the caller can't act on.
    r = haldir_client.post("/v1/audit/retention/prune", json={}, headers=h)
    assert r.status_code == 400
    assert "confirm" in r.get_json()["error"].lower()


def test_prune_without_a_window_reports_rather_than_deletes(haldir_client, bootstrap_key, fresh_counter) -> None:
    """With no window there is nothing to prune, and that is a 409 rather
    than a 200 that looks like it did something."""
    h = {"Authorization": f"Bearer {bootstrap_key}"}
    haldir_client.put("/v1/audit/retention", json={"retain_days": 0}, headers=h)

    r = haldir_client.post("/v1/audit/retention/prune", json={"confirm": True},
                           headers=h)
    assert r.status_code == 409
    assert r.get_json()["pruned"] is False

    r = haldir_client.get("/v1/audit/retention/checkpoints", headers=h)
    assert r.status_code == 200
    assert r.get_json()["count"] == 0


def test_tenants_are_isolated(db) -> None:
    now = time.time()
    append(db, "t1", now - 200 * DAY)
    append(db, "t2", now - 200 * DAY)

    haldir_retention.prune(db, "t1", retain_days=90)

    assert haldir_retention.latest_checkpoint(db, "t2") is None
    # t2 was never pruned, so its chain must be untouched and still valid.
    assert Watch(db_path=db).verify_chain(tenant_id="t2")["verified"] is True
