"""
Tests for haldir_compliance_scheduler — recurring evidence-pack delivery.

Scope:
  - Cadence + delivery validation (rejects unknown values)
  - Create / list / delete schedule lifecycle
  - find_due() returns rows whose now - last_run_at >= cadence
  - fire_one() generates a pack, dispatches via webhook_mgr, records
    last_run_at + run_count
  - scan_and_fire() returns one result per due schedule
  - HTTP routes: POST + GET + DELETE under admin:write / admin:read
  - Admin-write scope gates POST/DELETE; reading requires admin:read

Run: python -m pytest tests/test_compliance_scheduler.py -v
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_compliance_scheduler as sched  # noqa: E402


# ── Validation ───────────────────────────────────────────────────────

def test_validate_cadence_known_values() -> None:
    for c in ("daily", "weekly", "monthly", "quarterly"):
        assert sched.validate_cadence(c) == c


def test_validate_cadence_normalizes_case() -> None:
    assert sched.validate_cadence("MONTHLY") == "monthly"


def test_validate_cadence_rejects_unknown() -> None:
    with pytest.raises(sched.ScheduleValidationError, match="cadence"):
        sched.validate_cadence("hourly")


def test_validate_delivery_accepts_webhook() -> None:
    assert sched.validate_delivery("webhook:abc") == "webhook:abc"


def test_validate_delivery_rejects_unknown_scheme() -> None:
    """webhook + email are supported; s3 / gcs / postman / etc. are
    not (yet). Reject at create time so the holder doesn't sit on a
    silently-broken schedule."""
    with pytest.raises(sched.ScheduleValidationError, match="scheme"):
        sched.validate_delivery("s3://my-bucket/evidence")
    with pytest.raises(sched.ScheduleValidationError, match="scheme"):
        sched.validate_delivery("postman:abc")


def test_validate_delivery_rejects_empty_target() -> None:
    with pytest.raises(sched.ScheduleValidationError, match="target"):
        sched.validate_delivery("webhook:")


# ── CRUD round-trip ──────────────────────────────────────────────────

def test_create_then_list(tmp_path) -> None:
    """Need an isolated DB with the compliance_schedules table. Apply
    migrations so the table is present (mirrors the production boot)."""
    import haldir_migrate
    db = str(tmp_path / "sched.db")
    haldir_migrate.apply_pending(db)

    out = sched.create_schedule(db, "tnt-A", name="monthly-board",
                                  cadence="monthly", delivery="webhook:wh1")
    assert out["schedule_id"].startswith("sched_")
    assert out["cadence"] == "monthly"
    assert out["active"] is True

    rows = sched.list_schedules(db, "tnt-A")
    assert len(rows) == 1
    assert rows[0]["name"] == "monthly-board"


def test_list_is_tenant_scoped(tmp_path) -> None:
    import haldir_migrate
    db = str(tmp_path / "sched.db")
    haldir_migrate.apply_pending(db)

    sched.create_schedule(db, "tnt-A", "a-sched", "daily", "webhook:wh1")
    sched.create_schedule(db, "tnt-B", "b-sched", "weekly", "webhook:wh2")
    a = sched.list_schedules(db, "tnt-A")
    b = sched.list_schedules(db, "tnt-B")
    assert len(a) == 1 and a[0]["name"] == "a-sched"
    assert len(b) == 1 and b[0]["name"] == "b-sched"


def test_delete_only_removes_own_tenant(tmp_path) -> None:
    import haldir_migrate
    db = str(tmp_path / "sched.db")
    haldir_migrate.apply_pending(db)
    s = sched.create_schedule(db, "tnt-A", "x", "daily", "webhook:w")
    # Wrong tenant: no-op.
    assert sched.delete_schedule(db, "tnt-B", s["schedule_id"]) is False
    # Right tenant: removed.
    assert sched.delete_schedule(db, "tnt-A", s["schedule_id"]) is True
    assert sched.list_schedules(db, "tnt-A") == []


# ── find_due() ───────────────────────────────────────────────────────

def test_find_due_includes_freshly_created(tmp_path) -> None:
    """A new schedule has last_run_at=0, so it's due immediately."""
    import haldir_migrate
    db = str(tmp_path / "sched.db")
    haldir_migrate.apply_pending(db)
    s = sched.create_schedule(db, "tnt", "x", "daily", "webhook:w")
    due = sched.find_due(db)
    assert any(d["schedule_id"] == s["schedule_id"] for d in due)


def test_find_due_excludes_recently_run(tmp_path) -> None:
    import haldir_migrate
    db = str(tmp_path / "sched.db")
    haldir_migrate.apply_pending(db)
    s = sched.create_schedule(db, "tnt", "x", "monthly", "webhook:w")
    sched._record_run(db, s["schedule_id"],
                       success=True, status="fired",
                       when=time.time())
    due = sched.find_due(db)
    assert not any(d["schedule_id"] == s["schedule_id"] for d in due)


def test_find_due_excludes_inactive(tmp_path) -> None:
    """Manually flip active=0 + assert the row is filtered out."""
    import haldir_migrate
    import sqlite3
    db = str(tmp_path / "sched.db")
    haldir_migrate.apply_pending(db)
    s = sched.create_schedule(db, "tnt", "x", "daily", "webhook:w")
    conn = sqlite3.connect(db)
    conn.execute("UPDATE compliance_schedules SET active = 0 WHERE schedule_id = ?",
                 (s["schedule_id"],))
    conn.commit()
    conn.close()
    assert not any(
        d["schedule_id"] == s["schedule_id"] for d in sched.find_due(db)
    )


# ── fire_one() ───────────────────────────────────────────────────────

class _FakeWebhookMgr:
    """Stand-in for WebhookManager — captures every fire() call so
    tests can assert on the dispatched event without I/O."""
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def fire(self, event_type: str, payload: dict[str, Any],
             tenant_id: str = "") -> str:
        self.calls.append({"event_type": event_type,
                           "payload": payload, "tenant_id": tenant_id})
        return "evt_fake_" + str(len(self.calls))


def test_fire_one_dispatches_via_webhook_mgr(tmp_path) -> None:
    import haldir_migrate
    db = str(tmp_path / "sched.db")
    haldir_migrate.apply_pending(db)
    s = sched.create_schedule(db, "tnt-fire", "x", "daily", "webhook:any")
    mgr = _FakeWebhookMgr()
    result = sched.fire_one(db, s, webhook_mgr=mgr)
    assert result["success"] is True
    assert result["status"] == "fired"
    assert len(mgr.calls) == 1
    assert mgr.calls[0]["event_type"] == "compliance.evidence_pack"
    assert mgr.calls[0]["tenant_id"] == "tnt-fire"
    assert "digest" in result
    # Payload contains the expected metadata.
    p = mgr.calls[0]["payload"]
    for k in ("schedule_id", "schedule_name", "cadence",
              "period_start", "period_end", "digest", "pack"):
        assert k in p


def test_fire_one_records_run_state(tmp_path) -> None:
    import haldir_migrate
    db = str(tmp_path / "sched.db")
    haldir_migrate.apply_pending(db)
    s = sched.create_schedule(db, "tnt-state", "x", "daily", "webhook:w")
    sched.fire_one(db, s, webhook_mgr=_FakeWebhookMgr())
    rows = sched.list_schedules(db, "tnt-state")
    assert rows[0]["run_count"] == 1
    assert rows[0]["last_run_at"] > 0
    assert rows[0]["last_status"] == "fired"


def test_fire_one_without_dispatcher_records_failure(tmp_path) -> None:
    import haldir_migrate
    db = str(tmp_path / "sched.db")
    haldir_migrate.apply_pending(db)
    s = sched.create_schedule(db, "tnt-nofire", "x", "daily", "webhook:w")
    out = sched.fire_one(db, s, webhook_mgr=None)
    assert out["success"] is False
    assert out["status"] == "no_dispatcher"
    rows = sched.list_schedules(db, "tnt-nofire")
    assert rows[0]["fail_count"] == 1
    # last_run_at remains 0 — the run didn't happen.
    assert rows[0]["last_run_at"] == 0


# ── scan_and_fire() ─────────────────────────────────────────────────

def test_scan_and_fire_returns_result_per_due(tmp_path) -> None:
    import haldir_migrate
    db = str(tmp_path / "sched.db")
    haldir_migrate.apply_pending(db)
    sched.create_schedule(db, "tnt", "a", "daily", "webhook:w")
    sched.create_schedule(db, "tnt", "b", "daily", "webhook:w")
    mgr = _FakeWebhookMgr()
    results = sched.scan_and_fire(db, webhook_mgr=mgr)
    assert len(results) == 2
    assert all(r["success"] for r in results)
    assert len(mgr.calls) == 2


# ── HTTP endpoints ──────────────────────────────────────────────────

def test_create_schedule_endpoint(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/compliance/schedules",
        json={"name": "monthly-soc2", "cadence": "monthly",
              "delivery": "webhook:demo"},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 201, r.data
    body = r.get_json()
    assert body["cadence"] == "monthly"
    assert body["delivery"] == "webhook:demo"
    assert body["schedule_id"].startswith("sched_")


def test_create_schedule_rejects_bad_cadence(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/compliance/schedules",
        json={"name": "x", "cadence": "hourly", "delivery": "webhook:w"},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    # @validate_body returns 400 with code "invalid_request" because
    # "hourly" isn't in the choices list.
    assert r.status_code == 400


def test_list_schedules_endpoint(haldir_client, bootstrap_key) -> None:
    haldir_client.post(
        "/v1/compliance/schedules",
        json={"name": "list-me", "cadence": "daily",
              "delivery": "webhook:foo"},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    r = haldir_client.get(
        "/v1/compliance/schedules",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 200
    items = r.get_json()["schedules"]
    assert any(s["name"] == "list-me" for s in items)


def test_delete_schedule_endpoint(haldir_client, bootstrap_key) -> None:
    sched_obj = haldir_client.post(
        "/v1/compliance/schedules",
        json={"name": "del-me", "cadence": "daily",
              "delivery": "webhook:foo"},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    ).get_json()
    r = haldir_client.delete(
        f"/v1/compliance/schedules/{sched_obj['schedule_id']}",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 204


def test_delete_404_for_unknown_schedule(haldir_client, bootstrap_key) -> None:
    r = haldir_client.delete(
        "/v1/compliance/schedules/sched_nonexistent",
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    assert r.status_code == 404


# ── Scope enforcement ──────────────────────────────────────────────

def test_create_requires_admin_write_scope(haldir_client, bootstrap_key) -> None:
    # Mint a key with admin:read only — must NOT be able to create.
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "ro", "scopes": ["admin:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    ro_key = r.get_json()["key"]
    r2 = haldir_client.post(
        "/v1/compliance/schedules",
        json={"name": "should-fail", "cadence": "daily",
              "delivery": "webhook:x"},
        headers={"Authorization": f"Bearer {ro_key}"},
    )
    assert r2.status_code == 403
    assert r2.get_json()["required"] == "admin:write"


def test_list_works_with_admin_read(haldir_client, bootstrap_key) -> None:
    r = haldir_client.post(
        "/v1/keys",
        json={"name": "ro2", "scopes": ["admin:read"]},
        headers={"Authorization": f"Bearer {bootstrap_key}"},
    )
    ro_key = r.get_json()["key"]
    r2 = haldir_client.get(
        "/v1/compliance/schedules",
        headers={"Authorization": f"Bearer {ro_key}"},
    )
    assert r2.status_code == 200
