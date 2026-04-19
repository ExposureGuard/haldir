"""
Haldir compliance scheduler — recurring evidence-pack delivery.

The first compliance evidence pack a CISO generates is the demo. The
fortieth is the recurring deliverable that keeps Haldir's SaaS revenue
sticky. This module is the engine that fires the fortieth.

A tenant registers N schedules:

    POST /v1/compliance/schedules
    { "name": "monthly-board-prep",
      "cadence": "monthly",
      "delivery": "webhook:<webhook_id>" }

Once an hour, the scheduler thread wakes, scans the
`compliance_schedules` table for any row where
`now - last_run_at >= cadence_seconds`, generates the evidence pack
covering the prior period, and dispatches it via the registered
delivery target. Webhook delivery re-uses the production-grade
WebhookManager (retries, deliveries log, signed payloads) so we don't
re-implement reliability.

Why a thread, not a separate worker process: at our scale a single
gunicorn instance has plenty of capacity for one wakeup per hour.
When/if Haldir fans out across multiple processes, this becomes a
classic "elect a leader, only the leader fires" problem — solved with
a Postgres advisory lock or a Redis SETNX. Out of scope for v1.

The scheduler is idempotent on its `last_run_at` watermark: if the
process restarts, no schedule fires twice for the same period.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from haldir_logging import get_logger


log = get_logger("haldir.compliance.scheduler")

# Cadences expressed in seconds. Choose values that match the audit
# cycles humans actually plan on, not arbitrary intervals.
CADENCE_SECONDS: dict[str, int] = {
    "daily":     24 * 3600,
    "weekly":    7 * 24 * 3600,
    "monthly":   30 * 24 * 3600,
    "quarterly": 90 * 24 * 3600,
}

KNOWN_CADENCES = frozenset(CADENCE_SECONDS.keys())

# How often the worker thread wakes to scan for due schedules.
# At one-hour granularity, the worst-case lateness on a daily schedule
# is ~1 hour, which is irrelevant for compliance.
SCAN_INTERVAL_SECONDS: int = 3600


# ── Validation ────────────────────────────────────────────────────────

class ScheduleValidationError(ValueError):
    """Raised on bad cadence / delivery values at create time."""


def validate_cadence(c: str) -> str:
    c = (c or "").strip().lower()
    if c not in KNOWN_CADENCES:
        raise ScheduleValidationError(
            f"cadence must be one of {sorted(KNOWN_CADENCES)}, got {c!r}"
        )
    return c


def validate_delivery(d: str) -> str:
    """Today only `webhook:<id>` is supported. Future schemes
    (email:, s3://) get added here as we wire their dispatchers."""
    d = (d or "").strip()
    if not d.startswith("webhook:"):
        raise ScheduleValidationError(
            f"delivery must be 'webhook:<webhook_id>' (got {d!r}); "
            "email + s3 schemes ship in a follow-up tranche"
        )
    target = d.split(":", 1)[1].strip()
    if not target:
        raise ScheduleValidationError("delivery missing target id after ':'")
    return d


# ── CRUD ─────────────────────────────────────────────────────────────

def create_schedule(
    db_path: str,
    tenant_id: str,
    name: str,
    cadence: str,
    delivery: str,
) -> dict[str, Any]:
    """Persist a new schedule. Returns the row as a dict; raises
    ScheduleValidationError on bad input."""
    import secrets as _sec
    from haldir_db import get_db
    cadence = validate_cadence(cadence)
    delivery = validate_delivery(delivery)
    schedule_id = f"sched_{_sec.token_urlsafe(12)}"
    now = time.time()
    conn = get_db(db_path)
    try:
        conn.execute(
            "INSERT INTO compliance_schedules ("
            "schedule_id, tenant_id, name, cadence, delivery, "
            "active, created_at, last_run_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (schedule_id, tenant_id, name, cadence, delivery,
             1, now, 0.0),
        )
        conn.commit()
    finally:
        conn.close()
    return {
        "schedule_id": schedule_id,
        "tenant_id":   tenant_id,
        "name":        name,
        "cadence":     cadence,
        "delivery":    delivery,
        "active":      True,
        "created_at":  now,
        "last_run_at": 0.0,
        "next_due":    now,  # 0 last_run = due immediately
    }


def list_schedules(db_path: str, tenant_id: str) -> list[dict[str, Any]]:
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM compliance_schedules WHERE tenant_id = ? "
            "ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
    except Exception:
        rows = []
    finally:
        conn.close()
    return [_row_to_dict(r) for r in rows]


def delete_schedule(db_path: str, tenant_id: str, schedule_id: str) -> bool:
    """Returns True if a row was removed; False if not found / wrong
    tenant. Tenant-scoped delete prevents cross-tenant tampering."""
    from haldir_db import get_db
    conn = get_db(db_path)
    try:
        cur = conn.execute(
            "DELETE FROM compliance_schedules "
            "WHERE schedule_id = ? AND tenant_id = ?",
            (schedule_id, tenant_id),
        )
        conn.commit()
        return getattr(cur, "rowcount", 0) > 0 or conn.total_changes > 0
    finally:
        conn.close()


def _row_to_dict(r: Any) -> dict[str, Any]:
    last_run = float(r["last_run_at"])
    cadence_s = CADENCE_SECONDS.get(r["cadence"], 0)
    next_due = last_run + cadence_s if last_run > 0 else time.time()
    return {
        "schedule_id":  r["schedule_id"],
        "tenant_id":    r["tenant_id"],
        "name":         r["name"],
        "cadence":      r["cadence"],
        "delivery":     r["delivery"],
        "active":       bool(r["active"]),
        "created_at":   float(r["created_at"]),
        "last_run_at":  last_run,
        "last_status":  r["last_status"],
        "last_error":   r["last_error"],
        "run_count":    int(r["run_count"]),
        "fail_count":   int(r["fail_count"]),
        "next_due":     next_due,
    }


# ── Scanning + dispatching ──────────────────────────────────────────

def find_due(db_path: str, now: float | None = None) -> list[dict[str, Any]]:
    """Return every active schedule whose `now - last_run_at` exceeds
    its cadence. Sweeps across every tenant — the scheduler is
    process-global, not per-tenant."""
    from haldir_db import get_db
    now = now if now is not None else time.time()
    conn = get_db(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM compliance_schedules WHERE active = 1"
        ).fetchall()
    except Exception:
        rows = []
    finally:
        conn.close()
    due: list[dict[str, Any]] = []
    for r in rows:
        c = CADENCE_SECONDS.get(r["cadence"])
        if c is None:
            continue
        last = float(r["last_run_at"])
        if now - last >= c:
            due.append(_row_to_dict(r))
    return due


def _record_run(
    db_path: str,
    schedule_id: str,
    *,
    success: bool,
    status: str,
    error: str = "",
    when: float | None = None,
) -> None:
    """Update the schedule's run state. Always commits — the scheduler
    must record outcomes even when delivery fails."""
    from haldir_db import get_db
    when = when if when is not None else time.time()
    conn = get_db(db_path)
    try:
        if success:
            conn.execute(
                "UPDATE compliance_schedules SET "
                "last_run_at = ?, last_status = ?, last_error = '', "
                "run_count = run_count + 1 WHERE schedule_id = ?",
                (when, status, schedule_id),
            )
        else:
            conn.execute(
                "UPDATE compliance_schedules SET "
                "last_status = ?, last_error = ?, "
                "fail_count = fail_count + 1 WHERE schedule_id = ?",
                (status, error[:512], schedule_id),
            )
        conn.commit()
    finally:
        conn.close()


def fire_one(
    db_path: str,
    schedule: dict[str, Any],
    webhook_mgr: Any | None = None,
) -> dict[str, Any]:
    """Generate the evidence pack for this schedule's tenant + cadence
    period, then dispatch via the schedule's delivery target. Returns
    {success, status, error} so callers + the scheduler can log.

    Webhook fan-out is via the existing WebhookManager.fire(), which
    already handles retries, signing, deliveries log. Reuse over
    reimplementation."""
    import haldir_compliance
    cadence_s = CADENCE_SECONDS.get(schedule["cadence"], 0)
    until = time.time()
    since = until - cadence_s
    try:
        pack = haldir_compliance.build_evidence_pack(
            db_path, schedule["tenant_id"], since=since, until=until,
        )
    except Exception as e:
        _record_run(db_path, schedule["schedule_id"],
                    success=False, status="build_failed", error=str(e))
        return {"success": False, "status": "build_failed", "error": str(e)}

    delivery = schedule["delivery"]
    if delivery.startswith("webhook:"):
        # Fire as a regular webhook event so the existing delivery
        # machinery (retries, deliveries log, HMAC signing) applies.
        if webhook_mgr is None:
            err = "webhook delivery requested but no manager available"
            _record_run(db_path, schedule["schedule_id"],
                        success=False, status="no_dispatcher", error=err)
            return {"success": False, "status": "no_dispatcher", "error": err}
        event_id = webhook_mgr.fire(
            "compliance.evidence_pack",
            {
                "schedule_id": schedule["schedule_id"],
                "schedule_name": schedule["name"],
                "cadence": schedule["cadence"],
                "period_start": pack["period_start"],
                "period_end": pack["period_end"],
                "digest": pack["signatures"]["digest"],
                "pack": pack,
            },
            tenant_id=schedule["tenant_id"],
        )
        _record_run(db_path, schedule["schedule_id"],
                    success=True, status="fired",
                    error="")
        log.info("compliance schedule fired", extra={
            "schedule_id": schedule["schedule_id"],
            "tenant_id": schedule["tenant_id"],
            "event_id": event_id,
        })
        return {"success": True, "status": "fired",
                "event_id": event_id, "digest": pack["signatures"]["digest"]}

    err = f"unsupported delivery scheme: {delivery!r}"
    _record_run(db_path, schedule["schedule_id"],
                success=False, status="unsupported_delivery", error=err)
    return {"success": False, "status": "unsupported_delivery", "error": err}


def scan_and_fire(
    db_path: str,
    webhook_mgr: Any | None = None,
) -> list[dict[str, Any]]:
    """One pass: find every due schedule + fire it. Returns one result
    dict per schedule fired. Used by the scheduler thread + by tests
    that drive a single tick."""
    results: list[dict[str, Any]] = []
    for s in find_due(db_path):
        r = fire_one(db_path, s, webhook_mgr=webhook_mgr)
        r["schedule_id"] = s["schedule_id"]
        results.append(r)
    return results


# ── Background thread ───────────────────────────────────────────────

_thread: threading.Thread | None = None
_stop = threading.Event()


def start_background(db_path: str, webhook_mgr: Any | None = None,
                     interval_s: int = SCAN_INTERVAL_SECONDS) -> None:
    """Spin up the daemon thread that wakes every `interval_s` seconds
    to scan + fire. Idempotent — calling twice is a no-op."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return

    def _loop() -> None:
        while not _stop.is_set():
            try:
                scan_and_fire(db_path, webhook_mgr=webhook_mgr)
            except Exception:
                log.exception("compliance scheduler tick failed")
            # Sleep in small slices so stop() is responsive.
            for _ in range(interval_s):
                if _stop.is_set():
                    return
                time.sleep(1)

    _thread = threading.Thread(target=_loop, daemon=True,
                                name="haldir-compliance-scheduler")
    _thread.start()


def stop_background() -> None:
    """Signal the worker to exit + wait briefly. Used by tests +
    graceful shutdown."""
    _stop.set()
    if _thread is not None:
        _thread.join(timeout=5)
