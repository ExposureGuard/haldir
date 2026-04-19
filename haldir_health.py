"""
Haldir health probes — Kubernetes-grade liveness + readiness split.

Two endpoints, two distinct questions:

  GET /livez   "Is this process alive?"
               Answers 200 as long as the request loop is running.
               No I/O, no dependency checks. K8s liveness probes hit
               this — failure here means the container is wedged and
               the orchestrator should kill + restart it.

  GET /readyz  "Should this process receive traffic right now?"
               Checks the things that must be true before the load
               balancer sends users our way:
                 - Database is reachable on a 1 s timeout.
                 - Migration state is consistent (no drift, no
                   pending migrations under HALDIR_AUTO_MIGRATE).
                 - Encryption key is configured (warning level —
                   ephemeral keys are valid for dev but flagged).
               Failure here returns 503 so K8s readiness probes
               (and any L7 load balancer that respects status codes)
               pull this pod out of rotation without restarting it.

Why this matters: a pod can be alive (livez green) but not ready
(readyz red) — typical during boot when migrations are running, the
DB is warming up, or a transient downstream is recovering. Without
the split, K8s either restarts a perfectly healthy pod or routes
traffic to a wedged one. Every cloud-native deploy reviewer asks
about this on the first call.

Design:
  - Pure-function module — takes (db_path, migrations_dir) and
    returns {ready: bool, checks: [...]}. No Flask. Wrapped in api.py.
  - Each check is independent + bounded; one slow check doesn't
    block the others (sequential is fine at this small N).
  - Failure response is structured JSON so log aggregators + alerting
    rules can parse the failed check name without regex.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass, asdict
from typing import Any


# Probe budget — total wall-clock cap for readiness. K8s default
# probe timeout is 1 s; leave a margin so the response actually
# returns rather than getting cut off.
PROBE_TIMEOUT_S = 0.8


@dataclass
class CheckResult:
    name: str        # short id ("database", "migrations", "encryption_key")
    ok: bool
    message: str     # human-readable; logged when failed
    duration_ms: int # actual cost so operators can spot creeping checks


# ── Individual checks ────────────────────────────────────────────────

def check_database(db_path: str) -> CheckResult:
    """SELECT 1 against the configured DB. Treats anything slower than
    half the probe budget as 'ok but slow' — still ready, but the
    duration_ms field will surface in monitoring."""
    started = time.time()
    try:
        conn = sqlite3.connect(db_path, timeout=PROBE_TIMEOUT_S)
        try:
            conn.execute("SELECT 1").fetchone()
        finally:
            conn.close()
    except Exception as e:
        return CheckResult(
            name="database",
            ok=False,
            message=f"db unreachable: {type(e).__name__}",
            duration_ms=int((time.time() - started) * 1000),
        )
    return CheckResult(
        name="database",
        ok=True,
        message="ok",
        duration_ms=int((time.time() - started) * 1000),
    )


def check_migrations(db_path: str, migrations_dir: str | None = None) -> CheckResult:
    """No pending migrations + no checksum drift.

    Legacy-state tolerance: if schema_migrations doesn't exist yet but
    init_db has populated the core tables (api_keys etc.), we treat the
    state as ready. The migration runner's bootstrap path will adopt
    that schema as v1 on the next `up`, and meanwhile the running app
    is operating against a complete schema. Refusing traffic here would
    cause needless K8s churn during an upgrade window."""
    started = time.time()
    try:
        import haldir_migrate
        s = haldir_migrate.status(db_path, migrations_dir)
    except Exception as e:
        return CheckResult(
            name="migrations",
            ok=False,
            message=f"could not read migration state: {type(e).__name__}",
            duration_ms=int((time.time() - started) * 1000),
        )

    if s["drift"]:
        return CheckResult(
            name="migrations",
            ok=False,
            message=f"checksum drift on versions {s['drift']}",
            duration_ms=int((time.time() - started) * 1000),
        )
    if s["pending"]:
        # If schema_migrations is empty but core tables exist, this is
        # a legacy / pre-migrations DB — fine. Otherwise it's a real
        # mismatch and we refuse traffic so requests don't hit columns
        # that don't exist yet.
        if not s["applied"] and _legacy_schema_present(db_path):
            return CheckResult(
                name="migrations",
                ok=True,
                message=(
                    f"legacy schema in place; {len(s['pending'])} migrations "
                    "pending (will bootstrap on next runner pass)"
                ),
                duration_ms=int((time.time() - started) * 1000),
            )
        versions = [p["version"] for p in s["pending"]]
        return CheckResult(
            name="migrations",
            ok=False,
            message=f"pending migrations not yet applied: {versions}",
            duration_ms=int((time.time() - started) * 1000),
        )
    return CheckResult(
        name="migrations",
        ok=True,
        message=f"{len(s['applied'])} applied, none pending",
        duration_ms=int((time.time() - started) * 1000),
    )


def _legacy_schema_present(db_path: str) -> bool:
    """Detect the 'init_db created the tables already' state by probing
    for api_keys — the canonical core table that has existed since
    Haldir's first commit."""
    try:
        conn = sqlite3.connect(db_path, timeout=PROBE_TIMEOUT_S)
        try:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type='table' AND name='api_keys'"
            ).fetchone()
            return row is not None
        finally:
            conn.close()
    except Exception:
        return False


def check_encryption_key() -> CheckResult:
    """Is HALDIR_ENCRYPTION_KEY set? Without it, Vault generates an
    ephemeral key on each boot — secrets persist but become unreadable
    on restart. Acceptable for dev, never for prod. Returns ok=True
    with a 'warning' message rather than failing readiness, because
    self-hosted dev installs are a legitimate use case."""
    started = time.time()
    has_key = bool(os.environ.get("HALDIR_ENCRYPTION_KEY"))
    return CheckResult(
        name="encryption_key",
        ok=True,                         # don't 503 on this — warn instead
        message="configured" if has_key
                else "ephemeral (HALDIR_ENCRYPTION_KEY unset; secrets lost on restart)",
        duration_ms=int((time.time() - started) * 1000),
    )


# ── Top-level probes ─────────────────────────────────────────────────

def liveness() -> dict[str, Any]:
    """Trivial. As long as this function can be called, the process
    is responsive enough to live. No I/O — anything that hits the DB
    belongs in readyz."""
    return {
        "alive": True,
        "service": "haldir",
        "checked_at": int(time.time()),
    }


def readiness(db_path: str, migrations_dir: str | None = None) -> dict[str, Any]:
    """Compose every check and a top-level boolean. `ready=False`
    means the load balancer should pull this pod; `ready=True` means
    it's safe to send traffic."""
    checks = [
        check_database(db_path),
        check_migrations(db_path, migrations_dir),
        check_encryption_key(),
    ]
    return {
        "ready":      all(c.ok for c in checks),
        "service":    "haldir",
        "checked_at": int(time.time()),
        "checks":     [asdict(c) for c in checks],
    }
