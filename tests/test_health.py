"""
Tests for /livez and /readyz — the Kubernetes-grade health probes.

Scope:
  - /livez always 200 with {alive: true} regardless of DB state
  - /readyz returns 200 + ready=true on a healthy DB
  - /readyz returns 503 + ready=false when DB is unreachable
  - /readyz returns 503 when migrations have unapplied versions
  - /readyz returns 503 when migration files have drifted post-apply
  - encryption_key check is an informational warning, never blocks
  - /healthz remains 200 for back-compat consumers

Run: python -m pytest tests/test_health.py -v
"""

from __future__ import annotations

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_health  # noqa: E402


# ── Module-level pure-function checks ────────────────────────────────

def test_check_database_ok_on_reachable_path(tmp_path) -> None:
    db = tmp_path / "h.db"
    sqlite3.connect(str(db)).close()
    r = haldir_health.check_database(str(db))
    assert r.ok
    assert r.name == "database"
    assert r.duration_ms >= 0


def test_check_database_fails_on_unreachable_path(tmp_path) -> None:
    bogus = tmp_path / "no" / "such" / "path.db"
    r = haldir_health.check_database(str(bogus))
    assert not r.ok
    assert "db unreachable" in r.message


def test_check_migrations_passes_with_no_pending(tmp_path) -> None:
    """Apply every migration, then check should pass."""
    import haldir_migrate
    db = str(tmp_path / "m.db")
    haldir_migrate.apply_pending(db)
    r = haldir_health.check_migrations(db)
    assert r.ok
    assert "applied" in r.message


def test_check_migrations_fails_when_pending(tmp_path, monkeypatch) -> None:
    """Point at an empty DB + a migrations dir with one .sql file =
    schema_migrations table doesn't exist (treated as 'all pending')."""
    migs = tmp_path / "migs"
    migs.mkdir()
    (migs / "001_demo.sql").write_text("CREATE TABLE IF NOT EXISTS demo (x INT);")
    monkeypatch.setenv("HALDIR_MIGRATIONS_DIR", str(migs))
    db = str(tmp_path / "fresh.db")
    r = haldir_health.check_migrations(db, str(migs))
    assert not r.ok
    assert "pending" in r.message


def test_check_migrations_fails_on_drift(tmp_path, monkeypatch) -> None:
    """Apply a migration, then mutate the file on disk → drift."""
    import haldir_migrate
    migs = tmp_path / "migs"
    migs.mkdir()
    f = migs / "001_orig.sql"
    f.write_text("CREATE TABLE IF NOT EXISTS orig (x INT);")
    monkeypatch.setenv("HALDIR_MIGRATIONS_DIR", str(migs))
    db = str(tmp_path / "drift.db")
    haldir_migrate.apply_pending(db, str(migs))
    f.write_text("CREATE TABLE IF NOT EXISTS orig (x INT, y INT);")
    r = haldir_health.check_migrations(db, str(migs))
    assert not r.ok
    assert "drift" in r.message


def test_check_encryption_key_warns_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("HALDIR_ENCRYPTION_KEY", raising=False)
    r = haldir_health.check_encryption_key()
    # Warning, not failure — readyz should not 503 on this.
    assert r.ok
    assert "ephemeral" in r.message


def test_check_encryption_key_ok_when_set(monkeypatch) -> None:
    monkeypatch.setenv("HALDIR_ENCRYPTION_KEY", "a" * 44)
    r = haldir_health.check_encryption_key()
    assert r.ok
    assert "configured" in r.message


# ── Top-level probe shape ────────────────────────────────────────────

def test_liveness_payload_minimal() -> None:
    out = haldir_health.liveness()
    assert out["alive"] is True
    assert out["service"] == "haldir"
    assert isinstance(out["checked_at"], int)


def test_readiness_payload_includes_every_check(tmp_path) -> None:
    db = tmp_path / "r.db"
    sqlite3.connect(str(db)).close()
    out = haldir_health.readiness(str(db))
    names = {c["name"] for c in out["checks"]}
    assert names == {"database", "migrations", "encryption_key"}
    assert isinstance(out["ready"], bool)


def test_readiness_false_when_db_unreachable(tmp_path) -> None:
    bogus = tmp_path / "no" / "such" / "p.db"
    out = haldir_health.readiness(str(bogus))
    assert out["ready"] is False
    db_check = next(c for c in out["checks"] if c["name"] == "database")
    assert db_check["ok"] is False


# ── HTTP route integration ───────────────────────────────────────────

def test_livez_endpoint_returns_200(haldir_client) -> None:
    r = haldir_client.get("/livez")
    assert r.status_code == 200
    body = r.get_json()
    assert body["alive"] is True
    # Liveness is no-auth, no-DB; must work even on a wedged backend.


def test_readyz_endpoint_returns_200_in_test_env(haldir_client) -> None:
    r = haldir_client.get("/readyz")
    # The test fixture has a clean DB at HALDIR_DB_PATH so readiness
    # should be true. Migration check passes because the test_client
    # pathway runs init_db + auto-migrate at import time.
    assert r.status_code == 200
    body = r.get_json()
    assert body["ready"] is True
    assert {"database", "migrations", "encryption_key"} == \
        {c["name"] for c in body["checks"]}


def test_healthz_back_compat(haldir_client) -> None:
    """Existing consumers (Cloudflare uptime checks, Docker
    HEALTHCHECK on older images) point at /healthz; it must keep
    returning 200 with the legacy field set."""
    r = haldir_client.get("/healthz")
    assert r.status_code == 200
    body = r.get_json()
    assert body.get("status") == "ok"
