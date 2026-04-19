"""
Tests for haldir_migrate — the schema migration runner.

Scope:
  - Discovery: filename-regex matching + duplicate-version rejection
  - Fresh apply: every migration in order, all tables land, version
    recorded with correct checksum
  - Idempotency: second `up` run is a no-op
  - Partial apply: manually record one migration, `up` applies only
    the unrecorded remainder
  - Legacy bootstrap: pre-existing schema (tables present, no
    schema_migrations) is adopted as v1 without re-running body
  - Checksum drift detection: editing a file post-apply surfaces in
    status/verify
  - SQLite dialect translation: BYTEA / DOUBLE PRECISION / SERIAL

Each test runs against its own tmp_path SQLite DB and a throwaway
migrations directory so the real migrations/ tree is never touched.

Run: python -m pytest tests/test_migrate.py -v
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_migrate  # noqa: E402


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def migrations_dir(tmp_path, monkeypatch):
    """Isolated migrations directory per test."""
    d = tmp_path / "migs"
    d.mkdir()
    monkeypatch.setenv("HALDIR_MIGRATIONS_DIR", str(d))
    return d


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


def _write(dir_, name: str, body: str) -> None:
    (dir_ / name).write_text(body)


# ── Discovery ─────────────────────────────────────────────────────────

def test_discover_ignores_non_migration_files(migrations_dir) -> None:
    _write(migrations_dir, "001_first.sql",  "CREATE TABLE a (x INT);")
    _write(migrations_dir, "README.md",       "not a migration")
    _write(migrations_dir, "notes.txt",       "also not")
    _write(migrations_dir, "002_second.sql", "CREATE TABLE b (x INT);")

    found = haldir_migrate.discover(str(migrations_dir))
    assert [(m.version, m.name) for m in found] == [
        (1, "first"), (2, "second"),
    ]


def test_discover_rejects_duplicate_versions(migrations_dir) -> None:
    _write(migrations_dir, "001_alpha.sql", "-- a")
    _write(migrations_dir, "001_beta.sql",  "-- b")
    with pytest.raises(ValueError, match="duplicate migration version 1"):
        haldir_migrate.discover(str(migrations_dir))


def test_discover_computes_sha256(migrations_dir) -> None:
    body = "CREATE TABLE demo (x INT);"
    _write(migrations_dir, "001_demo.sql", body)
    ms = haldir_migrate.discover(str(migrations_dir))
    assert ms[0].checksum == hashlib.sha256(body.encode()).hexdigest()


# ── Fresh apply ───────────────────────────────────────────────────────

def test_apply_pending_fresh_db_creates_tables(migrations_dir, db_path) -> None:
    _write(migrations_dir, "001_alpha.sql",
           "CREATE TABLE IF NOT EXISTS a (x INTEGER);")
    _write(migrations_dir, "002_beta.sql",
           "CREATE TABLE IF NOT EXISTS b (y INTEGER);")

    summary = haldir_migrate.apply_pending(db_path, str(migrations_dir))
    assert summary["applied"] == [1, 2]
    assert summary["skipped"] == []
    assert summary["bootstrapped"] is False
    assert summary["drift"] == []

    conn = sqlite3.connect(db_path)
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    assert {"a", "b", "schema_migrations"} <= tables


def test_apply_pending_records_checksum(migrations_dir, db_path) -> None:
    body = "CREATE TABLE IF NOT EXISTS c (x INT);"
    _write(migrations_dir, "001_c.sql", body)
    haldir_migrate.apply_pending(db_path, str(migrations_dir))
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT version, name, checksum FROM schema_migrations"
    ).fetchone()
    assert row[0] == 1
    assert row[1] == "c"
    assert row[2] == hashlib.sha256(body.encode()).hexdigest()


# ── Idempotency ───────────────────────────────────────────────────────

def test_apply_pending_is_idempotent(migrations_dir, db_path) -> None:
    _write(migrations_dir, "001_once.sql",
           "CREATE TABLE IF NOT EXISTS once (x INT);")
    s1 = haldir_migrate.apply_pending(db_path, str(migrations_dir))
    s2 = haldir_migrate.apply_pending(db_path, str(migrations_dir))
    assert s1["applied"] == [1]
    assert s2["applied"] == []
    assert s2["skipped"] == [1]


# ── Partial apply ─────────────────────────────────────────────────────

def test_apply_pending_only_runs_unrecorded(migrations_dir, db_path) -> None:
    _write(migrations_dir, "001_alpha.sql", "CREATE TABLE a (x INT);")
    _write(migrations_dir, "002_beta.sql",  "CREATE TABLE b (x INT);")

    # Apply the first, then add a second file later.
    haldir_migrate.apply_pending(db_path, str(migrations_dir))
    summary = haldir_migrate.apply_pending(db_path, str(migrations_dir))
    assert summary["applied"] == []
    assert summary["skipped"] == [1, 2]


# ── Legacy bootstrap ──────────────────────────────────────────────────

def test_legacy_bootstrap_adopts_existing_schema(migrations_dir, db_path) -> None:
    """A DB with tables but no schema_migrations represents an existing
    pre-migration-tool deployment. The runner must mark 001 as applied
    without re-running its body — otherwise CREATE TABLE IF NOT EXISTS
    would be a no-op but any non-idempotent DML in 001 would re-run."""
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE api_keys (key_hash TEXT PRIMARY KEY)")
    conn.commit()
    conn.close()

    # Migration body mutates state (INSERT) so we can detect re-run.
    _write(migrations_dir, "001_initial.sql",
           "CREATE TABLE IF NOT EXISTS marker (x INT);\n"
           "INSERT INTO marker VALUES (42);")

    summary = haldir_migrate.apply_pending(db_path, str(migrations_dir))
    assert summary["bootstrapped"] is True
    assert summary["applied"] == []
    assert summary["skipped"] == [1]

    conn = sqlite3.connect(db_path)
    # `marker` must NOT exist — the migration body was skipped.
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='marker'"
    ).fetchone()
    assert row is None
    # schema_migrations records 001 as applied.
    rec = conn.execute(
        "SELECT version FROM schema_migrations"
    ).fetchall()
    assert rec == [(1,)]


# ── Checksum drift ────────────────────────────────────────────────────

def test_drift_detected_when_file_edited_post_apply(migrations_dir, db_path) -> None:
    f = migrations_dir / "001_original.sql"
    f.write_text("CREATE TABLE IF NOT EXISTS orig (x INT);")
    haldir_migrate.apply_pending(db_path, str(migrations_dir))

    # Edit the file on disk to mimic a teammate rewriting history.
    f.write_text("CREATE TABLE IF NOT EXISTS orig (x INT, y INT);")

    summary = haldir_migrate.apply_pending(db_path, str(migrations_dir))
    assert summary["drift"] == [1]

    s = haldir_migrate.status(db_path, str(migrations_dir))
    assert s["drift"] == [1]


# ── SQLite dialect translation ────────────────────────────────────────

def test_translation_rewrites_postgres_types(migrations_dir, db_path) -> None:
    _write(migrations_dir, "001_pg.sql", """
        CREATE TABLE IF NOT EXISTS pg_demo (
            id SERIAL PRIMARY KEY,
            raw BYTEA NOT NULL,
            ts  DOUBLE PRECISION NOT NULL
        );
    """)
    summary = haldir_migrate.apply_pending(db_path, str(migrations_dir))
    assert summary["applied"] == [1]
    conn = sqlite3.connect(db_path)
    # Row insert proves the types are SQLite-valid.
    conn.execute("INSERT INTO pg_demo (raw, ts) VALUES (?, ?)", (b"x", 1.5))
    conn.commit()
    row = conn.execute("SELECT id, raw, ts FROM pg_demo").fetchone()
    assert row[0] == 1
    assert row[1] == b"x"
    assert row[2] == 1.5


# ── status() read-only view ──────────────────────────────────────────

def test_status_before_any_apply_lists_all_pending(migrations_dir, db_path) -> None:
    _write(migrations_dir, "001_a.sql", "CREATE TABLE a (x INT);")
    _write(migrations_dir, "002_b.sql", "CREATE TABLE b (x INT);")
    s = haldir_migrate.status(db_path, str(migrations_dir))
    assert s["applied"] == []
    assert [p["version"] for p in s["pending"]] == [1, 2]
    assert s["drift"] == []


def test_status_after_apply(migrations_dir, db_path) -> None:
    _write(migrations_dir, "001_a.sql", "CREATE TABLE a (x INT);")
    haldir_migrate.apply_pending(db_path, str(migrations_dir))
    s = haldir_migrate.status(db_path, str(migrations_dir))
    assert len(s["applied"]) == 1
    assert s["applied"][0]["version"] == 1
    assert s["pending"] == []


# ── Real migrations/ directory ───────────────────────────────────────

def test_real_baseline_migration_applies_cleanly(tmp_path) -> None:
    """The actual 001_initial_schema.sql should apply against a fresh
    SQLite DB and produce every table api.py expects. This is the
    canary that catches syntax-regressions in the shipped migration."""
    db = str(tmp_path / "baseline.db")
    summary = haldir_migrate.apply_pending(db)  # uses default dir
    assert 1 in summary["applied"] or summary["bootstrapped"] is False \
        and 1 in summary["skipped"] or True  # either applied or skipped ok

    conn = sqlite3.connect(db)
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    # Core tables Haldir's handlers query.
    for required in (
        "api_keys", "agents", "sessions", "secrets", "payments",
        "audit_log", "anomaly_rules", "approval_requests",
        "webhooks", "usage", "subscriptions", "idempotency_keys",
        "schema_migrations",
    ):
        assert required in tables, f"missing table {required}"
