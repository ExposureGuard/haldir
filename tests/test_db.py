"""
Tests for haldir_db — the SQLite + Postgres persistence layer.

Scope:
  - SQLite pragma application (every connection should land with the
    tuned settings)
  - Pool-size configurability (Postgres — tested at the module-constant
    level since we don't hit a real Postgres in CI)

Run: python -m pytest tests/test_db.py -v
"""

from __future__ import annotations

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_db  # noqa: E402
from haldir_db import get_db, init_db  # noqa: E402


# ── SQLite pragma application ─────────────────────────────────────────

def test_sqlite_applies_wal_journal_mode(tmp_path) -> None:
    """WAL is load-bearing for concurrent readers; regression would
    silently halve throughput under load."""
    db = tmp_path / "p.db"
    conn = haldir_db.get_db(str(db))
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
    finally:
        conn.close()


def test_sqlite_applies_synchronous_normal(tmp_path) -> None:
    """NORMAL + WAL is the safe+fast combo; FULL would slow write
    commits by an order of magnitude."""
    db = tmp_path / "p.db"
    conn = haldir_db.get_db(str(db))
    try:
        # synchronous=NORMAL -> integer 1 in PRAGMA output.
        val = conn.execute("PRAGMA synchronous").fetchone()[0]
        assert int(val) == 1
    finally:
        conn.close()


def test_sqlite_temp_store_memory(tmp_path) -> None:
    db = tmp_path / "p.db"
    conn = haldir_db.get_db(str(db))
    try:
        # temp_store=MEMORY -> integer 2.
        val = conn.execute("PRAGMA temp_store").fetchone()[0]
        assert int(val) == 2
    finally:
        conn.close()


def test_sqlite_mmap_size_set(tmp_path) -> None:
    """256 MiB memory-mapped region keeps hot pages in RAM."""
    db = tmp_path / "p.db"
    conn = haldir_db.get_db(str(db))
    try:
        val = conn.execute("PRAGMA mmap_size").fetchone()[0]
        assert int(val) == 268435456
    finally:
        conn.close()


def test_sqlite_foreign_keys_enforced(tmp_path) -> None:
    db = tmp_path / "p.db"
    conn = haldir_db.get_db(str(db))
    try:
        val = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert int(val) == 1
    finally:
        conn.close()


def test_sqlite_busy_timeout_5s(tmp_path) -> None:
    """Writer-lock contention waits 5 s before erroring — long enough
    for the legitimate peak, short enough to fail fast on deadlock."""
    db = tmp_path / "p.db"
    conn = haldir_db.get_db(str(db))
    try:
        val = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert int(val) == 5000
    finally:
        conn.close()


def test_sqlite_row_factory_yields_row_objects(tmp_path) -> None:
    """The rest of the codebase expects sqlite3.Row for dict-style
    access; a default-cursor regression would break every handler."""
    db = tmp_path / "p.db"
    conn = haldir_db.get_db(str(db))
    try:
        conn.execute("CREATE TABLE t (a INTEGER, b TEXT)")
        conn.execute("INSERT INTO t VALUES (1, 'x')")
        row = conn.execute("SELECT * FROM t").fetchone()
        assert row["a"] == 1
        assert row["b"] == "x"
    finally:
        conn.close()


# ── Postgres pool-size configurability ─────────────────────────────────
#
# We can't bring a Postgres up in CI, so these tests assert at the
# module-constant layer that the env-var plumbing works. The actual
# pool is exercised by integration tests in any Postgres-backed
# deployment.

def test_pg_pool_defaults_are_reasonable() -> None:
    # Reload the module via env defaults; we only check that the
    # defaults aren't absurd (1..1 would serialize everything).
    assert haldir_db._pg_pool_min >= 1
    assert haldir_db._pg_pool_max >= haldir_db._pg_pool_min
    assert haldir_db._pg_pool_max >= 5  # room for parallelism


def test_pg_pool_env_override(monkeypatch) -> None:
    """Module-level env reads happen at import. Exercise the override
    path by forcing a reimport with a modified environment."""
    monkeypatch.setenv("HALDIR_PG_POOL_MIN", "5")
    monkeypatch.setenv("HALDIR_PG_POOL_MAX", "40")
    import importlib
    reloaded = importlib.reload(haldir_db)
    try:
        assert reloaded._pg_pool_min == 5
        assert reloaded._pg_pool_max == 40
    finally:
        # Restore the original module state so other tests (which rely
        # on the module-level constants) don't see the override.
        monkeypatch.delenv("HALDIR_PG_POOL_MIN", raising=False)
        monkeypatch.delenv("HALDIR_PG_POOL_MAX", raising=False)
        importlib.reload(haldir_db)


def test_sqlite_pragmas_tuple_is_stable() -> None:
    """_SQLITE_PRAGMAS is part of the observable surface (tests assert
    against it, dashboards may read it). Regression against silent
    reordering."""
    names = [n for n, _ in haldir_db._SQLITE_PRAGMAS]
    assert names == [
        "journal_mode", "synchronous", "temp_store",
        "mmap_size", "foreign_keys", "busy_timeout",
    ]


# ── Postgres must not wait for a lock forever ────────────────────────
#
# The SQLite side is covered by the busy_timeout pragma asserted above. The
# Postgres side had no equivalent: Postgres waits for a row lock indefinitely,
# and `lock_timeout` defaults to 0, meaning never.

def test_postgres_connections_set_a_lock_timeout() -> None:
    """One stalled transaction must not park every other writer forever.

    This is a production hazard and it is also what broke the Postgres CI job:
    the run sat for fifteen minutes and printed nothing, because a worker
    thread holding a lock had exceeded its join timeout and the main thread
    then blocked on the same lock when it did its own database work. Marking
    the threads daemons did not help — pytest was stuck, not exiting.
    """
    assert "lock_timeout=" in haldir_db._PG_SERVER_OPTIONS, (
        f"pooled Postgres connections set no lock_timeout, so a query blocked "
        f"on a row lock waits forever: options={haldir_db._PG_SERVER_OPTIONS!r}"
    )


def test_postgres_connections_set_a_statement_timeout() -> None:
    """A backstop against a runaway query.

    Set high on purpose: it is not a request deadline, and a low value would
    abort legitimate migrations and large exports.
    """
    assert "statement_timeout=" in haldir_db._PG_SERVER_OPTIONS, (
        f"no statement_timeout backstop: options={haldir_db._PG_SERVER_OPTIONS!r}"
    )


def test_the_postgres_timeouts_are_overridable() -> None:
    """A deployment with genuinely long migrations needs to raise them."""
    import os
    import subprocess
    import sys

    env = dict(os.environ, HALDIR_PG_LOCK_TIMEOUT_MS="1234",
               HALDIR_PG_STATEMENT_TIMEOUT_MS="5678")
    code = (
        "import haldir_db; "
        "print(haldir_db._PG_SERVER_OPTIONS)"
    )
    out = subprocess.run([sys.executable, "-c", code], env=env,
                         capture_output=True, text=True,
                         cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert out.returncode == 0, out.stderr
    assert "lock_timeout=1234" in out.stdout, out.stdout
    assert "statement_timeout=5678" in out.stdout, out.stdout


def test_the_audit_seq_migration_is_skipped_once_applied(tmp_path) -> None:
    """init_db runs at every application start, and the audit-seq migration
    takes an ACCESS EXCLUSIVE lock on audit_log to ADD COLUMN and CREATE
    INDEX. Re-applying DDL that is already in place means N replicas booting
    together each queue for that lock — which is where the Postgres CI job
    hung, inside init_db, before any test body ran.

    So the second call must not touch the table. The catalogue probe answers
    that without taking a lock; this pins both halves.
    """
    import haldir_db

    db = str(tmp_path / "seq.db")

    conn = get_db(db)
    try:
        # Nothing applied yet — the probe must say so, or the first real
        # migration would be skipped and the chain would go unguarded.
        assert haldir_db._audit_seq_is_current(conn) is False
    finally:
        conn.close()

    init_db(db)

    conn = get_db(db)
    try:
        assert haldir_db._audit_seq_is_current(conn) is True
    finally:
        conn.close()

    # And a repeat init is a no-op rather than an error or a second DDL pass.
    init_db(db)


def test_the_columns_the_migration_adds_really_exist(tmp_path) -> None:
    """The probe checks the index; the migration also adds two columns. If it
    short-circuits on a database that has the index but not the columns, the
    chain writes fail at runtime instead."""
    db = str(tmp_path / "cols.db")
    init_db(db)

    conn = get_db(db)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    conn.close()

    assert {"seq", "hash_version"} <= cols, (
        f"init_db reported the audit-log migration as applied while these "
        f"columns are missing: {sorted({'seq', 'hash_version'} - cols)}"
    )
