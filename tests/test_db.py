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
