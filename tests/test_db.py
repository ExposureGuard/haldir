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
import textwrap
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


def test_schema_init_connects_with_the_server_timeouts() -> None:
    """_init_pg connects directly rather than through the pool, and it is the
    path that needs a lock_timeout most — it runs the whole schema, and every
    statement in it takes a lock. It hung the Postgres CI job for fifteen
    minutes at a time, three runs in a row.

    Checked at the source level because there is no Postgres here to connect
    to; `psycopg2` accepting the parameter is covered separately.
    """
    import inspect
    import re

    src = inspect.getsource(haldir_db._init_pg)
    calls = re.findall(r"psycopg2\.connect\(([^)]*)\)", src)
    assert calls, "no connect call found in _init_pg"
    for args in calls:
        assert "options=" in args, (
            f"_init_pg connects without the server-side timeouts: "
            f"psycopg2.connect({args}). It runs DDL, so a lock wait there has "
            f"no bound and blocks application startup."
        )


def test_money_columns_are_double_precision_not_real() -> None:
    """REAL means two different things on the two backends.

    In Postgres REAL is a 4-byte float — about seven significant digits — and
    in SQLite it is 8-byte. So every money column declared REAL was precise on
    SQLite and imprecise on the backend the docs tell enterprises to run:
    1234.56 round-tripped through Postgres as 1234.56005859375.

    The spend cap is the product's central promise and the audit trail records
    cost_usd, so this is money silently drifting, not a style question.

    Checked against the schema text rather than a live table, because the
    difference only appears on Postgres and there is none here to query.
    """
    money_columns = ("max_spend", "spend_limit", "spent", "amount", "cost_usd")
    offenders = [
        line.strip()
        for line in haldir_db._SCHEMA.splitlines()
        if any(line.strip().startswith(f"{c} ") for c in money_columns)
        and "REAL" in line.replace("DOUBLE PRECISION", "")
    ]
    assert not offenders, (
        f"these money columns are declared REAL, which Postgres reads as a "
        f"4-byte float and SQLite as 8-byte, so the two backends disagree on "
        f"precision: {offenders}"
    )


def test_existing_postgres_money_columns_get_widened(tmp_path) -> None:
    """`CREATE TABLE IF NOT EXISTS` does not alter a column that already
    exists, so a deployment created before the fix keeps its float4 columns
    unless the type is changed in place."""
    import inspect

    # _apply_pg_schema, not _init_pg: the latter now only owns the connection
    # (and the schema-init lock around the call), so the DDL lives here.
    src = inspect.getsource(haldir_db._apply_pg_schema)
    assert "DOUBLE PRECISION" in src, (
        "_apply_pg_schema does not widen existing money columns, so a Postgres "
        "deployment created before this keeps losing precision"
    )


def test_pool_exhaustion_does_not_tear_down_in_flight_connections() -> None:
    """Saturation must wait, not destroy.

    The previous handler called `closeall()` and rebuilt the pool. That closes
    connections other threads are actively using, takes the pool's lock while
    doing it, and — because PgConnectionWrapper.close() swallowed putconn
    failures — leaked the connections whose pool had just been replaced. Leaks
    caused exhaustion, exhaustion triggered the rebuild, and the rebuild
    caused the leak.

    Checked at the source level: driving a real pool to exhaustion needs a
    Postgres, and what is being asserted is the shape of the handler.
    """
    import ast
    import inspect

    src = inspect.getsource(haldir_db._get_pg)
    # Parsed, not string-matched: the docstring explains why closeall() was
    # wrong, and a substring search finds that explanation rather than a call.
    # Both attribute calls (pool.closeall()) and plain ones
    # (_wait_for_connection(pool)), or the check only sees half of them.
    calls = set()
    for node in ast.walk(ast.parse(textwrap.dedent(src))):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute):
            calls.add(node.func.attr)
        elif isinstance(node.func, ast.Name):
            calls.add(node.func.id)
    assert "closeall" not in calls, (
        "_get_pg drains the pool on exhaustion, closing connections other "
        "threads are mid-query on. Wait for one to come back instead."
    )
    assert "_wait_for_connection" in calls, (
        "_get_pg has no bounded wait for a free connection"
    )


def test_a_connection_that_cannot_be_returned_is_not_leaked() -> None:
    """PgConnectionWrapper.close() swallowed every failure. A connection whose
    pool was replaced underneath it was then open, unreachable, and counted
    against the pool forever."""
    import inspect

    src = inspect.getsource(haldir_db.PgConnectionWrapper.close)
    assert "close()" in src, (
        "close() lets a failed putconn leak the connection instead of "
        "closing it outright"
    )


# ── The audit-log migration guard ────────────────────────────────────

def _mk(sql: str) -> "sqlite3.Connection":
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.executescript(sql)
    return conn


def test_the_migration_guard_notices_a_missing_column() -> None:
    """The trap this closes.

    The guard used to return True on the presence of idx_audit_seq alone. It
    happens to be correct today, because the index and the hash_version
    column were introduced in the same release — but it is correct by
    coincidence, not by construction. The day hash_version is added later
    than the index, every database that already has the index would
    short-circuit here, never get the column, and then fail *every audit
    write* with "no column named hash_version" on upgrade.

    A schema with the index but not the column is therefore the case that
    matters, and it must report "not current" so the migration runs.
    """
    conn = _mk("""
        CREATE TABLE audit_log (entry_id TEXT PRIMARY KEY, seq INTEGER, tenant_id TEXT);
        CREATE UNIQUE INDEX idx_audit_seq ON audit_log(tenant_id, seq);
    """)
    assert haldir_db._audit_seq_is_current(conn) is False, (
        "a half-migrated log reported itself current, so hash_version would "
        "never be added and every audit write would fail"
    )
    conn.close()


def test_the_migration_guard_skips_a_fully_migrated_log() -> None:
    """The reason the guard exists: ADD COLUMN and CREATE INDEX take ACCESS
    EXCLUSIVE locks, and init_db runs at every start. Once the work is done,
    nothing may touch the table."""
    conn = _mk("""
        CREATE TABLE audit_log (
            entry_id TEXT PRIMARY KEY, seq INTEGER,
            hash_version INTEGER, tenant_id TEXT);
        CREATE UNIQUE INDEX idx_audit_seq ON audit_log(tenant_id, seq);
    """)
    assert haldir_db._audit_seq_is_current(conn) is True
    conn.close()


def test_the_migration_guard_runs_on_a_fresh_log() -> None:
    conn = _mk("CREATE TABLE audit_log (entry_id TEXT PRIMARY KEY, tenant_id TEXT);")
    assert haldir_db._audit_seq_is_current(conn) is False
    conn.close()


def test_the_migration_guard_runs_when_there_is_no_table_at_all() -> None:
    """init_db is called against databases that do not have the schema yet."""
    conn = _mk("CREATE TABLE something_else (x INTEGER);")
    assert haldir_db._audit_seq_is_current(conn) is False
    conn.close()


# ── Connection vs cursor ─────────────────────────────────────────────
#
# psycopg2 connections have no .execute — only cursors do. sqlite3
# connections have both. So code written against the sqlite3 shape runs on
# SQLite and raises AttributeError on Postgres, and if that raise lands in a
# broad except it does so silently. That is exactly how the audit chain's
# uniqueness constraint came never to be created on Postgres: the migration
# that builds it was handed a raw psycopg2 connection, raised, was logged as
# a warning, and the fork protection did not exist.

class _Cursor:
    def __init__(self, conn):
        self._conn = conn
        self._rows: list = []
        self.statements: list[str] = []

    def execute(self, sql, params=None):
        self.statements.append(sql)
        self._conn.statements.append(sql)
        if "pragma_table_info" in sql or "information_schema" in sql:
            # Columns look migrated...
            self._rows = [("entry_id",), ("seq",), ("hash_version",)]
        elif "pg_indexes" in sql or "sqlite_master" in sql:
            # ...but the index is absent, so the guard must report "not
            # current" and the migration body runs. Returning the index here
            # instead would short-circuit _migrate_audit_seq and these tests
            # would assert nothing — which is exactly what the first version
            # of them did, caught by mutating the shim back and watching them
            # still pass.
            self._rows = []
        else:
            self._rows = []
        return self

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def close(self):
        pass


class Psycopg2LikeConn:
    """Has what a psycopg2 connection has, and nothing else."""

    def __init__(self):
        self.statements: list[str] = []

    def cursor(self):
        return _Cursor(self)

    def commit(self):
        pass

    def rollback(self):
        pass


def test_the_migration_runs_on_a_connection_without_execute() -> None:
    """The regression.

    Passing a psycopg2-shaped connection must work. Before the shim this
    raised AttributeError, which the caller swallowed — so the migration
    silently did nothing on Postgres while working on SQLite, and the only
    visible symptom was, much later, a forked audit chain.
    """
    conn = Psycopg2LikeConn()
    haldir_db._migrate_audit_seq(conn)   # must not raise
    joined = " ".join(conn.statements)
    # Matched on CREATE, not on the name alone: the guard's own catalogue
    # query contains the literal 'idx_audit_seq', so asserting on the name
    # passes even when no index is ever built. The first version of this test
    # did exactly that and survived reverting the fix.
    assert "CREATE UNIQUE INDEX" in joined and "idx_audit_seq" in joined, (
        f"the unique index was never created — this is the fork protection. "
        f"Statements that did run: {conn.statements}"
    )


def test_the_guard_runs_on_a_connection_without_execute() -> None:
    """Same shape, same hazard: the guard also used conn.execute, so on
    Postgres it raised, the broad except swallowed it, and it always
    reported 'not current'."""
    conn = Psycopg2LikeConn()
    haldir_db._audit_seq_is_current(conn)   # must not raise


def test_psycopg2_like_connection_really_lacks_execute() -> None:
    """Guards the guard: if a future refactor gives this fake an .execute
    method, the two tests above stop testing anything."""
    assert not hasattr(Psycopg2LikeConn(), "execute")


def test_exec_works_on_both_shapes(tmp_path) -> None:
    """The shim itself, against a real sqlite3 connection and the fake."""
    sqlite_conn = sqlite3.connect(":memory:")
    sqlite_conn.execute("CREATE TABLE t (a INTEGER)")
    haldir_db._exec(sqlite_conn, "INSERT INTO t VALUES (1)")
    assert haldir_db._exec(sqlite_conn, "SELECT a FROM t").fetchone()[0] == 1
    sqlite_conn.close()

    fake = Psycopg2LikeConn()
    haldir_db._exec(fake, "SELECT 1")
    assert fake.statements == ["SELECT 1"]


# ── A failed statement must not poison the transaction ───────────────
#
# Postgres aborts the whole transaction on any statement error, and every
# statement after that fails with "current transaction is aborted" until
# somebody rolls back. This is the mechanism behind the last Postgres-only
# failure: the audit-seq guard probes SQLite's catalogue first, which raises
# on Postgres and aborted the transaction, so the migration's own ALTERs and
# its SELECT were swallowed and it returned early — silently, and before the
# line that would have reported anything.

class AbortingCursor:
    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=None):
        if self._conn.aborted:
            raise RuntimeError("current transaction is aborted, commands "
                               "ignored until end of transaction block")
        self._conn.statements.append(sql)
        if "pragma_table_info" in sql:
            self._conn.aborted = True
            raise RuntimeError('relation "pragma_table_info" does not exist')
        return self

    def fetchall(self):
        return []

    def fetchone(self):
        return None

    def close(self):
        pass


class AbortingConn:
    """A connection with Postgres's transaction-abort semantics."""

    def __init__(self):
        self.aborted = False
        self.statements: list[str] = []

    def cursor(self):
        return AbortingCursor(self)

    def rollback(self):
        self.aborted = False

    def commit(self):
        pass


def test_a_failed_statement_does_not_leave_the_transaction_aborted() -> None:
    """The regression.

    Without the rollback in _exec, one failed probe — and the guard's first
    probe is SQLite SQL that always fails on Postgres — makes every
    subsequent statement fail, so the migration silently does nothing.
    """
    conn = AbortingConn()
    with pytest.raises(Exception):
        haldir_db._exec(conn, "SELECT name FROM pragma_table_info('audit_log')")

    assert conn.aborted is False, (
        "the failed statement left the transaction aborted, so everything "
        "after it fails — which is how the audit-seq migration came to do "
        "nothing at all on Postgres without logging anything"
    )
    # And the connection is usable again.
    haldir_db._exec(conn, "SELECT 1")
    assert conn.statements[-1] == "SELECT 1"


def test_the_migration_completes_on_a_connection_that_aborts() -> None:
    """End to end: the guard's SQLite probe fails, and the migration still
    reaches the index."""
    conn = AbortingConn()
    haldir_db._migrate_audit_seq(conn)
    joined = " ".join(conn.statements)
    assert "CREATE UNIQUE INDEX" in joined, (
        f"the migration never reached the constraint. Statements that ran: "
        f"{conn.statements}"
    )
