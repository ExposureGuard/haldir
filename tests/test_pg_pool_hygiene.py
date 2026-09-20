"""
A pooled connection must go back with no transaction open.

What this pins, and why it took a while to find:

The Postgres CI job spent fifteen minutes at a time emitting

    ERROR: canceling statement due to lock timeout
    STATEMENT: CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id)

on every idx_audit_* index in turn, from connections that kept taking turns
losing. The obvious reading was a race between schema initializers, and an
advisory lock was added to serialize them — which did not help, because the
blocker was never another initializer.

CREATE INDEX takes a SHARE lock on the table. SHARE conflicts with ROW
EXCLUSIVE, which is what any *open write transaction* holds. Connections here
are not autocommit, and PgConnectionWrapper.close() returned them to the pool
without committing or rolling back — so a write that was never committed put
the connection back mid-transaction, still holding its locks, and the next
borrower inherited them. The transaction then stays open until somebody
commits it, which nobody does, because everyone believes the connection was
closed. Every later CREATE INDEX on that table blocks, and gets cancelled.

SQLite cannot show this: sqlite3.close() discards uncommitted work, and
get_db on SQLite returns a fresh connection each time instead of recycling
one. So the bug lived only on the backend the docs tell enterprises to run.

These tests use fakes. The behaviour under test is "what does close() do to
the connection before releasing it", which is not something Postgres needs to
be present to answer, and the real Postgres job covers the integration.

Run: python -m pytest tests/test_pg_pool_hygiene.py -v
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import haldir_db  # noqa: E402


class FakeConn:
    def __init__(self, closed: int = 0):
        self.closed = closed
        self.rolled_back = 0
        self.committed = 0

    def rollback(self):
        self.rolled_back += 1

    def commit(self):
        self.committed += 1

    def close(self):
        self.closed = 1


class FakePool:
    def __init__(self, raise_on_put: bool = False):
        self.returned: list = []
        self.raise_on_put = raise_on_put

    def putconn(self, conn):
        if self.raise_on_put:
            raise RuntimeError("pool was rebuilt underneath this wrapper")
        self.returned.append(conn)


def _wrapper(conn: FakeConn, pool: FakePool) -> "haldir_db.PgConnectionWrapper":
    return haldir_db.PgConnectionWrapper(conn, pool)


def test_close_rolls_back_before_returning_the_connection() -> None:
    """The bug. Without this the connection goes back holding its locks."""
    conn, pool = FakeConn(), FakePool()
    _wrapper(conn, pool).close()

    assert conn.rolled_back == 1, (
        "close() returned the connection to the pool without rolling back, so "
        "an uncommitted write keeps its locks and the next borrower inherits "
        "an open transaction"
    )
    assert pool.returned == [conn]


def test_rollback_happens_before_putconn() -> None:
    """Order matters: releasing first, then rolling back, leaves a window in
    which another thread has already borrowed the connection."""
    order: list[str] = []

    class OrderedConn(FakeConn):
        def rollback(self):
            order.append("rollback")
            super().rollback()

    class OrderedPool(FakePool):
        def putconn(self, conn):
            order.append("putconn")
            super().putconn(conn)

    _wrapper(OrderedConn(), OrderedPool()).close()
    assert order == ["rollback", "putconn"], order


def test_a_closed_connection_is_not_rolled_back() -> None:
    """A dead connection has no transaction, and calling into one raises."""
    conn, pool = FakeConn(closed=1), FakePool()
    _wrapper(conn, pool).close()
    assert conn.rolled_back == 0
    assert pool.returned == [conn], "it should still be handed back"


def test_a_failing_rollback_does_not_leak_the_connection() -> None:
    """Rolling back must not be able to prevent the connection being
    returned — that would trade a lock leak for a connection leak."""

    class BrokenConn(FakeConn):
        def rollback(self):
            raise RuntimeError("connection already gone")

    conn, pool = BrokenConn(), FakePool()
    _wrapper(conn, pool).close()
    assert pool.returned == [conn]


def test_a_failing_putconn_still_closes_the_connection() -> None:
    """The pre-existing behaviour, kept: a connection that cannot be
    returned is closed rather than left dangling."""
    conn, pool = FakeConn(), FakePool(raise_on_put=True)
    _wrapper(conn, pool).close()
    assert conn.closed == 1


def test_close_is_idempotent_enough_to_be_safe() -> None:
    """close() gets called on paths that already committed. Those must not
    be turned into errors by the rollback."""
    conn, pool = FakeConn(), FakePool()
    w = _wrapper(conn, pool)
    w.commit()
    w.close()
    assert conn.committed == 1
    assert conn.rolled_back == 1, (
        "a rollback after a commit is a no-op in psycopg2 and must still be "
        "issued, because close() cannot know whether a write is pending"
    )


# ── The wrapper must have the DB-API surface callers use ─────────────

def test_the_wrapper_has_every_dbapi_method_callers_use() -> None:
    """It presents psycopg2 as sqlite3.Connection, so a caller must not have
    to check which it holds.

    `commit` was there and `rollback` was not. haldir_migrate.py had already
    grown `conn.rollback() if hasattr(conn, "rollback") else None` to cope;
    the audit append's retry path had not, so on Postgres a collision — the
    case the uniqueness constraint exists to create — raised AttributeError
    instead of re-reading the tail and retrying.
    """
    for method in ("execute", "executescript", "commit", "rollback", "close"):
        assert hasattr(haldir_db.PgConnectionWrapper, method), (
            f"PgConnectionWrapper is missing {method}, so callers that use it "
            f"work on SQLite and raise AttributeError on Postgres"
        )


def test_close_and_rollback_are_both_present_on_a_fake() -> None:
    """The two methods the append path uses together, in order.

    Two rollbacks is the expected count, not one: the caller rolls back to
    discard its failed insert, and close() rolls back again on the way to the
    pool. A rollback with nothing pending is a no-op in psycopg2, so the
    second costs nothing and close() cannot know whether one is needed.
    """
    conn, pool = FakeConn(), FakePool()
    w = haldir_db.PgConnectionWrapper(conn, pool)
    w.rollback()
    assert conn.rolled_back == 1, "the explicit rollback should reach the connection"
    w.close()
    assert conn.rolled_back == 2, "close() also rolls back, and that is harmless"
    assert pool.returned == [conn]
