"""
Schema initialization must be serialized across processes.

The bug these pin: `CREATE INDEX IF NOT EXISTS` is not concurrency-safe. Two
processes starting together both see the index as missing, both run the DDL,
and one queues behind the other's lock. Once lock_timeout was set on the
schema-init connection that wait became a cancellation — so on a deployment
of N replicas booting at once, every one of them kept losing the race and
none of them finished. The Postgres CI job burned its full 15-minute budget
emitting nothing but alternating cancellations on idx_audit_*.

Two properties have to hold:

  1. Only one process runs the DDL, and the others wait their turn rather
     than being cancelled into a livelock.

  2. The lock is always released, including when schema application raises.
     A lock leaked by a crashed initializer blocks every other replica's
     startup until the server notices the socket is gone.

These run against a fake cursor, because the logic being pinned is the
wait/release discipline rather than anything Postgres does. The integration
itself is covered by the Postgres CI job.

Run: python -m pytest tests/test_schema_init_lock.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import haldir_db  # noqa: E402


class FakeCursor:
    """Answers pg_try_advisory_lock with a scripted sequence.

    `granted` is the list of answers to hand back in order; the last one
    repeats, so a test can say "contended twice, then free" as [False, False,
    True] and "contended forever" as [False].
    """

    def __init__(self, granted):
        self.granted = list(granted)
        self.calls = 0
        self.statements = []

    def execute(self, sql, params=None):
        self.statements.append((sql, params))
        if "pg_try_advisory_lock" in sql:
            self.calls += 1

    def fetchone(self):
        idx = min(self.calls - 1, len(self.granted) - 1)
        return (self.granted[idx],)


# ── Acquiring ────────────────────────────────────────────────────────

def test_lock_is_taken_immediately_when_free() -> None:
    cur = FakeCursor([True])
    haldir_db._acquire_schema_init_lock(cur)
    assert cur.calls == 1, "a free lock should take exactly one attempt"


def test_lock_waits_out_a_contended_start() -> None:
    """The winner is still initializing; we wait, then proceed.

    This is the case that used to be a livelock: rather than retrying DDL
    under contention, the loser waits for the lock and then finds the schema
    already in place.
    """
    cur = FakeCursor([False, False, True])
    haldir_db._acquire_schema_init_lock(cur)
    assert cur.calls == 3


def test_lock_gives_up_rather_than_waiting_forever(monkeypatch) -> None:
    """A bounded wait, so a stuck holder is a loud failure not a hang.

    Blocking forever is what the advisory lock would do by default, and a
    startup that hangs with no output is exactly the failure mode this whole
    area already produced once.
    """
    monkeypatch.setattr(haldir_db, "_SCHEMA_INIT_LOCK_WAIT_S", 0.3)
    cur = FakeCursor([False])
    with pytest.raises(RuntimeError, match="schema-init lock"):
        haldir_db._acquire_schema_init_lock(cur)
    assert cur.calls > 1, "it should retry, not give up on the first refusal"


def test_lock_uses_a_key_every_process_shares() -> None:
    """The key has to be a constant, not per-process.

    A key derived from anything process-specific would give every replica its
    own lock and serialize nothing, while still looking correct.
    """
    cur = FakeCursor([True])
    haldir_db._acquire_schema_init_lock(cur)
    sql, params = cur.statements[0]
    assert params == (haldir_db._SCHEMA_INIT_LOCK_KEY,)


# ── Releasing ────────────────────────────────────────────────────────

def test_connection_is_closed_even_when_schema_application_fails(monkeypatch) -> None:
    """The finally is what makes the lock safe to rely on.

    The advisory lock is session-scoped, so closing the connection is what
    releases it. If an exception skipped the close, the lock would be held
    until the server reaped the socket — and every other replica's startup
    would block behind a process that had already given up.
    """
    closed = []

    class FakeConn:
        def cursor(self):
            return FakeCursor([True])

        def close(self):
            closed.append(True)

    class FakePsycopg2:
        @staticmethod
        def connect(*a, **k):
            return FakeConn()

    def boom(conn):
        raise RuntimeError("schema application failed")

    monkeypatch.setitem(sys.modules, "psycopg2", FakePsycopg2)
    monkeypatch.setattr(haldir_db, "_apply_pg_schema", boom)

    with pytest.raises(RuntimeError, match="schema application failed"):
        haldir_db._init_pg()

    assert closed == [True], "the connection must be closed on the failure path"


def test_lock_is_acquired_before_any_ddl(monkeypatch) -> None:
    """Ordering matters: taking the lock after the first CREATE INDEX would
    leave the race it exists to prevent."""
    seen = []

    class RecordCursor(FakeCursor):
        def execute(self, sql, params=None):
            seen.append(sql.strip().split("\n")[0][:40])
            super().execute(sql, params)

    class FakeConn:
        def cursor(self):
            return RecordCursor([True])

        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    class FakePsycopg2:
        @staticmethod
        def connect(*a, **k):
            return FakeConn()

    monkeypatch.setitem(sys.modules, "psycopg2", FakePsycopg2)
    haldir_db._init_pg()

    assert seen, "sanity: the schema should have run"
    assert "pg_try_advisory_lock" in seen[0], (
        f"the lock must be taken first, but the first statement was {seen[0]!r}"
    )


# ── Telling a cancellation apart from a rejection ────────────────────

def test_lock_cancellation_is_recognised_by_exception_class() -> None:
    """psycopg2 raises LockNotAvailable; recognising it by name means this
    works without importing psycopg2 (it may not be installed on SQLite-only
    deployments)."""

    class LockNotAvailable(Exception):
        pass

    assert haldir_db._is_lock_cancellation(LockNotAvailable("nope"))


def test_lock_cancellation_is_recognised_by_message() -> None:
    """And by the server's own wording, for wrapped or generic exceptions."""
    assert haldir_db._is_lock_cancellation(
        Exception("canceling statement due to lock timeout")
    )


def test_ordinary_errors_are_not_called_cancellations() -> None:
    """The distinction is load-bearing: a cancellation means the object was
    never created, which is logged as an error. Everything else stays a
    warning, and misclassifying would either bury a real problem or cry wolf
    on every start."""
    assert not haldir_db._is_lock_cancellation(
        Exception('relation "audit_log" already exists')
    )
    assert not haldir_db._is_lock_cancellation(Exception("syntax error"))
