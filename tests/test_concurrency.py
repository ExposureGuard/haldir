"""
Concurrency invariants.

Haldir makes two promises that only hold if concurrent writes behave:

  1. An agent cannot spend past its cap.
  2. The audit log is a single chain, so tampering is detectable.

Both are read-modify-write sequences, and neither was guarded by a lock, a
transaction, or a conditional update. Under one request at a time they are
correct; under two, they are not. Every one of these tests passes trivially
when run single-threaded, which is why the rest of the suite never caught
them.

Run: python -m pytest tests/test_concurrency.py -v
"""

from __future__ import annotations

import os
import sqlite3
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_db import init_db, get_db  # noqa: E402
from haldir_gate import Gate  # noqa: E402
from haldir_vault import Vault  # noqa: E402
from haldir_watch import Watch  # noqa: E402


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "concurrency.db")
    init_db(path)
    return path


def run_together(fn, count):
    """Run `fn(i)` on `count` threads released at the same instant.

    A Barrier rather than a pool: the whole point is to have every thread
    inside the critical section at once, which a work queue would serialise
    away.
    """
    barrier = threading.Barrier(count)
    results: list = [None] * count
    errors: list = [None] * count

    def worker(i):
        try:
            barrier.wait(timeout=10)
            results[i] = fn(i)
        except Exception as e:  # noqa: BLE001 — surfaced by the assertions
            errors[i] = e

    # daemon=True: a worker stuck in a blocking database call must not be able
    # to hold the interpreter open. Without it a hang inside one thread becomes
    # a hang of the whole run, at exit, producing no output at all — a much
    # harder failure to read than a red test.
    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    if any(errors):
        raise AssertionError(f"worker raised: {[e for e in errors if e]}")
    return results


# ── The spend cap ────────────────────────────────────────────────────

def test_concurrent_payments_cannot_exceed_the_cap(db) -> None:
    """Ten simultaneous $20 authorizations against a $100 cap.

    At most five may succeed. If the check and the write are not atomic,
    every thread reads spent=0, every thread passes the check, and the
    session authorizes $200 against a $100 limit — which is the one thing
    the product exists to prevent.
    """
    PER_CALL, THREADS, CAP = 20.0, 10, 100.0

    vault = Vault(db_path=db)
    gate = Gate(db_path=db)
    session = gate.create_session("spend-racer", scopes=["spend"],
                                  spend_limit=CAP, ttl=3600)

    results = run_together(
        lambda _i: vault.authorize_payment(session, PER_CALL), THREADS,
    )
    granted = [r for r in results if r.get("authorized")]
    total = sum(r["amount"] for r in granted)

    assert total <= CAP, (
        f"authorized ${total:.2f} against a ${CAP:.2f} cap "
        f"({len(granted)} of {THREADS} calls succeeded) — the budget check "
        f"and the spend write are not atomic"
    )

    # The persisted total must agree with what was handed out.
    conn = get_db(db)
    row = conn.execute("SELECT spent FROM sessions WHERE session_id = ?",
                       (session.session_id,)).fetchone()
    conn.close()
    assert row is not None
    assert row["spent"] <= CAP + 1e-9, (
        f"the sessions row records spent=${row['spent']:.2f} against a "
        f"${CAP:.2f} cap"
    )


def test_gate_record_spend_respects_the_cap_under_concurrency(db) -> None:
    """Same defect through the Gate entry point, which is what the REST API
    and the Python SDK actually call."""
    PER_CALL, THREADS, CAP = 25.0, 12, 100.0

    gate = Gate(db_path=db)
    session = gate.create_session("gate-racer", scopes=["spend"],
                                  spend_limit=CAP, ttl=3600)

    outcomes = run_together(
        lambda _i: gate.record_spend(session.session_id, PER_CALL), THREADS,
    )
    total = sum(PER_CALL for ok in outcomes if ok)

    assert total <= CAP, (
        f"Gate.record_spend allowed ${total:.2f} against a ${CAP:.2f} cap"
    )


def test_a_single_payment_over_the_cap_is_still_refused(db) -> None:
    """The guard rail that already worked, kept so a fix for the race cannot
    quietly remove the ordinary check."""
    vault = Vault(db_path=db)
    gate = Gate(db_path=db)
    session = gate.create_session("honest", scopes=["spend"],
                                  spend_limit=50.0, ttl=3600)

    assert vault.authorize_payment(session, 30.0)["authorized"] is True
    assert vault.authorize_payment(session, 30.0)["authorized"] is False


# ── The hash chain ───────────────────────────────────────────────────

def test_concurrent_audit_appends_keep_the_chain_linear(db) -> None:
    """The chain is built by reading the tail's hash and chaining onto it.

    Two writers that both read the same tail produce two entries naming the
    same predecessor — a fork. The log still verifies as "unchanged" entry
    by entry, but it is no longer a chain, and a log that is not a chain
    cannot prove anything about its own history.
    """
    THREADS = 12

    gate = Gate(db_path=db)
    watch = Watch(db_path=db)
    session = gate.create_session("chain-racer", scopes=["read"], ttl=3600)

    run_together(
        lambda i: watch.log_action(session, tool="racer", action=f"step-{i}"),
        THREADS,
    )

    conn = get_db(db)
    rows = conn.execute(
        "SELECT entry_id, prev_hash, entry_hash FROM audit_log ORDER BY timestamp",
    ).fetchall()
    conn.close()

    assert len(rows) == THREADS, f"expected {THREADS} entries, found {len(rows)}"

    # Exactly one entry may start the chain, and no predecessor hash may be
    # claimed by two entries.
    seen: dict[str, str] = {}
    roots = 0
    for r in rows:
        prev = r["prev_hash"] or ""
        if prev == "":
            roots += 1
            continue
        assert prev not in seen, (
            f"chain fork: {r['entry_id']} and {seen[prev]} both chain onto "
            f"{prev[:16]}…"
        )
        seen[prev] = r["entry_id"]

    assert roots <= 1, f"{roots} entries claim to start the chain"

    verdict = watch.verify_chain(tenant_id="")
    assert verdict["verified"] is True, (
        f"the audit chain does not verify after concurrent appends: {verdict}"
    )


def test_the_chain_covers_everything_it_was_given(db) -> None:
    """A chain is only evidence if nothing fell out of it. Every logged
    action must be reachable by walking from the head."""
    THREADS = 8

    gate = Gate(db_path=db)
    watch = Watch(db_path=db)
    session = gate.create_session("walker", scopes=["read"], ttl=3600)

    run_together(
        lambda i: watch.log_action(session, tool="walker", action=f"a{i}"),
        THREADS,
    )

    conn = get_db(db)
    rows = conn.execute("SELECT entry_hash, prev_hash FROM audit_log").fetchall()
    conn.close()

    by_prev = {r["prev_hash"]: r["entry_hash"] for r in rows}
    # Walk the chain from its root and count what we reach.
    reached, cursor, guard = 0, "", 0
    while cursor in by_prev and guard <= len(rows) + 1:
        cursor = by_prev[cursor]
        reached += 1
        guard += 1

    assert reached == len(rows), (
        f"walking the chain reaches {reached} of {len(rows)} entries — the "
        f"rest are on a branch, not in the chain"
    )


def test_sequence_numbers_are_contiguous_under_concurrency(db) -> None:
    """Proves the *retry* works, not merely that the index exists.

    The chain test above passes if appends are serialized or if they collide
    and give up. This one checks the numbers actually handed out: 1..N with
    no gaps and no repeats. A gap would mean an append lost its race and
    vanished; a repeat is what the index forbids.
    """
    THREADS = 10

    gate = Gate(db_path=db)
    watch = Watch(db_path=db)
    session = gate.create_session("seq-racer", scopes=["read"], ttl=3600)

    run_together(
        lambda i: watch.log_action(session, tool="t", action=f"s{i}"), THREADS,
    )

    conn = get_db(db)
    seqs = [r["seq"] for r in conn.execute(
        "SELECT seq FROM audit_log ORDER BY seq").fetchall()]
    conn.close()

    assert seqs == list(range(1, THREADS + 1)), (
        f"expected sequence 1..{THREADS}, got {seqs} — an append either lost "
        f"its race without retrying, or wrote an out-of-order number"
    )


def test_the_unique_index_actually_exists(db) -> None:
    """The guard itself. Without it the retry loop above is dead code that
    never fires, and the chain forks exactly as before — which is what
    happened when the migration returned early on an empty table."""
    conn = get_db(db)
    rows = conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' "
        "AND tbl_name = 'audit_log'"
    ).fetchall()
    conn.close()

    ddl = " ".join((r["sql"] or "") for r in rows)
    assert "idx_audit_seq" in ddl, (
        f"no unique index on audit_log(tenant_id, seq); indexes present: "
        f"{[r['name'] for r in rows]}"
    )
    assert "UNIQUE" in ddl.upper(), f"idx_audit_seq is not UNIQUE: {ddl}"


def test_a_duplicate_sequence_number_is_refused(db) -> None:
    """End-to-end proof that a second row cannot claim a taken sequence."""
    gate = Gate(db_path=db)
    watch = Watch(db_path=db)
    session = gate.create_session("dup", scopes=["read"], ttl=3600)
    watch.log_action(session, tool="t", action="first")

    conn = get_db(db)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO audit_log (entry_id, tenant_id, session_id, agent_id, "
                "action, tool, details, cost_usd, timestamp, flagged, flag_reason, "
                "prev_hash, entry_hash, seq) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', '', ?, 1)",
                ("collide", "", "s", "a", "act", "t", "{}", 0.0, 0.0, "h"),
            )
    finally:
        conn.rollback()
        conn.close()


# ── SQLite write contention ──────────────────────────────────────────

def test_concurrent_writes_do_not_fail_with_database_locked(db) -> None:
    """Concurrent writers must not surface a raw sqlite3 error to a caller.

    A governance layer that returns Internal Server Error under load is
    worse than one that queues: the agent's retry is indistinguishable from
    a first attempt, so the action happens twice.
    """
    gate = Gate(db_path=db)
    watch = Watch(db_path=db)
    session = gate.create_session("contention", scopes=["read"], ttl=3600)

    results = run_together(
        lambda i: watch.log_action(session, tool="t", action=f"c{i}"), 16,
    )
    assert all(r is not None for r in results)
