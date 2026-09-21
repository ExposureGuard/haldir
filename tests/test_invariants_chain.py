"""
The audit chain claim, asserted as a property rather than demonstrated by example.

Haldir's pitch is that the audit log *proves* it was not edited. That is a
claim about every possible edit, so testing it with a handful of hand-written
tamper cases tests almost nothing: it shows the cases an engineer thought of,
which are exactly the ones already handled.

These tests invert it. The central one walks every column of `audit_log`,
mutates each in turn, and requires `verify_chain` to notice — reporting a
crash as a failure, because raising is not detecting.

Found by writing this file:

  * corrupting `details` made verify_chain raise JSONDecodeError instead of
    reporting tampering — denial of verification, on the one function whose
    job is to survive tampering;
  * `flag_reason` was not covered by the hash at all, so the stated reason an
    action was flagged could be rewritten freely.

Run: python -m pytest tests/test_invariants_chain.py -v
"""

from __future__ import annotations

import os
import sqlite3
import sys
import threading
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_db import init_db, get_db  # noqa: E402
from haldir_gate import Gate  # noqa: E402
from haldir_watch import Watch  # noqa: E402


# Every column a tamperer could reach. Kept in step with the schema on
# purpose — if a column is added and not covered here, the omission is the
# bug, so this list is asserted against the live table below.
MUTABLE_FIELDS = [
    "entry_id", "tenant_id", "session_id", "agent_id", "action", "tool",
    "details", "cost_usd", "timestamp", "flagged", "flag_reason",
    "prev_hash", "entry_hash", "seq",
]

# Fields the chain deliberately does not hash, with the reason. Each is
# covered by its own test below proving the *meaningful* tamper is still
# caught by linkage or by ordering.
UNHASHED = {
    "seq": "ordering is validated by the prev_hash walk, not by the hash",
    "hash_version": "records which hash rule was used; see test below",
}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "chain.db")
    init_db(path)
    return path


# A tenant per test.
#
# On SQLite `path` above is a fresh temp file, so tests are isolated by
# construction. On Postgres DATABASE_URL wins and the path is ignored, so
# every test in the run shares one database — and these tests then write into
# the default tenant "" alongside everything else that ran before them.
# `verify_chain` walks that whole tenant, so it sees rows this test never
# created and reports a broken chain that is nobody's fault.
_TENANT: dict[str, str] = {"name": ""}


@pytest.fixture(autouse=True)
def _own_tenant():
    """Give each test its own tenant, so a shared database is still isolated."""
    _TENANT["name"] = f"chain-{uuid.uuid4().hex[:10]}"
    yield _TENANT["name"]


def tenant() -> str:
    return _TENANT["name"]


def fresh(db, agent="chain-agent", n=1):
    """A gate, a watch, and a session with `n` entries logged."""
    gate, watch = Gate(db_path=db), Watch(db_path=db)
    session = gate.create_session(agent, scopes=["read"], ttl=3600,
                                  tenant_id=tenant())
    entries = [watch.log_action(session, tool="t", action=f"a{i}",
                                   tenant_id=tenant()) for i in range(n)]
    return gate, watch, session, entries


def mutate(db, entry_id, field, value):
    """Write `value` into one column of one row.

    Closes in a `finally`. A statement the backend rejects leaves its implicit
    transaction open holding the write lock, so skipping the close on the
    exception path makes the *next* connection block until SQLite's busy
    timeout expires — which turned the fuzz test below from 4 seconds into 40.
    """
    conn = get_db(db)
    try:
        conn.execute(f"UPDATE audit_log SET {field} = ? WHERE entry_id = ?",  # noqa: S608 — field is from MUTABLE_FIELDS
                     (value, entry_id))
        conn.commit()
    finally:
        conn.close()


def read(db, entry_id):
    conn = get_db(db)
    row = conn.execute("SELECT * FROM audit_log WHERE entry_id = ?", (entry_id,)).fetchone()
    conn.close()
    return row


# ── The schema coverage guard ────────────────────────────────────────

def test_every_column_is_either_tested_or_excused(db) -> None:
    """The field list above has to track the schema.

    A new column that is silently unprotected is precisely the defect this
    file exists to catch, so the list is checked against the live table
    rather than trusted.
    """
    # PRAGMA is SQLite-only and Postgres rejects it outright ("syntax error
    # at or near PRAGMA"). information_schema is the portable way to ask.
    conn = get_db(db)
    try:
        columns = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    except Exception:
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'audit_log'"
        ).fetchall()
        columns = {r[0] for r in rows}
    conn.close()

    untested = columns - set(MUTABLE_FIELDS) - set(UNHASHED)
    assert not untested, (
        f"audit_log has columns no tamper test covers: {sorted(untested)}. "
        f"Add them to MUTABLE_FIELDS, or to UNHASHED with a reason."
    )
    stale = set(MUTABLE_FIELDS) - columns
    assert not stale, f"MUTABLE_FIELDS names columns that do not exist: {sorted(stale)}"


# ── The central claim ────────────────────────────────────────────────

@pytest.mark.parametrize("field", MUTABLE_FIELDS)
def test_modifying_any_field_is_detected(db, field: str) -> None:
    """Change one column of one entry and verification must fail.

    A crash counts as a failure. `verify_chain` reporting "tampered" is the
    product; `verify_chain` raising means an attacker who corrupts a single
    field can make the endpoint error instead of confessing, which is worse
    than a wrong answer because it looks like an outage.

    `seq` is excluded from the hash on purpose — see
    test_reordering_is_detected_by_linkage for the tamper that matters.
    """
    if field in UNHASHED:
        pytest.skip(f"{field}: {UNHASHED[field]}")

    _, watch, _, entries = fresh(db, n=3)
    entry = entries[1]
    original = read(db, entry.entry_id)[field]

    if isinstance(original, (int, float)) and not isinstance(original, bool):
        tampered = original + 1
    elif field == "details":
        tampered = "{not json"
    else:
        tampered = "TAMPERED"

    mutate(db, entry.entry_id, field, tampered)

    try:
        verdict = watch.verify_chain(tenant_id=tenant())
    except Exception as e:  # noqa: BLE001 — a raise *is* the defect
        pytest.fail(
            f"verify_chain raised {type(e).__name__} instead of reporting "
            f"tampering when {field!r} was modified: {e}"
        )

    assert verdict.get("verified") is False, (
        f"verify_chain reported the log intact after {field!r} was changed "
        f"from {original!r} to {tampered!r} — that field is not protected"
    )


def test_the_hash_covers_every_field_it_claims_to(db) -> None:
    """The same claim, checked against the hash directly rather than through
    the whole verify path, so a failure says *which* field is uncovered."""
    from haldir_watch.watch import AuditEntry

    base = AuditEntry(entry_id="e", session_id="s", agent_id="a", action="act",
                      tool="t", details={"k": "v"}, cost_usd=1.0,
                      timestamp=1_700_000_000.0, flagged=True,
                      flag_reason="why", prev_hash="p")

    uncovered = []
    for field in ("entry_id", "session_id", "agent_id", "action", "tool",
                  "details", "cost_usd", "timestamp", "flagged",
                  "flag_reason", "prev_hash"):
        changed = AuditEntry(**{**base.__dict__, field: _different(getattr(base, field))})
        if changed.compute_hash() == base.compute_hash():
            uncovered.append(field)

    assert not uncovered, (
        f"these fields are not covered by compute_hash, so editing them in "
        f"the database leaves the entry verifying: {uncovered}"
    )


def _different(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 7
    if isinstance(value, dict):
        return {**value, "tampered": True}
    return str(value) + "-tampered"


# ── verify_chain must always answer ──────────────────────────────────

def test_verify_chain_never_raises_on_corrupt_data(db) -> None:
    """Fuzz the persisted row with values that are the right type for the
    column but nonsense for the code, and require a verdict every time.

    An auditor asking "is this log intact?" must get an answer, including
    when the log has been mangled into something the reader did not expect.
    """
    _, watch, _, entries = fresh(db, n=3)
    target = entries[1].entry_id

    hostile = {
        "details": ["", "null", "[1,2", "{}", '{"a": }', "\\x00", "not json"],
        "timestamp": [float("nan"), float("inf"), -1.0],
        "cost_usd": [float("nan"), -1.0],
        "flagged": [2, -1],
        # Not None: seq is NOT NULL in the schema, so a null there is not a
        # state an attacker can create, and the constraint rejecting it is
        # the database doing its job rather than a gap in verification.
        "seq": [-5, 999_999],
    }

    for field, values in hostile.items():
        for value in values:
            try:
                mutate(db, target, field, value)
            except sqlite3.Error as e:
                # The backend refused to store it — SQLite turns NaN into
                # NULL (rejected by NOT NULL) and overflows on infinity, so
                # neither is a state the database can be in. Postgres stores
                # both, which is why this file also runs in the Postgres job.
                print(f"  (backend refused {field}={value!r}: {type(e).__name__}: {e})")
                continue

            try:
                verdict = watch.verify_chain(tenant_id=tenant())
            except Exception as e:  # noqa: BLE001
                pytest.fail(
                    f"verify_chain raised {type(e).__name__} on "
                    f"{field}={value!r}: {e}"
                )
            assert isinstance(verdict, dict) and "verified" in verdict, (
                f"verify_chain returned {verdict!r} for {field}={value!r}"
            )


def test_verify_chain_returns_a_verdict_on_an_empty_log(db) -> None:
    _, watch, _, _ = fresh(db, n=0)
    verdict = watch.verify_chain(tenant_id=tenant())
    assert verdict["verified"] is True


# ── The tampers that are not field edits ─────────────────────────────

def test_deleting_an_entry_is_detected(db) -> None:
    """Removing a row from the middle breaks the linkage."""
    _, watch, _, entries = fresh(db, n=4)
    conn = get_db(db)
    conn.execute("DELETE FROM audit_log WHERE entry_id = ?", (entries[1].entry_id,))
    conn.commit()
    conn.close()

    assert watch.verify_chain(tenant_id=tenant())["verified"] is False


def test_inserting_a_fabricated_entry_is_detected(db) -> None:
    """An attacker who can write to the table can append a plausible row.
    Without the previous entry's hash they cannot make it link."""
    _, watch, _, _ = fresh(db, n=2)
    conn = get_db(db)
    conn.execute(
        "INSERT INTO audit_log (entry_id, tenant_id, session_id, agent_id, action, "
        "tool, details, cost_usd, timestamp, flagged, flag_reason, prev_hash, "
        "entry_hash, seq) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        # Into this test's own tenant, or verification would never look at it.
        ("forged", tenant(), "s", "a", "exfiltrate", "t", "{}", 0.0, 1.0, 0,
         "", "deadbeef", 99, 99),
    )
    conn.commit()
    conn.close()

    assert watch.verify_chain(tenant_id=tenant())["verified"] is False


def test_reordering_is_detected_by_linkage(db) -> None:
    """The tamper `seq` is not hashed to catch.

    `seq` is deliberately outside the hash, because hashing it would
    invalidate every entry written before the column existed. What protects
    ordering is the prev_hash walk: swap two entries' positions and the
    second one's predecessor no longer matches. This test is the reason that
    carve-out is acceptable rather than a hole.
    """
    _, watch, _, entries = fresh(db, n=3)
    conn = get_db(db)
    # Give the last entry a sequence number that sorts it first.
    conn.execute("UPDATE audit_log SET seq = 0 WHERE entry_id = ?", (entries[-1].entry_id,))
    conn.commit()
    conn.close()

    assert watch.verify_chain(tenant_id=tenant())["verified"] is False, (
        "moving an entry to the front of the chain was not detected — ordering "
        "is not actually protected by the linkage walk"
    )


def test_swapping_two_entries_payloads_is_detected(db) -> None:
    """Swap the bodies of two entries, leaving hashes in place. The AAD-free
    audit chain catches this because action is inside the hash."""
    _, watch, _, entries = fresh(db, n=3)
    a, b = entries[0], entries[2]
    conn = get_db(db)
    conn.execute("UPDATE audit_log SET action = ? WHERE entry_id = ?", (b.action, a.entry_id))
    conn.execute("UPDATE audit_log SET action = ? WHERE entry_id = ?", (a.action, b.entry_id))
    conn.commit()
    conn.close()

    assert watch.verify_chain(tenant_id=tenant())["verified"] is False


def test_an_untouched_log_verifies(db) -> None:
    """The other half: verification must not cry wolf. A detector that fires
    on an intact log is one people learn to ignore."""
    _, watch, _, _ = fresh(db, n=5)
    verdict = watch.verify_chain(tenant_id=tenant())
    assert verdict["verified"] is True
    assert verdict["entries_checked"] == 5


# ── Linearity under concurrency ──────────────────────────────────────

def test_the_chain_is_linear_after_concurrent_appends(db) -> None:
    """Whatever the interleaving, the result must be one chain.

    Restated here as a property of the *shape* — one root, no shared
    predecessor, everything reachable — rather than only as "verify_chain
    says ok", so a failure localises to the structure.
    """
    THREADS = 16
    gate, watch = Gate(db_path=db), Watch(db_path=db)
    session = gate.create_session("linear", scopes=["read"], ttl=3600,
                                  tenant_id=tenant())

    barrier = threading.Barrier(THREADS)

    def writer(i):
        barrier.wait(timeout=10)
        watch.log_action(session, tool="t", action=f"w{i}", tenant_id=tenant())

    threads = [threading.Thread(target=writer, args=(i,), daemon=True)
               for i in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    conn = get_db(db)
    # Scoped to this test's tenant. Without the filter this walks every
    # tenant's rows, which is invisible on SQLite (a fresh file per test)
    # and wrong on Postgres, where the database is shared.
    rows = conn.execute(
        "SELECT entry_id, entry_hash, prev_hash FROM audit_log "
        "WHERE tenant_id = ?", (tenant(),)).fetchall()
    conn.close()
    assert len(rows) == THREADS

    predecessors: dict[str, str] = {}
    roots = 0
    for r in rows:
        if not r["prev_hash"]:
            roots += 1
            continue
        assert r["prev_hash"] not in predecessors, (
            f"fork: {r['entry_id']} and {predecessors[r['prev_hash']]} both "
            f"chain onto {r['prev_hash'][:16]}…"
        )
        predecessors[r["prev_hash"]] = r["entry_id"]

    assert roots == 1, f"{roots} entries claim to start the chain, expected 1"

    by_prev = {r["prev_hash"]: r["entry_hash"] for r in rows}
    reached, cursor = 0, ""
    while cursor in by_prev and reached <= len(rows):
        cursor = by_prev[cursor]
        reached += 1
    assert reached == len(rows), f"only {reached} of {len(rows)} entries are in the chain"

    assert watch.verify_chain(tenant_id=tenant())["verified"] is True
