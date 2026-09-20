"""
Cost is recorded at the precision the product actually spends at.

The bug this pins: _build_entry did `round(cost_usd, 2)`. Cents. But Haldir
settles x402 micropayments, and the payment path deliberately scales to 6
decimals — so the rounding downstream of it discarded the precision that path
existed to preserve. Measured before the fix, five ordinary micro-settlements
recorded as:

    intended   recorded
    0.0021     0.0000
    0.0049     0.0000
    0.0010     0.0000
    0.0075     0.0100     <- over-reports
    0.2500     0.2500

Three of the five recorded as exactly zero, and the trail's own total said
$0.2600 against $0.2655 actually spent. For an audit product that is worse
than recording nothing, because it looks authoritative.

Two things have to be true at once, and the second is what makes this
changeable at all:

  1. New entries record cost at 6 decimals, and the trail totals agree.

  2. Entries written under the older rules still verify. The hash covers the
     cost field, so changing its precision changes the hash of every entry
     written that way. If version 1 and version 2 entries were re-hashed
     under the new rule they would all report as tampered — and a log that
     cries tampering on its own format change reads as a breach, not a
     version bump. That is what HASH_VERSION_* is for, and these tests are
     the reason it has to keep working.

Run: python -m pytest tests/test_cost_precision.py -v
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
from haldir_watch import (  # noqa: E402
    HASH_VERSION_CURRENT,
    HASH_VERSION_FLAG_REASON,
    HASH_VERSION_LEGACY,
    Watch,
)


@pytest.fixture
def db(tmp_path):
    import haldir_migrate
    from haldir_db import init_db
    path = str(tmp_path / "cost.db")
    init_db(path)
    haldir_migrate.apply_pending(path)
    return path


# ── The old formulas, reproduced exactly ─────────────────────────────
#
# Written out rather than imported, because the point is to prove that an
# entry hashed by the *older* rule still verifies. Calling the current
# implementation would test nothing.

def _v1_payload(entry) -> str:
    return (
        f"{entry.entry_id}|{entry.session_id}|{entry.agent_id}|{entry.action}|"
        f"{entry.tool}|{json.dumps(entry.details, sort_keys=True)}|"
        f"{entry.cost_usd:.2f}|{int(entry.timestamp)}|"
        f"{1 if entry.flagged else 0}|{entry.prev_hash}"
    )


def _v2_payload(entry) -> str:
    return _v1_payload(entry) + f"|{entry.flag_reason}"


def _insert(db: str, tenant: str, *, cost: float, version: int,
            flag_reason: str = "", action: str = "tool_call"):
    """Write one entry hashed under the rule its version used."""
    from haldir_db import get_db
    from haldir_watch import AuditEntry

    conn = get_db(db)
    last = conn.execute(
        "SELECT entry_hash, seq FROM audit_log WHERE tenant_id = ? "
        "ORDER BY seq DESC LIMIT 1", (tenant,)
    ).fetchone()
    prev = last["entry_hash"] if last else ""
    # Verification walks the chain ORDER BY seq ASC, so a hand-built chain has
    # to number its entries the same way. Leaving seq at 0 for every row makes
    # the walk fall back to timestamp ordering, which is not the order these
    # were linked in — the second entry then reports the first as modified.
    next_seq = (int(last["seq"]) + 1) if last else 1

    entry = AuditEntry(
        entry_id=f"e_{version}_{cost}_{time.time()}",
        session_id="s", agent_id="a", action=action,
        tool="t", details={}, cost_usd=cost,
        timestamp=time.time(), prev_hash=prev,
        flagged=bool(flag_reason), flag_reason=flag_reason,
        hash_version=version,
    )
    if version == HASH_VERSION_LEGACY:
        payload = _v1_payload(entry)
    elif version == HASH_VERSION_FLAG_REASON:
        payload = _v2_payload(entry)
    else:
        raise AssertionError("this helper only reproduces the old rules")
    entry.entry_hash = hashlib.sha256(payload.encode()).hexdigest()

    conn.execute(
        "INSERT INTO audit_log (entry_id, tenant_id, session_id, agent_id, action, "
        "tool, details, cost_usd, timestamp, flagged, flag_reason, prev_hash, "
        "entry_hash, seq, hash_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (entry.entry_id, tenant, entry.session_id, entry.agent_id, entry.action,
         entry.tool, "{}", entry.cost_usd, entry.timestamp, int(entry.flagged),
         entry.flag_reason, entry.prev_hash, entry.entry_hash, next_seq, version),
    )
    conn.commit()
    conn.close()
    return entry


# ── New entries keep the precision ───────────────────────────────────

MICRO = [0.0021, 0.0049, 0.0010, 0.0075, 0.2500]


def test_micropayments_are_recorded_exactly(db) -> None:
    """The whole point. Every one of these recorded as $0.00 or $0.01 before."""
    w = Watch(db_path=db)
    from haldir_gate import Gate
    g = Gate(db_path=db)
    sess = g.create_session(agent_id="payer", tenant_id="t1", scopes=["pay"])

    for amount in MICRO:
        w.log_system_action(actor="hld_x402", action="x402.settle", tool="x402",
                            cost_usd=round(amount, 6), tenant_id="t1")

    from haldir_db import get_db
    conn = get_db(db)
    rows = conn.execute(
        "SELECT cost_usd FROM audit_log WHERE tenant_id = ? ORDER BY timestamp, entry_id",
        ("t1",),
    ).fetchall()
    conn.close()

    recorded = [float(r["cost_usd"]) for r in rows]
    assert len(recorded) == len(MICRO)
    for intended, got in zip(MICRO, recorded):
        assert abs(intended - got) < 1e-9, (
            f"a payment of ${intended:.4f} was recorded as ${got:.4f}"
        )


def test_the_trail_total_matches_what_was_spent(db) -> None:
    """The number an operator reconciles against. It said $0.2600 for
    $0.2655 of payments, which is a discrepancy nobody would find by eye."""
    w = Watch(db_path=db)
    for amount in MICRO:
        w.log_system_action(actor="hld_x402", action="x402.settle", tool="x402",
                            cost_usd=round(amount, 6), tenant_id="t1")

    from haldir_db import get_db
    conn = get_db(db)
    total = conn.execute(
        "SELECT SUM(cost_usd) FROM audit_log WHERE tenant_id = ?", ("t1",)
    ).fetchone()[0]
    conn.close()

    assert abs(float(total) - sum(MICRO)) < 1e-9, (
        f"trail totals ${float(total):.4f} against ${sum(MICRO):.4f} spent"
    )


def test_new_entries_are_written_at_the_current_version(db) -> None:
    w = Watch(db_path=db)
    w.log_system_action(actor="hld_x402", action="x402.settle", tool="x402",
                        cost_usd=0.0021, tenant_id="t1")

    from haldir_db import get_db
    conn = get_db(db)
    row = conn.execute(
        "SELECT hash_version FROM audit_log WHERE tenant_id = ?", ("t1",)
    ).fetchone()
    conn.close()
    assert int(row["hash_version"]) == HASH_VERSION_CURRENT


# ── Old entries keep verifying ───────────────────────────────────────

def test_v1_entries_still_verify(db) -> None:
    """Entries written before flag_reason was covered, at 2dp cost.

    If the version gate were dropped, every one of these would report as
    tampered — a false breach report on a customer's own history.
    """
    for amount in (0.0021, 1.25, 0.0075):
        _insert(db, "t1", cost=amount, version=HASH_VERSION_LEGACY)

    result = Watch(db_path=db).verify_chain(tenant_id="t1")
    assert result["verified"] is True, result
    assert result["entries_checked"] == 3


def test_v2_entries_still_verify(db) -> None:
    """Entries written with flag_reason covered, still at 2dp cost.

    These are the ones a naive version bump breaks: the flag_reason field is
    gated on its own constant precisely so that raising the cost precision
    does not silently stop appending it here.
    """
    _insert(db, "t1", cost=0.0021, version=HASH_VERSION_FLAG_REASON,
            flag_reason="over-threshold")
    _insert(db, "t1", cost=1.25, version=HASH_VERSION_FLAG_REASON)

    result = Watch(db_path=db).verify_chain(tenant_id="t1")
    assert result["verified"] is True, result
    assert result["entries_checked"] == 2


def test_v1_and_v2_and_v3_can_share_one_chain(db) -> None:
    """A real deployment upgrades in place: the log already holds v1 and v2
    entries when the first v3 entry arrives, and all of them have to verify
    together."""
    _insert(db, "t1", cost=0.0021, version=HASH_VERSION_LEGACY)
    _insert(db, "t1", cost=0.0049, version=HASH_VERSION_FLAG_REASON)
    Watch(db_path=db).log_system_action(
        actor="hld_x402", action="x402.settle", tool="x402",
        cost_usd=0.0010, tenant_id="t1",
    )

    result = Watch(db_path=db).verify_chain(tenant_id="t1")
    assert result["verified"] is True, result
    assert result["entries_checked"] == 3


# ── And tampering is still caught ────────────────────────────────────

def test_a_restated_cost_is_still_detected(db) -> None:
    """Raising the recorded precision must not cost the chain its teeth.

    Cost sits inside the hash, so a row whose cost was edited after the fact
    has to fail — including a change too small to see at two decimals, which
    is exactly the kind of edit the old precision could not have caught.
    """
    w = Watch(db_path=db)
    w.log_system_action(actor="hld_x402", action="x402.settle", tool="x402",
                        cost_usd=0.0021, tenant_id="t1")
    assert Watch(db_path=db).verify_chain(tenant_id="t1")["verified"] is True

    from haldir_db import get_db
    conn = get_db(db)
    conn.execute("UPDATE audit_log SET cost_usd = 0.0022 WHERE tenant_id = ?",
                 ("t1",))
    conn.commit()
    conn.close()

    result = Watch(db_path=db).verify_chain(tenant_id="t1")
    assert result["verified"] is False, "an edited cost verified"
    assert "modified" in result["error"].lower()


def test_an_old_entry_with_an_edited_cost_is_still_detected(db) -> None:
    """The same has to hold for entries written under the old rule: versioning
    changes which formula applies, not whether the entry is checked."""
    _insert(db, "t1", cost=1.25, version=HASH_VERSION_LEGACY)
    assert Watch(db_path=db).verify_chain(tenant_id="t1")["verified"] is True

    from haldir_db import get_db
    conn = get_db(db)
    conn.execute("UPDATE audit_log SET cost_usd = 9.99 WHERE tenant_id = ?",
                 ("t1",))
    conn.commit()
    conn.close()

    assert Watch(db_path=db).verify_chain(tenant_id="t1")["verified"] is False
