"""
Tests for haldir_watch.watch — AuditEntry hash chain + Watch operations.

The audit trail is the security-critical output of Haldir: auditors rely on
the hash chain to prove entries haven't been tampered with post-hoc.

Covers:
  - compute_hash determinism (same inputs → same SHA-256 digest)
  - Hash chain integrity (tampering any field breaks the chain)
  - prev_hash → entry_hash linkage across a sequence of entries
  - Timestamp normalization (sub-second precision doesn't leak into the hash)
  - Cost normalization (2-decimal rounding; avoids float drift)
  - Flagged-state participation in the hash

Run: python -m pytest tests/test_watch.py -v
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_watch import Watch
from haldir_watch.watch import AuditEntry


# ── Helpers ──────────────────────────────────────────────────────────────

def _make_entry(**overrides) -> AuditEntry:
    defaults = dict(
        entry_id="aud_test",
        session_id="ses_1",
        agent_id="agent-1",
        action="execute",
        tool="stripe",
        details={"amount": 10},
        cost_usd=1.50,
        timestamp=1700000000.123,  # fixed for determinism
        flagged=False,
        flag_reason="",
        tenant_id="t",
        prev_hash="",
    )
    defaults.update(overrides)
    return AuditEntry(**defaults)


# ── compute_hash: determinism + field sensitivity ───────────────────────

def test_compute_hash_is_deterministic() -> None:
    e1 = _make_entry()
    e2 = _make_entry()
    assert e1.compute_hash() == e2.compute_hash()


def test_compute_hash_is_sha256_hex() -> None:
    h = _make_entry().compute_hash()
    assert len(h) == 64
    # Valid hex string
    int(h, 16)


def test_changing_any_field_changes_the_hash() -> None:
    """Any tampered field produces a different hash — core tamper-evidence property."""
    base = _make_entry()
    base_h = base.compute_hash()

    # Every field that participates in the hash: changing it breaks the chain
    assert _make_entry(entry_id="aud_other").compute_hash() != base_h
    assert _make_entry(session_id="ses_other").compute_hash() != base_h
    assert _make_entry(agent_id="other-agent").compute_hash() != base_h
    assert _make_entry(action="delete").compute_hash() != base_h
    assert _make_entry(tool="other-tool").compute_hash() != base_h
    assert _make_entry(details={"amount": 20}).compute_hash() != base_h
    assert _make_entry(cost_usd=2.00).compute_hash() != base_h
    assert _make_entry(flagged=True).compute_hash() != base_h
    assert _make_entry(prev_hash="a" * 64).compute_hash() != base_h


# ── Timestamp normalization ──────────────────────────────────────────────

def test_subsecond_timestamp_jitter_does_not_affect_hash() -> None:
    """
    Postgres REAL column loses sub-second precision vs. Python float. The hash
    uses int(timestamp) so Postgres round-tripping doesn't break the chain.
    """
    e1 = _make_entry(timestamp=1700000000.1)
    e2 = _make_entry(timestamp=1700000000.9)  # same whole second
    assert e1.compute_hash() == e2.compute_hash()


def test_different_whole_second_changes_hash() -> None:
    e1 = _make_entry(timestamp=1700000000.0)
    e2 = _make_entry(timestamp=1700000001.0)
    assert e1.compute_hash() != e2.compute_hash()


# ── Cost normalization ───────────────────────────────────────────────────

def test_cost_is_rounded_to_two_decimals_in_hash() -> None:
    """Cost is formatted as '.2f' in the hash, so float drift doesn't break chains."""
    e1 = _make_entry(cost_usd=1.50)
    e2 = _make_entry(cost_usd=1.504)  # same when rounded to 2 decimals
    assert e1.compute_hash() == e2.compute_hash()


def test_different_cost_changes_hash() -> None:
    e1 = _make_entry(cost_usd=1.00)
    e2 = _make_entry(cost_usd=2.00)
    assert e1.compute_hash() != e2.compute_hash()


# ── Hash chain integrity ─────────────────────────────────────────────────

def test_prev_hash_linkage_forms_a_chain() -> None:
    """Each entry's prev_hash equals the previous entry's entry_hash."""
    entries = [
        _make_entry(entry_id="aud_1", timestamp=1700000000.0),
        _make_entry(entry_id="aud_2", timestamp=1700000001.0),
        _make_entry(entry_id="aud_3", timestamp=1700000002.0),
    ]

    # Link them
    chain: list[AuditEntry] = []
    prev = ""
    for e in entries:
        e.prev_hash = prev
        e.entry_hash = e.compute_hash()
        chain.append(e)
        prev = e.entry_hash

    # Verify linkage
    assert chain[0].prev_hash == ""
    assert chain[1].prev_hash == chain[0].entry_hash
    assert chain[2].prev_hash == chain[1].entry_hash


def test_tampering_a_middle_entry_breaks_the_chain() -> None:
    """If someone edits entry N, the hash of entry N (and everything after) becomes invalid."""
    # Build a three-entry chain
    entries = [_make_entry(entry_id=f"aud_{i}", timestamp=1700000000.0 + i) for i in range(3)]
    prev = ""
    for e in entries:
        e.prev_hash = prev
        e.entry_hash = e.compute_hash()
        prev = e.entry_hash

    # Stored hashes (what would be in DB)
    stored_hashes = [e.entry_hash for e in entries]

    # Attacker tampers entry 1 (changes cost from 1.50 to 0.00)
    entries[1].cost_usd = 0.00

    # Recomputed hash now differs from the stored one
    assert entries[1].compute_hash() != stored_hashes[1]

    # Entry 2's prev_hash still points at the OLD hash, but re-verification of
    # the chain catches the tamper because entry 1's new hash ≠ entry 2's prev_hash
    new_hash_1 = entries[1].compute_hash()
    assert new_hash_1 != entries[2].prev_hash


# ── Watch.log_action live-chain (integration, uses temp SQLite DB) ──────

@pytest.fixture
def temp_db(tmp_path):
    """Ephemeral SQLite DB for a single test."""
    from haldir_db import init_db

    db_path = str(tmp_path / "haldir_test.db")
    init_db(db_path)
    return db_path


class _StubSession:
    """Just enough of a Session interface for Watch.log_action."""
    def __init__(self, session_id="ses_1", agent_id="agent-1"):
        self.session_id = session_id
        self.agent_id = agent_id


def test_watch_log_action_chains_entries(temp_db) -> None:
    """End-to-end: Watch persists entries and each prev_hash points at the previous entry."""
    watch = Watch(db_path=temp_db)
    session = _StubSession()

    e1 = watch.log_action(session, tool="stripe", action="charge", cost_usd=1.0, tenant_id="t")
    e2 = watch.log_action(session, tool="stripe", action="refund", cost_usd=0.5, tenant_id="t")
    e3 = watch.log_action(session, tool="github", action="commit", tenant_id="t")

    assert e1.prev_hash == ""
    assert e2.prev_hash == e1.entry_hash
    assert e3.prev_hash == e2.entry_hash

    # And each entry's own hash matches what compute_hash produces from its fields
    for e in (e1, e2, e3):
        assert e.entry_hash == e.compute_hash()


def test_audit_trail_query_returns_entries_in_reverse_chronological_order(temp_db) -> None:
    watch = Watch(db_path=temp_db)
    session = _StubSession()

    for i in range(3):
        watch.log_action(session, tool=f"tool-{i}", action="call", tenant_id="t")

    trail = watch.get_audit_trail(tenant_id="t", limit=10)
    assert len(trail) == 3
    # Newest first
    assert trail[0].tool == "tool-2"
    assert trail[2].tool == "tool-0"


def test_get_spend_aggregates_cost_across_entries(temp_db) -> None:
    watch = Watch(db_path=temp_db)
    session = _StubSession()

    watch.log_action(session, tool="stripe", action="charge", cost_usd=1.00, tenant_id="t")
    watch.log_action(session, tool="stripe", action="charge", cost_usd=2.50, tenant_id="t")
    watch.log_action(session, tool="github", action="api_call", cost_usd=0.10, tenant_id="t")

    spend = watch.get_spend(tenant_id="t")
    assert spend["action_count"] == 3
    assert spend["total_usd"] == pytest.approx(3.60, abs=0.001)
    assert spend["by_tool"]["stripe"] == pytest.approx(3.50, abs=0.001)
    assert spend["by_tool"]["github"] == pytest.approx(0.10, abs=0.001)
