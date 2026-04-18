"""
Property-based tests for the audit hash chain using Hypothesis.

The hash chain is the load-bearing tamper-evidence guarantee. These
properties prove invariants over the entire input space rather than the
handful of cases an engineer can hand-write.

Run: python -m pytest tests/test_watch_properties.py -v
"""

from __future__ import annotations

import json
import os
import sys

from hypothesis import HealthCheck, given, settings, strategies as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_watch.watch import AuditEntry


_SETTINGS = settings(max_examples=200, deadline=None,
                     suppress_health_check=[HealthCheck.too_slow])


# ── Strategies ───────────────────────────────────────────────────────────

# Field-level strategies that match the AuditEntry contract.
ascii_text = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126),
    min_size=1, max_size=64,
)
costs = st.floats(min_value=0.0, max_value=10_000.0, allow_nan=False, allow_infinity=False)
timestamps = st.floats(min_value=1_000_000_000.0, max_value=4_000_000_000.0,
                       allow_nan=False, allow_infinity=False)

# JSON-serialisable details dicts. Nested dicts are deliberately included
# because anomaly rules and integrators commonly attach structured metadata.
json_scalars = st.one_of(
    st.text(min_size=0, max_size=20),
    st.integers(min_value=-10_000, max_value=10_000),
    st.floats(min_value=-1000.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
    st.booleans(),
    st.none(),
)
details = st.dictionaries(
    keys=st.text(min_size=1, max_size=12),
    values=json_scalars,
    max_size=8,
)


def _entry(**overrides) -> AuditEntry:
    defaults = dict(
        entry_id="aud_x",
        session_id="ses_x",
        agent_id="agent",
        action="execute",
        tool="stripe",
        details={},
        cost_usd=1.0,
        timestamp=1700000000.0,
        flagged=False,
        flag_reason="",
        tenant_id="t",
        prev_hash="",
    )
    defaults.update(overrides)
    return AuditEntry(**defaults)


# ── Properties ───────────────────────────────────────────────────────────

@_SETTINGS
@given(
    entry_id=ascii_text, session_id=ascii_text, agent_id=ascii_text,
    action=ascii_text, tool=ascii_text, details=details,
    cost=costs, ts=timestamps, flagged=st.booleans(), prev=ascii_text,
)
def test_compute_hash_is_pure(entry_id, session_id, agent_id, action,
                              tool, details, cost, ts, flagged, prev) -> None:
    """For ANY field combination, compute_hash is deterministic and pure
    (same inputs always produce the same output)."""
    e1 = _entry(entry_id=entry_id, session_id=session_id, agent_id=agent_id,
                action=action, tool=tool, details=details, cost_usd=cost,
                timestamp=ts, flagged=flagged, prev_hash=prev)
    e2 = _entry(entry_id=entry_id, session_id=session_id, agent_id=agent_id,
                action=action, tool=tool, details=details, cost_usd=cost,
                timestamp=ts, flagged=flagged, prev_hash=prev)
    assert e1.compute_hash() == e2.compute_hash()


@_SETTINGS
@given(cost=costs, jitter=st.floats(min_value=0.0, max_value=0.999,
                                     allow_nan=False, allow_infinity=False))
def test_subsecond_jitter_does_not_change_hash(cost, jitter) -> None:
    """Two entries with timestamps that differ only in their sub-second part
    must produce the same hash (because the hash uses int(timestamp))."""
    base_ts = 1700000000.0
    e1 = _entry(cost_usd=cost, timestamp=base_ts)
    e2 = _entry(cost_usd=cost, timestamp=base_ts + jitter)
    assert e1.compute_hash() == e2.compute_hash()


@_SETTINGS
@given(cost_a=costs, cost_b=costs)
def test_costs_within_one_cent_have_equal_hashes(cost_a: float, cost_b: float) -> None:
    """Two costs that round to the same `.2f` formatted string must hash
    identically (the format string is `{cost_usd:.2f}`)."""
    if f"{cost_a:.2f}" != f"{cost_b:.2f}":
        return  # not the same when rounded — skip
    e1 = _entry(cost_usd=cost_a)
    e2 = _entry(cost_usd=cost_b)
    assert e1.compute_hash() == e2.compute_hash()


@_SETTINGS
@given(
    entries=st.lists(
        st.tuples(ascii_text, costs, timestamps, details),
        min_size=1, max_size=12,
    ),
)
def test_chain_of_any_length_is_self_consistent(entries) -> None:
    """For any sequence of entries, linking via prev_hash → entry_hash
    produces a chain where each entry's compute_hash matches its stored
    entry_hash."""
    chain: list[AuditEntry] = []
    prev = ""
    for i, (entry_id, cost, ts, dets) in enumerate(entries):
        e = _entry(
            entry_id=entry_id + str(i),
            cost_usd=cost,
            timestamp=ts,
            details=dets,
            prev_hash=prev,
        )
        e.entry_hash = e.compute_hash()
        chain.append(e)
        prev = e.entry_hash

    # Re-verify the chain end-to-end
    expected_prev = ""
    for e in chain:
        assert e.prev_hash == expected_prev
        assert e.entry_hash == e.compute_hash()
        expected_prev = e.entry_hash


@_SETTINGS
@given(
    entries=st.lists(
        st.tuples(ascii_text, costs, timestamps),
        min_size=2, max_size=10,
    ),
    tamper_idx=st.integers(min_value=0, max_value=20),
    new_cost=costs,
)
def test_tampering_any_middle_entry_breaks_the_chain(entries, tamper_idx, new_cost) -> None:
    """Build a chain. Mutate entry K's cost. Then for any K, the recomputed
    hash of K differs from its stored hash, AND from entry K+1's prev_hash."""
    if tamper_idx >= len(entries):
        return  # bounds; let Hypothesis find new examples

    # Build the chain
    chain: list[AuditEntry] = []
    prev = ""
    for i, (entry_id, cost, ts) in enumerate(entries):
        e = _entry(entry_id=entry_id + str(i), cost_usd=cost, timestamp=ts, prev_hash=prev)
        e.entry_hash = e.compute_hash()
        chain.append(e)
        prev = e.entry_hash

    target = chain[tamper_idx]
    if f"{target.cost_usd:.2f}" == f"{new_cost:.2f}":
        return  # tampering wouldn't actually change the hash

    stored_hash = target.entry_hash
    target.cost_usd = new_cost
    new_hash = target.compute_hash()

    # The recomputed hash must differ from what was stored
    assert new_hash != stored_hash

    # And if there's a successor, its stored prev_hash no longer matches
    # the tampered entry's recomputed hash (the chain is broken).
    if tamper_idx + 1 < len(chain):
        successor = chain[tamper_idx + 1]
        assert successor.prev_hash != new_hash


@_SETTINGS
@given(details=details)
def test_details_field_canonicalisation_is_stable(details) -> None:
    """Details dicts with the same content but different key insertion orders
    must hash identically (because compute_hash uses json.dumps with sort_keys=True)."""
    # Build a "shuffled" version of the same dict by re-inserting keys reversed
    reversed_dict = dict(reversed(list(details.items())))

    e1 = _entry(details=details)
    e2 = _entry(details=reversed_dict)
    assert e1.compute_hash() == e2.compute_hash()


@_SETTINGS
@given(prev_a=ascii_text, prev_b=ascii_text)
def test_different_prev_hash_changes_entry_hash(prev_a: str, prev_b: str) -> None:
    """The chain links to the past via prev_hash; if it's different, this
    entry's hash must differ. (Otherwise the chain wouldn't actually chain.)"""
    if prev_a == prev_b:
        return
    e1 = _entry(prev_hash=prev_a)
    e2 = _entry(prev_hash=prev_b)
    assert e1.compute_hash() != e2.compute_hash()
