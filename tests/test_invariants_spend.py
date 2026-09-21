"""
The spend cap claim, asserted as a property.

"An agent cannot exceed its budget" is the promise a customer is buying when
they put an agent in front of a payment API. It is a claim about every
sequence of amounts under every interleaving, so an example test proving that
`authorize(30)` twice against a $50 cap refuses the second one proves almost
nothing — that is one ordering out of many, and the failure mode is a
*different* ordering.

Found by writing this file: ten simultaneous $20 authorizations against a
$100 cap all succeeded, because the budget check and the spend write were
separate statements and `Gate.record_spend` reloads the session per call.

Run: python -m pytest tests/test_invariants_spend.py -v
"""

from __future__ import annotations

import os
import sys
import threading

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_db import init_db, get_db  # noqa: E402
from haldir_gate import Gate  # noqa: E402
from haldir_vault import Vault  # noqa: E402


_SETTINGS = settings(
    max_examples=60, deadline=None,
    suppress_health_check=[
        HealthCheck.too_slow,
        # Deliberate: the `db` fixture is function-scoped but initialises the
        # schema once for the whole test, and every example then runs against
        # its own session in that one database. Hypothesis objects because it
        # cannot know the fixture's state does not leak between examples —
        # here it cannot, since each example creates its own session and
        # asserts about that session alone. Without this, each example paid
        # for a full schema migration and the file took 55s instead of 2s.
        HealthCheck.function_scoped_fixture,
    ],
)

# Money, so two decimal places and no NaN or infinity — a payment of NaN
# would compare False against every limit and slip through.
amounts = st.floats(min_value=0.01, max_value=500.0, allow_nan=False,
                    allow_infinity=False).map(lambda f: round(f, 2))
caps = st.floats(min_value=1.0, max_value=1000.0, allow_nan=False,
                 allow_infinity=False).map(lambda f: round(f, 2))


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "spend.db")
    init_db(path)
    return path


def run_concurrently(fn, count):
    barrier = threading.Barrier(count)
    results: list = [None] * count
    errors: list = [None] * count

    def worker(i):
        try:
            barrier.wait(timeout=15)
            results[i] = fn(i)
        except Exception as e:  # noqa: BLE001
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
        t.join(timeout=40)
    if any(errors):
        raise AssertionError(f"worker raised: {[e for e in errors if e]}")
    return results


def persisted_spent(db, session_id):
    conn = get_db(db)
    row = conn.execute("SELECT spent FROM sessions WHERE session_id = ?",
                       (session_id,)).fetchone()
    conn.close()
    return row["spent"]


# ── The cap holds, whatever the amounts ──────────────────────────────

@given(attempts=st.lists(amounts, min_size=1, max_size=10), cap=caps)
@_SETTINGS
def test_granted_never_exceeds_the_cap(db, attempts, cap) -> None:
    """Sequential: for any list of amounts against any cap, the total the
    vault says yes to is at most the cap."""
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    session = gate.create_session("seq", scopes=["spend"], spend_limit=cap, ttl=3600)

    granted = sum(
        a["amount"] for a in (vault.authorize_payment(session, amt) for amt in attempts)
        if a.get("authorized")
    )

    assert granted <= cap + 1e-6, (
        f"authorized ${granted:.2f} against a ${cap:.2f} cap from {attempts}"
    )


@given(amount=amounts, cap=caps, threads=st.integers(min_value=2, max_value=12))
@_SETTINGS
def test_the_cap_holds_when_the_same_amount_arrives_at_once(db, amount, cap, threads) -> None:
    """Concurrent, all identical — the shape that broke.

    Every caller reads the same starting balance and every one of them is
    individually within budget. Only the *sum* is over.
    """
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    session = gate.create_session("race", scopes=["spend"], spend_limit=cap, ttl=3600)

    results = run_concurrently(lambda _i: vault.authorize_payment(session, amount), threads)
    granted = sum(r["amount"] for r in results if r.get("authorized"))

    assert granted <= cap + 1e-6, (
        f"{threads} simultaneous ${amount:.2f} authorizations granted "
        f"${granted:.2f} against a ${cap:.2f} cap"
    )


@given(amounts_=st.lists(amounts, min_size=2, max_size=8), cap=caps)
@_SETTINGS
def test_mixed_concurrent_amounts_stay_within_the_cap(db, amounts_, cap) -> None:
    """Distinct amounts arriving together, which defeats any fix that only
    handles the identical-value case."""
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    session = gate.create_session("mixed", scopes=["spend"], spend_limit=cap, ttl=3600)

    results = run_concurrently(
        lambda i: vault.authorize_payment(session, amounts_[i % len(amounts_)]),
        len(amounts_),
    )
    granted = sum(r["amount"] for r in results if r.get("authorized"))
    assert granted <= cap + 1e-6


# ── The books balance ────────────────────────────────────────────────

@given(attempts=st.lists(amounts, min_size=1, max_size=12), cap=caps)
@_SETTINGS
def test_recorded_spend_equals_what_was_granted(db, attempts, cap) -> None:
    """The other half of the guarantee, and the half that was silently wrong.

    A cap that holds while the ledger under-reports is a cap you cannot
    audit: the session row said $20 had been spent while $200 had been
    authorised. Sum what was handed out, and it must be what the row says.
    """
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    session = gate.create_session("ledger", scopes=["spend"], spend_limit=cap, ttl=3600)

    results = [vault.authorize_payment(session, amt) for amt in attempts]
    granted = sum(r["amount"] for r in results if r.get("authorized"))

    recorded = persisted_spent(db, session.session_id)
    assert abs(recorded - granted) < 1e-6, (
        f"handed out ${granted:.2f} but the session row records ${recorded:.2f}"
    )

    conn = get_db(db)
    paid = conn.execute("SELECT COALESCE(SUM(amount), 0) AS t FROM payments "
                        "WHERE session_id = ?", (session.session_id,)).fetchone()["t"]
    conn.close()
    assert abs(paid - granted) < 1e-6, (
        f"handed out ${granted:.2f} but the payments table totals ${paid:.2f}"
    )


@given(attempts=st.lists(amounts, min_size=2, max_size=10), cap=caps)
@_SETTINGS
def test_the_ledger_balances_under_concurrency(db, attempts, cap) -> None:
    """The lost-update half: concurrent writers each wrote their own idea of
    the total, so the row kept only the last one's."""
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    session = gate.create_session("cl", scopes=["spend"], spend_limit=cap, ttl=3600)

    results = run_concurrently(
        lambda i: vault.authorize_payment(session, attempts[i % len(attempts)]),
        len(attempts),
    )
    granted = sum(r["amount"] for r in results if r.get("authorized"))
    recorded = persisted_spent(db, session.session_id)

    assert abs(recorded - granted) < 1e-6, (
        f"handed out ${granted:.2f}, row records ${recorded:.2f} — a write "
        f"was lost"
    )
    assert recorded <= cap + 1e-6


# ── Edge cases that must not become loopholes ────────────────────────

def test_a_refusal_does_not_consume_budget(db) -> None:
    """Otherwise an agent that tries too much once is starved."""
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    session = gate.create_session("refuse", scopes=["spend"], spend_limit=50.0, ttl=3600)

    assert vault.authorize_payment(session, 500.0)["authorized"] is False
    assert persisted_spent(db, session.session_id) == 0.0
    assert vault.authorize_payment(session, 50.0)["authorized"] is True


def test_a_zero_cap_means_unlimited_not_nothing(db) -> None:
    """`spend_limit = 0` is "no limit" throughout the codebase. Reading it as
    "no budget" would silently refuse every payment on a default session."""
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    session = gate.create_session("unl", scopes=["spend"], spend_limit=0.0, ttl=3600)

    for _ in range(5):
        assert vault.authorize_payment(session, 1_000.0)["authorized"] is True


def test_exactly_the_remaining_budget_is_allowed(db) -> None:
    """The boundary is inclusive. An off-by-one here refuses the last valid
    payment, which shows up as a support ticket rather than a test failure."""
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    session = gate.create_session("edge", scopes=["spend"], spend_limit=100.0, ttl=3600)

    assert vault.authorize_payment(session, 60.0)["authorized"] is True
    assert vault.authorize_payment(session, 40.0)["authorized"] is True
    assert vault.authorize_payment(session, 0.01)["authorized"] is False


def test_a_revoked_session_cannot_spend(db) -> None:
    """Revocation has to stop money moving, not just hide the session."""
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    session = gate.create_session("rev", scopes=["spend"], spend_limit=100.0, ttl=3600)
    gate.revoke_session(session.session_id)

    result = vault.authorize_payment(session, 10.0)
    assert result["authorized"] is False
    assert persisted_spent(db, session.session_id) == 0.0


def test_an_expired_session_cannot_spend(db) -> None:
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    session = gate.create_session("exp", scopes=["spend"], spend_limit=100.0, ttl=1)
    session.expires_at = 0.0  # 0 means "never" — set a past instant instead
    import time as _t
    session.expires_at = _t.time() - 10

    result = vault.authorize_payment(session, 10.0)
    assert result["authorized"] is False


def test_a_negative_amount_is_refused(db) -> None:
    """A negative reservation would *raise* the cap, letting a caller mint
    budget for itself."""
    from haldir_gate import reserve_spend

    Vault(db_path=db)
    gate = Gate(db_path=db)
    session = gate.create_session("neg", scopes=["spend"], spend_limit=100.0, ttl=3600)

    conn = get_db(db)
    try:
        with pytest.raises(ValueError):
            reserve_spend(conn, session.session_id, "", -50.0)
    finally:
        conn.close()

    assert persisted_spent(db, session.session_id) == 0.0


def test_two_sessions_do_not_share_a_budget(db) -> None:
    vault, gate = Vault(db_path=db), Gate(db_path=db)
    a = gate.create_session("a", scopes=["spend"], spend_limit=50.0, ttl=3600)
    b = gate.create_session("b", scopes=["spend"], spend_limit=50.0, ttl=3600)

    assert vault.authorize_payment(a, 50.0)["authorized"] is True
    assert vault.authorize_payment(b, 50.0)["authorized"] is True
    assert persisted_spent(db, b.session_id) == 50.0
