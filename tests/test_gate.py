"""
Tests for haldir_gate.gate — Session + Gate (identity and permissions).

Covers the invariants the REST API and framework integrations depend on:
  - Session validity (expiry, revocation)
  - Permission checks (scope matching, admin override, prefix splits)
  - Spend authorization (budget enforcement)
  - Session creation (default scopes, spend parsing from "spend:50")
  - Revocation (kill switch semantics)

Run: python -m pytest tests/test_gate.py -v
"""

from __future__ import annotations

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_gate import Gate, Session


# ── Session invariants ───────────────────────────────────────────────────

def _make_session(**overrides) -> Session:
    """Build a Session with sane defaults for test scenarios."""
    defaults = dict(
        session_id="ses_test",
        agent_id="agent",
        scopes=["read"],
        spend_limit=0.0,
        spent=0.0,
        created_at=time.time(),
        expires_at=0.0,
        revoked=False,
    )
    defaults.update(overrides)
    return Session(**defaults)


def test_fresh_session_is_valid() -> None:
    assert _make_session().is_valid is True


def test_revoked_session_is_invalid() -> None:
    assert _make_session(revoked=True).is_valid is False


def test_expired_session_is_invalid() -> None:
    assert _make_session(expires_at=time.time() - 1).is_valid is False


def test_expires_at_zero_means_no_expiry() -> None:
    """expires_at=0 is the "never expires" sentinel."""
    assert _make_session(expires_at=0).is_valid is True


def test_remaining_budget_is_never_negative() -> None:
    """If somehow spent > spend_limit, remaining_budget clamps to 0, not negative."""
    s = _make_session(spend_limit=10.0, spent=15.0)
    assert s.remaining_budget == 0.0


def test_remaining_budget_subtracts_spent() -> None:
    s = _make_session(spend_limit=100.0, spent=30.0)
    assert s.remaining_budget == 70.0


# ── Permissions ──────────────────────────────────────────────────────────

def test_exact_scope_match() -> None:
    s = _make_session(scopes=["read", "search"])
    assert s.has_permission("read") is True
    assert s.has_permission("search") is True


def test_missing_scope_is_denied() -> None:
    s = _make_session(scopes=["read"])
    assert s.has_permission("delete") is False
    assert s.has_permission("admin") is False


def test_admin_scope_grants_everything() -> None:
    s = _make_session(scopes=["admin"])
    assert s.has_permission("anything") is True
    assert s.has_permission("delete") is True
    assert s.has_permission("spend:1000000") is True


def test_base_scope_matches_prefixed_request() -> None:
    """'spend' in scopes permits 'spend:50' and 'spend:anything'."""
    s = _make_session(scopes=["spend"])
    assert s.has_permission("spend") is True
    assert s.has_permission("spend:50") is True


# ── Spend authorization ──────────────────────────────────────────────────

def test_authorize_spend_without_scope_is_denied() -> None:
    s = _make_session(scopes=["read"], spend_limit=100.0)
    assert s.authorize_spend(10.0) is False


def test_authorize_spend_within_budget() -> None:
    s = _make_session(scopes=["spend"], spend_limit=50.0, spent=10.0)
    assert s.authorize_spend(20.0) is True


def test_authorize_spend_exceeds_budget_is_denied() -> None:
    s = _make_session(scopes=["spend"], spend_limit=50.0, spent=40.0)
    assert s.authorize_spend(20.0) is False  # would hit 60 > 50


def test_authorize_spend_exactly_at_budget_is_allowed() -> None:
    s = _make_session(scopes=["spend"], spend_limit=50.0, spent=30.0)
    assert s.authorize_spend(20.0) is True  # exactly 50, allowed


def test_zero_spend_limit_means_unlimited() -> None:
    """spend_limit=0 is the "no cap" sentinel."""
    s = _make_session(scopes=["spend"], spend_limit=0.0)
    assert s.authorize_spend(1_000_000.0) is True


def test_record_spend_accumulates() -> None:
    s = _make_session(scopes=["spend"], spend_limit=100.0)
    s.record_spend(30.0)
    s.record_spend(20.0)
    assert s.spent == 50.0
    assert s.remaining_budget == 50.0


# ── Gate: session creation + retrieval ───────────────────────────────────

@pytest.fixture
def gate() -> Gate:
    """In-memory Gate (no DB)."""
    return Gate()


def test_create_session_returns_valid_session(gate: Gate) -> None:
    session = gate.create_session("my-agent", scopes=["read"], ttl=3600)
    assert session.agent_id == "my-agent"
    assert session.session_id.startswith("ses_")
    assert session.is_valid is True


def test_create_session_defaults_when_no_scopes_given(gate: Gate) -> None:
    """With no agent policy and no scopes, defaults to ['read']."""
    session = gate.create_session("my-agent", ttl=3600)
    assert session.scopes == ["read"]


def test_create_session_parses_spend_from_scope(gate: Gate) -> None:
    """`spend:50` should set spend_limit=50 automatically."""
    session = gate.create_session("agent", scopes=["read", "spend:50"], ttl=3600)
    assert session.spend_limit == 50.0
    # The scopes list stores the base scope name, not the colon-form
    assert "spend" in session.scopes


def test_create_session_explicit_spend_limit_overrides_scope(gate: Gate) -> None:
    session = gate.create_session(
        "agent", scopes=["spend:10"], spend_limit=100.0, ttl=3600
    )
    assert session.spend_limit == 100.0


def test_get_session_returns_stored_session(gate: Gate) -> None:
    created = gate.create_session("agent", ttl=3600)
    retrieved = gate.get_session(created.session_id)
    assert retrieved is not None
    assert retrieved.session_id == created.session_id


def test_get_session_returns_none_for_unknown_id(gate: Gate) -> None:
    assert gate.get_session("ses_nonexistent") is None


def test_check_permission_denies_unknown_session(gate: Gate) -> None:
    """No session → no permission, regardless of scope."""
    assert gate.check_permission("ses_fake", "read") is False


def test_check_permission_respects_session_scopes(gate: Gate) -> None:
    session = gate.create_session("agent", scopes=["read"], ttl=3600)
    assert gate.check_permission(session.session_id, "read") is True
    assert gate.check_permission(session.session_id, "delete") is False


# ── Tenant isolation ─────────────────────────────────────────────────────

def test_session_from_one_tenant_is_not_visible_to_another(gate: Gate) -> None:
    """In-memory mode: tenant_id is part of session scope."""
    session = gate.create_session("agent", tenant_id="alice", ttl=3600)
    assert gate.get_session(session.session_id, tenant_id="bob") is None
    assert gate.get_session(session.session_id, tenant_id="alice") is not None


# ── Session IDs are unguessable ──────────────────────────────────────────

def test_session_ids_are_unique_and_sufficiently_random(gate: Gate) -> None:
    """Session IDs use secrets.token_urlsafe(24) → 32 chars after ses_ prefix."""
    ids = {gate.create_session("a", ttl=1).session_id for _ in range(50)}
    assert len(ids) == 50  # all unique
    for sid in ids:
        assert sid.startswith("ses_")
        assert len(sid) >= 20  # well over birthday-paradox threshold
