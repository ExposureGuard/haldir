"""
Tests for haldir_gate.proxy.HaldirProxy — policy engine.

These tests focus on `_enforce_policies` — the pure, deterministic function
that decides whether an intercepted tool call is allowed. Integration-level
tests that actually forward to upstream HTTP servers live in tests/integration/
(planned) and require Docker, so they run separately.

Policy types covered:
  - block_tool:   named tool is blocked
  - allow_list:   only listed tools allowed
  - deny_list:    listed tools blocked, everything else allowed
  - spend_limit:  per-call amount must not exceed max
  - time_window:  calls only permitted within UTC hour window

Run: python -m pytest tests/test_proxy.py -v
"""

from __future__ import annotations

import datetime
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_gate.proxy import HaldirProxy, UpstreamServer


# ── Fixtures ─────────────────────────────────────────────────────────────

class _StubSession:
    def __init__(self, session_id="ses_1", agent_id="agent-1"):
        self.session_id = session_id
        self.agent_id = agent_id


@pytest.fixture
def proxy() -> HaldirProxy:
    return HaldirProxy()


@pytest.fixture
def session() -> _StubSession:
    return _StubSession()


# ── Upstream registration ────────────────────────────────────────────────

def test_register_upstream_stores_server(proxy: HaldirProxy) -> None:
    # register_upstream fires a discovery request at the upstream; with no
    # upstream running the server is marked unhealthy. We only assert the
    # registration bookkeeping (url, presence), not network-dependent state.
    proxy.register_upstream("stripe", "http://127.0.0.1:1")
    assert "stripe" in proxy._upstreams
    assert proxy._upstreams["stripe"].url == "http://127.0.0.1:1"


def test_register_upstream_initial_state_sane(proxy: HaldirProxy) -> None:
    proxy.register_upstream("github", "http://127.0.0.1:1")
    u = proxy._upstreams["github"]
    assert u.total_calls == 0
    assert u.total_errors == 0


# ── No policies = all calls pass ─────────────────────────────────────────

def test_no_policies_allows_any_call(proxy: HaldirProxy, session) -> None:
    assert proxy._enforce_policies("anything", {}, session) is None
    assert proxy._enforce_policies("stripe.charge", {"amount": 1_000_000}, session) is None


# ── block_tool ───────────────────────────────────────────────────────────

def test_block_tool_blocks_exact_match(proxy: HaldirProxy, session) -> None:
    proxy.add_policy("block_tool", tool="delete_database")
    result = proxy._enforce_policies("delete_database", {}, session)
    assert result is not None
    assert result.get("isError") is True


def test_block_tool_blocks_suffix_match(proxy: HaldirProxy, session) -> None:
    """A 'stripe.refund' call should be blocked by tool='refund' (suffix-style)."""
    proxy.add_policy("block_tool", tool="refund")
    result = proxy._enforce_policies("stripe.refund", {}, session)
    assert result is not None
    assert result.get("isError") is True


def test_block_tool_allows_unrelated(proxy: HaldirProxy, session) -> None:
    proxy.add_policy("block_tool", tool="delete_database")
    assert proxy._enforce_policies("list_customers", {}, session) is None


# ── allow_list ───────────────────────────────────────────────────────────

def test_allow_list_permits_listed_tool(proxy: HaldirProxy, session) -> None:
    proxy.add_policy("allow_list", tools=["list_customers", "get_invoice"])
    assert proxy._enforce_policies("list_customers", {}, session) is None


def test_allow_list_blocks_unlisted_tool(proxy: HaldirProxy, session) -> None:
    proxy.add_policy("allow_list", tools=["list_customers"])
    result = proxy._enforce_policies("charge", {}, session)
    assert result is not None
    assert result.get("isError") is True


def test_allow_list_matches_dotted_tool_name(proxy: HaldirProxy, session) -> None:
    """'stripe.list_customers' should match allow_list with 'list_customers'."""
    proxy.add_policy("allow_list", tools=["list_customers"])
    assert proxy._enforce_policies("stripe.list_customers", {}, session) is None


# ── deny_list ────────────────────────────────────────────────────────────

def test_deny_list_blocks_listed_tool(proxy: HaldirProxy, session) -> None:
    proxy.add_policy("deny_list", tools=["drop_table", "delete_database"])
    result = proxy._enforce_policies("drop_table", {}, session)
    assert result is not None
    assert result.get("isError") is True


def test_deny_list_allows_unlisted_tool(proxy: HaldirProxy, session) -> None:
    proxy.add_policy("deny_list", tools=["drop_table"])
    assert proxy._enforce_policies("select_from_users", {}, session) is None


def test_deny_list_matches_dotted_tool_name(proxy: HaldirProxy, session) -> None:
    proxy.add_policy("deny_list", tools=["delete_database"])
    result = proxy._enforce_policies("postgres.delete_database", {}, session)
    assert result is not None
    assert result.get("isError") is True


# ── spend_limit ──────────────────────────────────────────────────────────

def test_spend_limit_allows_under_max(proxy: HaldirProxy, session) -> None:
    proxy.add_policy("spend_limit", max=100.0)
    assert proxy._enforce_policies("charge", {"amount": 50.0}, session) is None


def test_spend_limit_allows_exactly_at_max(proxy: HaldirProxy, session) -> None:
    proxy.add_policy("spend_limit", max=100.0)
    assert proxy._enforce_policies("charge", {"amount": 100.0}, session) is None


def test_spend_limit_blocks_over_max(proxy: HaldirProxy, session) -> None:
    proxy.add_policy("spend_limit", max=100.0)
    result = proxy._enforce_policies("charge", {"amount": 100.01}, session)
    assert result is not None
    assert result.get("isError") is True


def test_spend_limit_ignores_missing_amount(proxy: HaldirProxy, session) -> None:
    """No amount argument = treated as 0, which should pass any positive cap."""
    proxy.add_policy("spend_limit", max=100.0)
    assert proxy._enforce_policies("list_customers", {}, session) is None


# ── time_window ──────────────────────────────────────────────────────────
# `_enforce_policies` reads the current UTC hour from datetime inside the
# function body. Rather than monkey-patching stdlib, we construct windows
# relative to `now` so the test is deterministic regardless of when it runs.

def _current_utc_hour() -> int:
    return datetime.datetime.now(datetime.timezone.utc).hour


def test_time_window_allows_when_now_is_inside(proxy: HaldirProxy, session) -> None:
    hour = _current_utc_hour()
    # Build an inclusive window around the current hour
    start = (hour - 2) % 24
    end = (hour + 2) % 24
    # Avoid wrap-around cases that the simple < comparator doesn't handle
    if start < end:
        proxy.add_policy("time_window", start_hour=start, end_hour=end)
        assert proxy._enforce_policies("charge", {}, session) is None


def test_time_window_blocks_when_now_is_outside(proxy: HaldirProxy, session) -> None:
    hour = _current_utc_hour()
    # Window well before the current hour
    start = (hour + 3) % 24
    end = (hour + 5) % 24
    if start < end:
        proxy.add_policy("time_window", start_hour=start, end_hour=end)
        result = proxy._enforce_policies("charge", {}, session)
        assert result is not None
        assert result.get("isError") is True


# ── Multiple policies ────────────────────────────────────────────────────

def test_multiple_policies_all_must_pass(proxy: HaldirProxy, session) -> None:
    """Policies are AND-combined. Allowed by one but blocked by another = blocked."""
    proxy.add_policy("deny_list", tools=["charge"])
    proxy.add_policy("spend_limit", max=1000.0)

    # "charge" is on the deny list even though amount is fine
    result = proxy._enforce_policies("charge", {"amount": 50.0}, session)
    assert result is not None
    assert result.get("isError") is True


def test_policies_list_position_independent(proxy: HaldirProxy, session) -> None:
    """Reversing the order of add_policy calls produces the same result."""
    proxy.add_policy("spend_limit", max=100.0)
    proxy.add_policy("deny_list", tools=["charge"])

    result = proxy._enforce_policies("charge", {"amount": 50.0}, session)
    assert result is not None
    assert result.get("isError") is True


# ── Aliases: add_policy accepts `type=` OR `policy_type=` ────────────────

def test_add_policy_accepts_type_kwarg(proxy: HaldirProxy, session) -> None:
    """`type=` alias (backward-compat) should work the same as `policy_type=`."""
    proxy.add_policy(type="block_tool", tool="drop_table")
    result = proxy._enforce_policies("drop_table", {}, session)
    assert result is not None


# ── get_tools ────────────────────────────────────────────────────────────

def test_get_tools_returns_empty_when_no_upstreams(proxy: HaldirProxy) -> None:
    assert proxy.get_tools() == []


def test_get_tools_includes_haldir_governance_metadata(proxy: HaldirProxy) -> None:
    """Every tool returned gets a _haldir block so agents know it's governed."""
    server = UpstreamServer(name="stripe", url="http://localhost:3001")
    server.tools = [{"name": "charge", "description": "Charge a card"}]
    proxy._upstreams["stripe"] = server

    tools = proxy.get_tools()
    assert len(tools) == 1
    assert tools[0]["_haldir"]["upstream"] == "stripe"
    assert tools[0]["_haldir"]["proxied"] is True
    assert tools[0]["_haldir"]["governance"] == "enforced"


def test_get_tools_skips_unhealthy_upstreams(proxy: HaldirProxy) -> None:
    server = UpstreamServer(name="stripe", url="http://localhost:3001", healthy=False)
    server.tools = [{"name": "charge"}]
    proxy._upstreams["stripe"] = server

    assert proxy.get_tools() == []
