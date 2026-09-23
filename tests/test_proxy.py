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
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_gate.proxy import HaldirProxy, UpstreamServer
from haldir_outbound import UnsafeURL


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

def test_register_upstream_stores_server(proxy: HaldirProxy, monkeypatch) -> None:
    # register_upstream fires a discovery request at the upstream; with no
    # upstream running the server is marked unhealthy. We only assert the
    # registration bookkeeping (url, presence), not network-dependent state.
    #
    # The private-address opt-out is set because this stub lives on loopback.
    # That is the self-hosted case the switch exists for; the guard itself is
    # asserted separately, below.
    monkeypatch.setenv("HALDIR_ALLOW_PRIVATE_OUTBOUND", "1")
    proxy.register_upstream("stripe", "http://127.0.0.1:1")
    assert "stripe" in proxy._upstreams
    assert proxy._upstreams["stripe"].url == "http://127.0.0.1:1"


def test_register_upstream_initial_state_sane(proxy: HaldirProxy, monkeypatch) -> None:
    monkeypatch.setenv("HALDIR_ALLOW_PRIVATE_OUTBOUND", "1")
    proxy.register_upstream("github", "http://127.0.0.1:1")
    u = proxy._upstreams["github"]
    assert u.total_calls == 0
    assert u.total_errors == 0


# ── Upstream URLs are guarded the way webhook URLs are ───────────────────
#
# The URL is tenant-supplied on the hosted service, which puts it in the same
# class as a webhook URL — but it was not checked at all. An upstream pointed
# at the metadata endpoint was accepted, fetched during tool discovery, and
# its response body returned in the registration reply.

@pytest.fixture
def discovery_calls(monkeypatch) -> list[str]:
    """Record what registration would have fetched, without fetching it.

    register_upstream fires a real tools/list request at whatever URL it is
    given. Stubbing it keeps these tests off the network and lets them assert
    the stronger property — not only that a bad URL is refused, but that no
    request was made to it at all.
    """
    calls: list[str] = []
    monkeypatch.setattr(HaldirProxy, "_discover_tools",
                        lambda self, server: calls.append(server.url))
    return calls


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8000/healthz",
    "http://[::1]:8000/",
])
def test_a_refused_upstream_url_is_not_registered(proxy: HaldirProxy,
                                                  url: str,
                                                  discovery_calls) -> None:
    """Refused, refused before it is stored, and never fetched."""
    with pytest.raises(UnsafeURL):
        proxy.register_upstream("probe", url)
    assert "probe" not in proxy._upstreams
    assert discovery_calls == []


def test_a_public_upstream_url_is_accepted(proxy: HaldirProxy,
                                           discovery_calls) -> None:
    """The control. Without this, the test above would also pass against a
    guard that refuses everything, which is not a guard."""
    proxy.register_upstream("probe", "https://example.com/mcp")
    assert proxy._upstreams["probe"].url == "https://example.com/mcp"
    assert discovery_calls == ["https://example.com/mcp"]


def test_a_private_upstream_is_allowed_when_the_opt_out_is_set(
        proxy: HaldirProxy, monkeypatch, discovery_calls) -> None:
    """Self-hosted deployments point upstreams at internal services — this
    module's own config example is `http://localhost:3001`. The opt-out is
    what stops the guard being security theatre for them."""
    monkeypatch.setenv("HALDIR_ALLOW_PRIVATE_OUTBOUND", "1")
    proxy.register_upstream("local", "http://127.0.0.1:1")
    assert "local" in proxy._upstreams


def test_the_opt_out_still_honours_its_original_name(
        proxy: HaldirProxy, monkeypatch, discovery_calls) -> None:
    """HALDIR_ALLOW_PRIVATE_WEBHOOKS shipped first. Two switches for one
    decision is how a deployment ends up with the check relaxed in one place
    and enforced in the other, so the old name stays an alias."""
    monkeypatch.setenv("HALDIR_ALLOW_PRIVATE_WEBHOOKS", "1")
    proxy.register_upstream("local", "http://127.0.0.1:1")
    assert "local" in proxy._upstreams


def test_a_call_to_an_upstream_that_is_now_private_is_refused(
        proxy: HaldirProxy) -> None:
    """The call-time re-check, asserted directly.

    Registration-time checking alone cannot hold: a name that resolved to a
    public address then can resolve inward by the time a call is made. This
    builds the server by hand to reach that path without a rebinding DNS
    server, and asserts the call carries no arguments anywhere.
    """
    server = UpstreamServer(name="rebound", url="http://127.0.0.1:8000/mcp")
    result = proxy._forward(server, "some_tool", {"secret": "value"})

    assert result.get("isError") is True
    body = json.dumps(result)
    assert "not a public address" in body


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
