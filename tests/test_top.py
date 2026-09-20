"""
`haldir top` — the live console.

Two things are being pinned here, and they are different in kind.

The presentation: that the frame shows what an operator watching a fleet
needs — which agents are running, what they are spending against their caps,
what they just did, and whether the audit chain is intact. The frame is a
pure function of the overview payload, so all of that is testable as a
string, with no terminal anywhere near it.

The terminal handling: that the console does not hang or corrupt a terminal
in the environments where it is not wanted — a pipe, a file, CI. `top` in a
non-tty has to draw one frame and exit rather than block on a keypress that
will never arrive, which is also what makes `haldir top --once > file` work.

The rendering deliberately contains no escape codes. Colour belongs to the
terminal loop; putting it in the frame would turn every layout assertion
below into a puzzle about invisible bytes.

Run: python -m pytest tests/test_top.py -v
"""

from __future__ import annotations

import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import haldir_top  # noqa: E402


def _overview(**over: object) -> dict:
    """A payload shaped like /v1/admin/overview, with overrides."""
    base = {
        "tenant_id": "acme0123456789ab",
        "tier": "pro",
        "usage": {
            "actions_this_month": 1234,
            "actions_limit": 2_500_000,
            "actions_pct_used": 0.0005,
            "spend_usd_this_month": 12.40,
            "overage_actions": 0,
            "overage_usd": None,
            "metered": True,
        },
        "sessions": {
            "active_count": 2,
            "agents_active": 2,
            "agents_limit": 25,
            "sessions": [
                {"session_id": "ses_aaaaaaaaaaaa", "agent_id": "research-agent",
                 "scopes": ["read", "http"], "spent": 31.40, "spend_limit": 50.0,
                 "last_active": 1_000.0},
                {"session_id": "ses_bbbbbbbbbbbb", "agent_id": "code-agent",
                 "scopes": ["exec"], "spent": 0.0, "spend_limit": 10.0,
                 "last_active": 900.0},
            ],
        },
        "audit": {
            "total_entries": 1234,
            "flagged_7d": 0,
            "chain_verified": True,
            "recent": [
                {"timestamp": 1_000.0, "agent_id": "research-agent",
                 "action": "tool_call", "tool": "web.search",
                 "cost_usd": 0.02, "flagged": False, "flag_reason": ""},
            ],
        },
    }
    base.update(over)  # type: ignore[arg-type]
    return base


# ── What the operator needs to see ───────────────────────────────────

def test_header_names_the_tenant_and_tier() -> None:
    out = haldir_top.render_frame(_overview(), now=1_000.0)
    assert "acme0123456789ab" in out
    assert "pro" in out


def test_usage_is_shown_against_the_allowance() -> None:
    out = haldir_top.render_frame(_overview(), now=1_000.0)
    assert "1,234" in out
    assert "2,500,000" in out
    assert "$12.40" in out


def test_every_active_agent_is_listed() -> None:
    out = haldir_top.render_frame(_overview(), now=1_000.0)
    assert "research-agent" in out
    assert "code-agent" in out


def test_spend_is_shown_against_each_session_cap() -> None:
    out = haldir_top.render_frame(_overview(), now=1_000.0)
    assert "$31.40 / $50.00" in out
    assert "$0.00 / $10.00" in out


def test_a_session_with_no_cap_says_so_rather_than_showing_zero() -> None:
    """"$0.00 / $0.00" reads as a cap of zero, which is the opposite of
    uncapped."""
    ov = _overview()
    ov["sessions"]["sessions"][0]["spend_limit"] = 0.0
    out = haldir_top.render_frame(ov, now=1_000.0)
    assert "no cap" in out


def test_recent_activity_is_shown() -> None:
    out = haldir_top.render_frame(_overview(), now=1_000.0)
    assert "web.search" in out
    assert "tool_call" in out


def test_idle_time_is_human_readable() -> None:
    out = haldir_top.render_frame(_overview(), now=1_060.0)
    assert "1m" in out, "60 seconds idle should read as a minute"


# ── The things that mean something is wrong ──────────────────────────

def test_a_broken_chain_is_impossible_to_miss() -> None:
    """This is the one line in the whole frame that says the audit trail has
    stopped being trustworthy. It must not be a subtle colour change."""
    ov = _overview()
    ov["audit"]["chain_verified"] = False
    out = haldir_top.render_frame(ov, now=1_000.0)
    assert "CHAIN BROKEN" in out.upper()
    assert "chain OK" not in out


def test_flagged_actions_are_marked() -> None:
    ov = _overview()
    ov["audit"]["recent"][0]["flagged"] = True
    ov["audit"]["recent"][0]["flag_reason"] = "over-threshold"
    ov["audit"]["flagged_7d"] = 1
    out = haldir_top.render_frame(ov, now=1_000.0)
    marked = [ln for ln in out.splitlines() if ln.startswith(" !")]
    assert marked, "a flagged entry should be marked in the activity feed"
    assert "1 flagged" in out


def test_overage_is_surfaced_when_there_is_any() -> None:
    ov = _overview()
    ov["usage"]["overage_actions"] = 500_000
    ov["usage"]["overage_usd"] = 50.0
    out = haldir_top.render_frame(ov, now=1_000.0)
    assert "500,000" in out
    assert "$50.00" in out


def test_no_overage_row_when_under_the_allowance() -> None:
    out = haldir_top.render_frame(_overview(), now=1_000.0)
    assert "Over by" not in out


# ── Degrading rather than crashing ───────────────────────────────────

def test_an_empty_fleet_renders() -> None:
    """A fresh instance has no sessions and no activity. It must draw, not
    divide by zero or print a bare table header."""
    ov = _overview()
    ov["sessions"]["sessions"] = []
    ov["sessions"]["active_count"] = 0
    ov["audit"]["recent"] = []
    out = haldir_top.render_frame(ov, now=1_000.0)
    assert "ACTIVE AGENTS" in out
    assert "RECENT ACTIVITY" in out
    assert "none" in out.lower() or "nothing" in out.lower()


def test_a_missing_payload_does_not_crash() -> None:
    """A malformed or partial response should leave the console on screen
    rather than take it down — losing the connection is exactly when an
    operator most wants to keep looking at the last state."""
    out = haldir_top.render_frame({}, now=1_000.0)
    assert out.strip()


def test_a_zero_allowance_does_not_divide_by_zero() -> None:
    ov = _overview()
    ov["usage"]["actions_limit"] = 0
    out = haldir_top.render_frame(ov, now=1_000.0)
    assert "0.0%" in out


def test_very_long_values_are_clipped_to_the_width() -> None:
    """An agent named with a 5000-character string must not reflow the
    console into unreadable soup."""
    ov = _overview()
    ov["sessions"]["sessions"][0]["agent_id"] = "A" * 5000
    out = haldir_top.render_frame(ov, now=1_000.0, width=80)
    assert max(len(ln) for ln in out.splitlines()) <= 80


def test_no_line_exceeds_the_terminal_width() -> None:
    """Including below the minimum, where the frame is drawn at MIN_WIDTH
    rather than clipped. A table cut mid-column reads as data loss; a frame
    that is consistently a bit wider than a very narrow terminal reads as a
    terminal that is too narrow, which is the truth."""
    for requested in (50, 80, 120, 200):
        out = haldir_top.render_frame(_overview(), now=1_000.0, width=requested)
        widest = max(len(ln) for ln in out.splitlines())
        effective = max(haldir_top.MIN_WIDTH, requested)
        assert widest <= effective, (
            f"at width={requested} (effective {effective}) the widest line was "
            f"{widest}, which would wrap"
        )


def test_the_minimum_width_actually_fits_the_widest_table() -> None:
    """MIN_WIDTH is a promise, so it has to be measured against the real
    frame rather than assumed. If a column is ever added, this fails rather
    than the console silently wrapping in everyone's terminal."""
    out = haldir_top.render_frame(_overview(), now=1_000.0,
                                  width=haldir_top.MIN_WIDTH)
    widest = max(len(ln) for ln in out.splitlines())
    assert widest <= haldir_top.MIN_WIDTH, (
        f"MIN_WIDTH is {haldir_top.MIN_WIDTH} but the frame needs {widest}"
    )


# ── The frame carries no terminal control ────────────────────────────

def test_the_frame_has_no_escape_codes() -> None:
    """Colour and cursor control belong to the terminal loop. If they leak
    into the frame, every assertion above becomes a counting exercise and
    plain-text consumers get bytes they cannot read."""
    out = haldir_top.render_frame(_overview(), now=1_000.0)
    assert "\033" not in out, "the frame should be plain text"
    assert "\x1b" not in out


# ── The non-terminal path ────────────────────────────────────────────

class _FakeClient:
    def __init__(self, payload=None, raises=None):
        self.payload = payload if payload is not None else _overview()
        self.raises = raises
        self.calls = 0

    def get(self, path, **kwargs):
        self.calls += 1
        if self.raises:
            raise self.raises
        return self.payload


def test_once_draws_one_frame_and_returns(monkeypatch) -> None:
    """`haldir top --once` is what a pipe and a smoke test both use."""
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    buf = io.StringIO()
    rc = haldir_top.run(_FakeClient(), once=True, stream=buf)
    assert rc == 0
    assert "ACTIVE AGENTS" in buf.getvalue()


def test_a_pipe_draws_one_frame_instead_of_hanging(monkeypatch) -> None:
    """The failure this prevents: `haldir top | head` blocking forever on a
    keypress, because stdin is a pipe and nobody is going to press one."""
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    buf = io.StringIO()
    rc = haldir_top.run(_FakeClient(), stream=buf)
    assert rc == 0
    assert buf.getvalue().strip()
