"""
`haldir top` — a live console for a fleet of agents, in the terminal.

Why this exists when there is already a web dashboard:

  * The people who watch agents for a living — security and platform
    engineers — are already in a terminal, usually over SSH, often on a box
    where opening a browser is not the thing you do during an incident.
  * The dashboard refreshes on a `<meta http-equiv="refresh" content="30">`.
    Thirty seconds is fine for a status page and useless for watching
    something happen; you cannot see an agent misbehave at that frame rate.
  * Nothing to deploy. It ships in the wheel and talks to the same
    /v1/admin/overview the web console uses, so there is no second source of
    truth about what the fleet is doing.

The split that matters: `render_frame` is a pure function from the overview
payload to a string. Everything about terminals — the alternate screen
buffer, raw key input, the redraw timer — lives in `run`, below it. That is
what makes the presentation testable without a tty, and the terminal handling
small enough to read in one sitting.

Why not Rich or Textual: this is a security product whose dependencies are
bounded and audited on every build, and a UI framework is a large amount of
code to add for one command. The CLI already draws its own bars and boxes.

(That is also why the drawing here is deliberately plain ASCII where it can
be. Box-drawing characters render as mojibake through some SSH clients and
screen readers, and the earlier `_bar` helper already sticks to block
elements for the same reason.)
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from typing import Any

# ── The pure part ────────────────────────────────────────────────────

# Rows of activity to show. Fixed rather than filling the terminal, because a
# console that changes shape as you resize it is harder to read than one that
# stays put and scrolls its data.
ACTIVITY_ROWS = 12
SESSION_ROWS = 8

# The narrowest terminal this draws correctly in. The widest row is the
# activity table at 72 columns (time, agent, action, tool, cost), so below
# that the tables cannot fit and the frame would wrap into soup. `top` and
# `htop` solve this by declaring a floor; so does this, rather than pretending
# to be responsive and producing something unreadable.
#
# Clipping each line to the width instead would satisfy the invariant and look
# broken: a table cut mid-column reads as data loss, not as a narrow terminal.
MIN_WIDTH = 74


def _human_age(seconds: float) -> str:
    """Idle time, coarsening with age. A console is scanned rather than read,
    so the unit carries more than the precision."""
    if seconds < 0:
        seconds = 0.0
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.0f}h"
    return f"{seconds / 86400:.0f}d"


def _clock(ts: float) -> str:
    if not ts:
        return "--:--:--"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")


def _bar(pct: float, width: int = 22) -> str:
    """Plain-text progress bar. No colour: render_frame returns a string that
    tests compare against directly, and escape codes in it would make every
    assertion about the layout a puzzle."""
    pct = max(0.0, min(1.0, pct))
    filled = int(round(pct * width))
    return "[" + "#" * filled + "." * (width - filled) + "]"


def _bar_width(total_width: int) -> int:
    """How much room the quota bar gets, given the terminal.

    Everything else on that line is fixed — indent, label, a ten-digit count,
    the separator and a percentage — so whatever is left belongs to the bar,
    clamped so it neither vanishes nor dominates.
    """
    overhead = 43          # measured from the rendered line, not estimated
    return max(8, min(22, total_width - overhead))


def _money(amount: float) -> str:
    """Dollar amount as one token, so the sign stays against the digits.

    `f"${v:>10,.2f}"` pads between the two and prints "$     12.40", which
    reads as a layout bug and makes the amount hard to scan down a column.
    """
    return f"${amount:,.2f}"


def _clip(text: str, width: int) -> str:
    """Truncate to width, marking that it happened."""
    text = str(text or "")
    if width <= 1 or len(text) <= width:
        return text
    return text[: width - 1] + "~"


def render_frame(
    overview: dict[str, Any],
    *,
    now: float | None = None,
    width: int = 78,
    paused: bool = False,
    status_line: str = "",
) -> str:
    """One frame of the console, as a string. Pure — no I/O, no terminal.

    `overview` is the /v1/admin/overview payload verbatim, so this renders
    exactly what the API returns and cannot drift from it.
    """
    now = time.time() if now is None else now
    w = max(MIN_WIDTH, width)
    out: list[str] = []

    def rule() -> str:
        return "  " + "-" * (w - 4)

    usage = overview.get("usage", {}) or {}
    sessions = overview.get("sessions", {}) or {}
    audit = overview.get("audit", {}) or {}

    # ── Header ──
    tenant = str(overview.get("tenant_id", ""))[:16]
    tier = overview.get("tier", "?")
    stamp = _clock(now)
    head = f"  Haldir top   {tenant}   tier {tier}   {stamp}"
    if paused:
        head += "   [PAUSED]"
    out.append(_clip(head, w))
    out.append(rule())

    # ── The four numbers worth a row each ──
    used = int(usage.get("actions_this_month", 0) or 0)
    limit = int(usage.get("actions_limit", 0) or 0)
    pct = (used / limit) if limit else 0.0
    # The bar gives up its width before the line does. A fixed 22-cell bar on
    # an 80-column terminal pushes the quota line past the edge, where it
    # wraps and takes the layout with it.
    out.append(
        f"  API calls  {used:>10,} / {limit:,}  "
        f"{_bar(pct, _bar_width(w))}  {pct * 100:5.1f}%"
    )

    over = int(usage.get("overage_actions", 0) or 0)
    if over:
        cost = usage.get("overage_usd")
        shown = f"${float(cost):,.2f}" if cost is not None else "not billable"
        out.append(f"  Over by    {over:>10,} API calls            ({shown})")

    spend = float(usage.get("spend_usd_this_month", 0.0) or 0.0)
    active = int(sessions.get("active_count", 0) or 0)
    agents = int(sessions.get("agents_active", 0) or 0)
    agents_cap = int(sessions.get("agents_limit", 0) or 0)
    out.append(f"  Spend      {_money(spend):>10} this month")
    out.append(f"  Sessions   {active:>10,} active   ({agents}/{agents_cap} agents)")

    entries = int(audit.get("total_entries", 0) or 0)
    flagged = int(audit.get("flagged_7d", 0) or 0)
    verified = audit.get("chain_verified", True)
    chain = "chain OK" if verified else "CHAIN BROKEN"
    flag_note = f"   {flagged} flagged (7d)" if flagged else ""
    out.append(f"  Audit      {entries:>10,} entries   {chain}{flag_note}")
    out.append("")

    # ── Who is running ──
    out.append("  ACTIVE AGENTS")
    rows = (sessions.get("sessions") or [])[:SESSION_ROWS]
    if rows:
        out.append(
            f"  {'AGENT':<20} {'SESSION':<14} {'SPEND / CAP':<22} {'IDLE':>6}"
        )
        for r in rows:
            agent = _clip(r.get("agent_id", ""), 20)
            sid = _clip(str(r.get("session_id", ""))[:12], 14)
            spent = float(r.get("spent", 0.0) or 0.0)
            cap = float(r.get("spend_limit", 0.0) or 0.0)
            money = (f"${spent:,.2f} / ${cap:,.2f}" if cap > 0
                     else f"${spent:,.2f} / no cap")
            idle = _human_age(max(0.0, now - float(r.get("last_active", 0) or 0)))
            out.append(f"  {agent:<20} {sid:<14} {_clip(money, 22):<22} {idle:>6}")
        total = int(sessions.get("active_count", 0) or 0)
        if total > len(rows):
            out.append(f"  ... and {total - len(rows)} more")
    else:
        out.append("  (none — an agent appears here when it opens a session)")
    out.append("")

    # ── What is happening ──
    out.append("  RECENT ACTIVITY")
    recent = (audit.get("recent") or [])[:ACTIVITY_ROWS]
    if recent:
        out.append(
            f"  {'TIME':<9} {'AGENT':<18} {'ACTION':<12} {'TOOL':<18} {'COST':>9}"
        )
        for r in recent:
            mark = "!" if r.get("flagged") else " "
            out.append(
                f" {mark}{_clock(float(r.get('timestamp', 0) or 0)):<9}"
                f" {_clip(r.get('agent_id', ''), 18):<18}"
                f" {_clip(r.get('action', ''), 12):<12}"
                f" {_clip(r.get('tool', '') or '-', 18):<18}"
                f" ${float(r.get('cost_usd', 0.0) or 0.0):>8.4f}"
            )
    else:
        out.append("  (nothing recorded yet)")
    out.append("")

    # ── Controls ──
    out.append(rule())
    if status_line:
        out.append(f"  {_clip(status_line, w - 4)}")
    out.append("  q quit   p pause   r revoke a session   +/- refresh rate")
    return "\n".join(out)


# ── The terminal part ────────────────────────────────────────────────

# Alternate screen buffer: entering it saves whatever was on screen and gives
# us a scratch page, so the console does not scribble over scrollback and the
# terminal is put back exactly as it was on exit. This is why `top` does not
# leave your shell full of half-drawn frames.
_ALT_SCREEN_ON = "\033[?1049h"
_ALT_SCREEN_OFF = "\033[?1049l"
_HOME_AND_CLEAR = "\033[H\033[J"
_HIDE_CURSOR = "\033[?25l"
_SHOW_CURSOR = "\033[?25h"


def _read_key(timeout: float) -> str:
    """One keypress, or "" if none arrived within `timeout`.

    Uses termios directly rather than select+sys.stdin.read(1): in cbreak
    mode a read returns as soon as a byte is available, which is what makes
    the redraw timer responsive.
    """
    import select
    try:
        if not select.select([sys.stdin], [], [], timeout)[0]:
            return ""
        return sys.stdin.read(1) or ""
    except (OSError, ValueError):
        return ""


class _RawTerminal:
    """cbreak mode + alternate screen, restored on the way out.

    A context manager because every one of these has to be undone, and the
    paths that forget — ^C, an exception mid-frame, a broken pipe — are
    exactly the ones that leave a terminal unusable.
    """

    def __init__(self, stream=None):
        self._stream = stream or sys.stdout
        self._saved: list[Any] = []
        self._entered = False

    def __enter__(self):
        import termios
        import tty
        try:
            self._saved = termios.tcgetattr(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            self._entered = True
        except Exception:
            # Not a tty, or a platform without termios. Callers check
            # isatty() first; this is the belt to that suspenders.
            self._entered = False
        self._stream.write(_ALT_SCREEN_ON + _HIDE_CURSOR)
        self._stream.flush()
        return self

    def __exit__(self, *exc: Any) -> bool:
        self._stream.write(_SHOW_CURSOR + _ALT_SCREEN_OFF)
        self._stream.flush()
        if self._entered:
            import termios
            try:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._saved)
            except Exception:
                pass
        return False


def run(
    client: Any,
    *,
    interval: float = 1.0,
    stream: Any = None,
    once: bool = False,
) -> int:
    """Draw the console until the user quits. Returns a process exit code."""
    stream = stream or sys.stdout

    def fetch() -> dict[str, Any]:
        return client.get("/v1/admin/overview")

    # Not a terminal — a pipe, a file, CI. Draw one frame and leave, so
    # `haldir top > snapshot.txt` and a smoke test both do something useful
    # instead of hanging on a keypress that will never come.
    if once or not sys.stdin.isatty():
        stream.write(render_frame(fetch(), width=_terminal_width()) + "\n")
        stream.flush()
        return 0

    interval = max(0.25, min(60.0, interval))
    paused = False
    status = ""
    overview: dict[str, Any] = {}

    with _RawTerminal(stream):
        while True:
            if not paused:
                try:
                    overview = fetch()
                    status = ""
                except SystemExit:
                    # APIClient exits on a transport error. Losing the
                    # connection should not close the console — the operator
                    # wants to see the last good state and the error, and
                    # keep trying.
                    status = "API unreachable — retrying; last good frame shown"
                except Exception as e:  # noqa: BLE001
                    status = f"{type(e).__name__}: {e}"

            frame = render_frame(
                overview, width=_terminal_width(), paused=paused, status_line=status
            )
            stream.write(_HOME_AND_CLEAR + frame + "\n")
            stream.flush()

            key = _read_key(interval)
            if key in ("q", "Q", "\x03", "\x04"):   # q, ^C, ^D
                return 0
            if key in ("p", "P", " "):
                paused = not paused
            elif key == "+":
                interval = min(60.0, interval * 2)
                status = f"refresh every {interval:.1f}s"
            elif key == "-":
                interval = max(0.25, interval / 2)
                status = f"refresh every {interval:.1f}s"
            elif key in ("r", "R"):
                target = _prompt(stream, "  session id to revoke: ")
                if target:
                    status = _revoke(client, target.strip())
            elif key == "\x0c":                      # ^L
                pass                                 # redraw happens anyway


def _terminal_width(default: int = 78) -> int:
    try:
        return max(48, __import__("shutil").get_terminal_size((default, 24)).columns)
    except Exception:
        return default


def _prompt(stream: Any, label: str) -> str:
    """Read a line with the console still running underneath.

    Deliberately simple: the alternative is a full line editor, and the only
    thing typed here is a session id.
    """
    stream.write(_SHOW_CURSOR + "\033[H\033[J" + label)
    stream.flush()
    buf: list[str] = []
    while True:
        ch = _read_key(30.0)
        if not ch or ch in ("\r", "\n"):
            break
        if ch in ("\x7f", "\b"):
            if buf:
                buf.pop()
                stream.write("\b \b")
                stream.flush()
            continue
        if ch == "\x1b" or ch == "\x03":
            break
        buf.append(ch)
        stream.write(ch)
        stream.flush()
    stream.write(_HIDE_CURSOR)
    return "".join(buf)


def _revoke(client: Any, session_id: str) -> str:
    """Kill a session, cascading to its subagents.

    Cascade is not optional here for the same reason it is not optional on
    the dashboard: revoking an orchestrator while its children keep live
    credentials leaves the thing you were trying to stop still running.
    """
    try:
        out = client.delete(
            f"/v1/sessions/{session_id}", params={"cascade": "true"}
        )
    except SystemExit:
        return f"revoke failed — could not reach the API for {session_id}"
    except Exception as e:  # noqa: BLE001
        return f"revoke failed ({type(e).__name__}): {e}"
    if not out:
        return f"revoke failed for {session_id}"
    killed = out.get("cascade_revoked") or []
    return (f"revoked {session_id}" +
            (f" and {len(killed)} subagent session(s)" if killed else ""))
