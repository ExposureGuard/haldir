"""
Generate demo/quickstart.svg — the animated terminal GIF that opens the
README. SVG rather than GIF because:

  - Text source checks into git (diffable, reviewable, regeneratable)
  - Crisp at any zoom (vector)
  - Smaller than a comparable GIF (~8 KB vs ~800 KB)
  - Renders on github.com without external tooling

The animation is driven by CSS @keyframes: every line starts at
opacity 0, fades to 1 at its scheduled offset, and stays visible for
the rest of the loop. A blinking caret sits at the most-recently-
revealed line.

Re-run after editing the script:
    python demo/gen_quickstart.py
    # writes demo/quickstart.svg

No runtime dependencies.
"""

from __future__ import annotations

import os


def _package_version() -> str:
    """The version this animation advertises, read from pyproject.toml.

    Read rather than written here. The hardcoded "haldir-0.3.0" this
    replaced was two releases stale by the time anyone looked, and this SVG
    is the first thing a visitor to the README sees — an install line that
    names a version nobody can get is a poor first sentence.

    Parsed by hand rather than with tomllib, which is 3.11+ while this
    package supports 3.10.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "pyproject.toml"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("version"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise RuntimeError("no version line in pyproject.toml")


VERSION = _package_version()


# ── Script ─────────────────────────────────────────────────────────────
#
# Each entry is (delay_seconds_from_start, kind, text).
#
#   kind "prompt"  → shell prompt line, green `$`
#   kind "output"  → plain text, slightly dimmer
#   kind "comment" → grey, italic (shell comment)
#   kind "repl"    → Python REPL input, cyan `>>>`
#   kind "result"  → REPL return value, yellow
#   kind "blank"   → empty spacer line
#
# Every line below was run against a live instance and pasted back. The
# script this replaced imported a class named `Haldir` that has never
# existed, and printed a `chain_verified` field the response does not
# contain, so a reader who copied it failed on the first line.
#
# Spelled that way on purpose: it is what the fix was, not an example to
# copy. `tests/test_public_api.py` reads this file for importable names and
# would rightly flag the literal version of it.
#
FRAMES: list[tuple[float, str, str]] = [
    (0.0,  "prompt",  "pip install haldir"),
    (0.6,  "output",  f"Successfully installed haldir-{VERSION}"),
    (1.4,  "blank",   ""),
    (1.8,  "prompt",  "export HALDIR_API_KEY=hld_..."),
    (2.6,  "blank",   ""),
    (3.0,  "prompt",  "python"),
    (3.5,  "repl",    "from haldir import HaldirClient"),
    (4.2,  "repl",    'h = HaldirClient(api_key="hld_...",'),
    (4.5,  "repl",    '                   base_url="http://127.0.0.1:8000")'),
    (5.2,  "repl",    's = h.create_session("my-agent",'),
    (5.5,  "repl",    '    scopes=["read", "execute"],'),
    (5.8,  "repl",    '    spend_limit=5.00)'),
    (6.6,  "repl",    's["session_id"]'),
    (7.0,  "result",  "'ses_abc123def456'"),
    (7.8,  "blank",   ""),
    (8.2,  "comment", "# Every agent call: check -> act -> log"),
    (9.0,  "repl",    'h.check_permission(s["session_id"], "execute")'),
    (9.7,  "result",  "{'allowed': True, 'scope': 'execute'}"),
    (10.6, "blank",   ""),
    (11.0, "repl",    'h.log_action(s["session_id"], "stripe",'),
    (11.3, "repl",    '             "charge", 0.50)'),
    (12.1, "result",  "{'entry_id': 'aud_789', 'logged': True}"),
    (12.9, "blank",   ""),
    (13.3, "comment", "# Audit trail is tamper-evident. Spend is capped."),
    (14.1, "comment", "# Your agent is governed."),
]

LOOP_SECONDS = 18.0           # one full cycle before restart
CHAR_WIDTH   = 8              # monospace cell width in px
LINE_HEIGHT  = 20             # line height in px
TOP_PAD      = 56             # space for the window chrome
LEFT_PAD     = 22
WIDTH        = 780
HEIGHT       = TOP_PAD + LINE_HEIGHT * (len(FRAMES) + 1) + 16


# ── Style per kind ─────────────────────────────────────────────────────

KIND_STYLE = {
    "prompt":  ("#e8e8e8", "$ "),
    "output":  ("#aab7bd", ""),
    "comment": ("#6a6a6a", ""),
    "repl":    ("#e8e8e8", ">>> "),
    "result":  ("#d4b86a", ""),
    "blank":   ("#ffffff", ""),
}


# ── SVG assembly ───────────────────────────────────────────────────────

def _escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
    )


def build_svg() -> str:
    out: list[str] = []
    out.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {WIDTH} {HEIGHT}" width="{WIDTH}" height="{HEIGHT}" '
        f'role="img" aria-label="Haldir quickstart: install, create session, check, log">'
    )

    # ── Style block (once) ───────────────────────────────────────────
    anim_rules: list[str] = []
    for i, (t, _, _) in enumerate(FRAMES):
        pct_reveal = (t / LOOP_SECONDS) * 100
        # Hold visible from reveal through end of loop (98%), then fade
        # back to 0 for the restart.
        anim_rules.append(
            f"@keyframes reveal-{i} {{"
            f"0% {{opacity:0}}"
            f"{pct_reveal:.2f}% {{opacity:0}}"
            f"{min(pct_reveal + 0.1, 99.99):.2f}% {{opacity:1}}"
            f"98% {{opacity:1}}"
            f"100% {{opacity:0}}"
            f"}}"
        )
        anim_rules.append(
            f".line-{i} {{animation: reveal-{i} {LOOP_SECONDS}s infinite;}}"
        )

    out.append(
        "<style>"
        ".bg{fill:#0a0a0a}"
        ".chrome{fill:#171717}"
        ".title{fill:#5a5a5a;font:12px -apple-system,BlinkMacSystemFont,sans-serif}"
        ".dot-r{fill:#ff5f57}.dot-y{fill:#ffbd2e}.dot-g{fill:#28ca42}"
        ".code{font:14px 'SF Mono','Cascadia Code',Menlo,Monaco,Consolas,monospace}"
        ".sigil-prompt{fill:#28ca42;font-weight:600}"
        ".sigil-repl{fill:#4ea3e0;font-weight:600}"
        ".k-comment{font-style:italic}"
        ".line{opacity:0}"
        + "".join(anim_rules)
        + "</style>"
    )

    # ── Background + window chrome ───────────────────────────────────
    out.append(f'<rect class="bg" width="{WIDTH}" height="{HEIGHT}" rx="8"/>')
    out.append(f'<rect class="chrome" width="{WIDTH}" height="36" rx="8"/>')
    out.append(f'<rect class="chrome" y="20" width="{WIDTH}" height="16"/>')
    out.append('<circle class="dot-r" cx="18" cy="18" r="6"/>')
    out.append('<circle class="dot-y" cx="38" cy="18" r="6"/>')
    out.append('<circle class="dot-g" cx="58" cy="18" r="6"/>')
    out.append(
        f'<text class="title" x="{WIDTH // 2}" y="23" text-anchor="middle">'
        "haldir-quickstart</text>"
    )

    # ── Body lines ──────────────────────────────────────────────────
    for i, (_, kind, text) in enumerate(FRAMES):
        color, sigil = KIND_STYLE[kind]
        y = TOP_PAD + LINE_HEIGHT * (i + 1)
        cls = f"line line-{i} k-{kind} code"
        sigil_class = ""
        if kind == "prompt":
            sigil_class = "sigil-prompt"
        elif kind == "repl":
            sigil_class = "sigil-repl"
        sigil_span = (
            f'<tspan class="{sigil_class}">{_escape(sigil)}</tspan>'
            if sigil else ""
        )
        out.append(
            f'<text class="{cls}" x="{LEFT_PAD}" y="{y}" fill="{color}">'
            f"{sigil_span}{_escape(text)}"
            "</text>"
        )

    # ── Blinking caret that trails the last revealed line ────────────
    # Approximated by a small rect that is hidden/shown in time with
    # the final frame, blinking via its own keyframes.
    final_t, _, final_text = FRAMES[-1]
    caret_y = TOP_PAD + LINE_HEIGHT * len(FRAMES) - 14
    caret_x = LEFT_PAD + CHAR_WIDTH * (len(final_text) + 0)
    caret_reveal_pct = (final_t / LOOP_SECONDS) * 100
    out.append(
        "<style>"
        "@keyframes blink{0%,50%{opacity:1}51%,100%{opacity:0}}"
        f"@keyframes caret-appear{{0%{{opacity:0}}{caret_reveal_pct:.2f}%{{opacity:0}}"
        f"{min(caret_reveal_pct + 0.1, 99.99):.2f}%{{opacity:1}}98%{{opacity:1}}100%{{opacity:0}}}}"
        ".caret{"
        f"animation: caret-appear {LOOP_SECONDS}s infinite,"
        "           blink 1s infinite steps(1);"
        "}"
        "</style>"
    )
    out.append(
        f'<rect class="caret" x="{caret_x}" y="{caret_y}" '
        f'width="8" height="16" fill="#e8e8e8"/>'
    )

    out.append("</svg>")
    return "\n".join(out)


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "quickstart.svg")
    with open(path, "w") as f:
        f.write(build_svg())
    print(f"wrote {path} ({os.path.getsize(path)} bytes)")


if __name__ == "__main__":
    main()
