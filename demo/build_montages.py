#!/usr/bin/env python3
"""
Compose README's montage images from the captured screenshots.

Same reasoning as ``capture.py``: these composites drifted from the product
because they were assembled by hand. The "annotated dashboard" shipped for
months as a sign-in page with labels pointing at empty black space, and the
"before/after" had four bullets in a box with a large dead band beneath them.

Building them from the real screenshots, in a browser, keeps them consistent
with whatever ``capture.py`` last captured and makes the layout reviewable as
CSS rather than as pixels.

Usage
-----
    python3 demo/build_montages.py                  # all of them
    python3 demo/build_montages.py --only quick_tour

Run ``capture.py`` first — this reads its output rather than taking its own
screenshots. Requires Chrome/Chromium, which capture.py already needs.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

DEMO = Path(__file__).resolve().parent
SHOTS = DEMO / "screenshots"

# The product's own palette, lifted from the landing page and cloud dashboard
# CSS so these composites read as the same product rather than as marketing
# material bolted on beside it.
GOLD = "#b8973a"
GREEN = "#6bbd6b"
RED = "#e87b7b"
W = "#e0ddd5"
BG = "#050505"

BASE_CSS = f"""
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    background: {BG}; color: {W}; width: fit-content;
    font-family: 'Inter', -apple-system, 'DejaVu Sans', sans-serif;
    -webkit-font-smoothing: antialiased;
  }}
  .mono {{ font-family: 'IBM Plex Mono', 'DejaVu Sans Mono', monospace; }}
  img {{ display:block; }}
"""


def chrome() -> str:
    for c in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
        found = shutil.which(c)
        if found:
            return found
    sys.exit("[-] No Chrome/Chromium on PATH.")


def render(html: str, out: Path, width: int, height: int, scale: int = 2) -> bool:
    """Lay out `html` in headless Chrome at an exact size and screenshot it.

    The viewport is fixed rather than full-page so each composite has a
    predictable aspect ratio — the previous montages were letterboxed into
    canvases far larger than their content, which is what left the dead space.
    """
    page = DEMO / f".{out.stem}.html"
    page.write_text(
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<style>{BASE_CSS}</style></head><body>{html}</body></html>"
    )
    try:
        subprocess.run(
            [
                chrome(), "--headless", "--disable-gpu", "--no-sandbox",
                "--hide-scrollbars",
                "--force-device-scale-factor=" + str(scale),
                f"--window-size={width},{height}",
                "--virtual-time-budget=4000",
                f"--screenshot={out}",
                page.resolve().as_uri(),
            ],
            capture_output=True, timeout=90, check=False,
        )
    finally:
        page.unlink(missing_ok=True)
    ok = out.exists() and out.stat().st_size > 2000
    print(f"    {'[+]' if ok else '[-]'} {out.name}  {width}x{height} @{scale}x")
    return ok


def need(name: str) -> str:
    """Path to a captured screenshot, failing early if capture.py hasn't run."""
    p = SHOTS / name
    if not p.exists():
        sys.exit(f"[-] missing {p.relative_to(DEMO.parent)} — run demo/capture.py first")
    return f"screenshots/{name}"


# ── before / after ────────────────────────────────────────────────────────

def build_before_after() -> bool:
    """The conceptual comparison. Rendered as text, not captured from the UI,
    because there is no "without Haldir" page to screenshot — and the old
    version was a box of four bullets with a large empty band under it."""
    rows = [
        ("Any API, any scope",          "Scoped sessions, per action"),
        ("Spend whatever it wants",     "Per-session budget, enforced"),
        ("Reads secrets from env",      "Secrets in an encrypted vault"),
        ("No record of what happened",  "Hash-chained, tamper-evident audit"),
        ("No human in the loop",        "Approvals + webhook alerts"),
    ]
    left = "".join(
        f"<li><span class='x'>×</span>{a}</li>" for a, _ in rows
    )
    right = "".join(
        f"<li><span class='ok'>✓</span>{b}</li>" for _, b in rows
    )
    html = f"""
    <div style="display:flex;gap:2px;padding:2px;">
      <div style="flex:1;border:1px solid rgba(232,123,123,0.35);background:rgba(232,123,123,0.04);padding:26px 30px 30px;">
        <div class="mono" style="color:{RED};font-size:15px;letter-spacing:2.5px;font-weight:600;margin-bottom:6px;">WITHOUT HALDIR</div>
        <div style="color:rgba(224,221,213,0.4);font-size:12.5px;margin-bottom:20px;">Your agent has the keys to everything</div>
        <ul style="list-style:none;font-size:14px;line-height:2.15;color:rgba(224,221,213,0.72);">{left}</ul>
      </div>
      <div style="flex:1;border:1px solid rgba(107,189,107,0.35);background:rgba(107,189,107,0.04);padding:26px 30px 30px;">
        <div class="mono" style="color:{GREEN};font-size:15px;letter-spacing:2.5px;font-weight:600;margin-bottom:6px;">WITH HALDIR</div>
        <div style="color:rgba(224,221,213,0.4);font-size:12.5px;margin-bottom:20px;">Every call scoped, capped, and logged</div>
        <ul style="list-style:none;font-size:14px;line-height:2.15;color:rgba(224,221,213,0.88);">{right}</ul>
      </div>
    </div>
    <style>
      li {{ display:flex; gap:12px; align-items:baseline; }}
      .x  {{ color:{RED};  font-weight:700; width:14px; flex:none; }}
      .ok {{ color:{GREEN}; font-weight:700; width:14px; flex:none; }}
    </style>
    """
    return render(html, DEMO / "before_after.png", 1180, 330)


# ── quick tour ────────────────────────────────────────────────────────────

def build_quick_tour() -> bool:
    """Three screens, stacked with captions.

    Stacked rather than side by side: the previous version put three 1400x757
    screenshots into 300px-wide panels, which is why nothing in it was legible
    at README width.
    """
    # `keep` crops each screenshot to the height its content actually fills.
    # Every page is captured at a fixed 1400x900 viewport, but the landing
    # hero ends around 88% of that and the sessions table around 45% — leaving
    # the shortfall in makes the montage read as mostly empty boxes, which is
    # what the previous version looked like.
    steps = [
        ("01_landing.png", 0.88, "Landing page",
         "What the product is, in one screen."),
        ("04_cloud_overview.png", 0.56, "Cloud dashboard",
         "Tenant, tier, live counts, and your API keys."),
        ("06_cloud_audit.png", 0.70, "Audit trail",
         "Every tool call, filterable — expand any row for the MCP call details."),
    ]
    width = 1020
    full_h = width * 900 / 1400               # screenshots are 1400x900 at 1x
    cards = ""
    heights = []
    for name, keep, title, caption in steps:
        crop = int(full_h * keep)
        heights.append(crop)
        cards += f"""
        <div style="margin-bottom:30px;">
          <div style="display:flex;align-items:baseline;gap:12px;margin-bottom:11px;">
            <span style="color:{GOLD};font-size:15px;font-weight:600;">{title}</span>
            <span style="color:rgba(224,221,213,0.42);font-size:13px;">{caption}</span>
          </div>
          <div style="width:{width}px;height:{crop}px;overflow:hidden;
                      border:1px solid rgba(224,221,213,0.12);border-radius:3px;">
            <img src="{need(name)}" width="{width}">
          </div>
        </div>"""
    html = f"<div style='padding:30px 30px 6px;'>{cards}</div>"
    total = 30 + sum(h + 30 + 38 for h in heights) + 6
    return render(html, DEMO / "quick_tour.png", width + 60, total)


# ── annotated dashboard ───────────────────────────────────────────────────

def build_annotated() -> bool:
    """The overview with numbered markers and a legend underneath.

    Numbered pins plus a legend, rather than labels floating beside each
    element: the labels collided with the very UI they described (one sat on
    top of the "Account" heading), and positioning text over a page is how the
    previous version ended up with arrows pointing at empty black space.

    The screenshot is also cropped to its content. The page is captured at a
    fixed 1400x900 viewport, but the account view only fills the top half of
    it — leaving the bottom half empty was a large part of why the old
    montages looked so sparse.
    """
    shot = need("04_cloud_overview.png")
    width = 1300
    full_h = width * 900 / 1400
    keep = 0.54                      # the dashboard's content ends about here
    crop_h = int(full_h * keep)

    # (marker%, from-top%, label) — percentages of the *cropped* box.
    marks = [
        (6.5, 85, "Sidebar — every page is one click"),
        (20.0, 35, "Tenant, tier, and live counts at a glance"),
        (20.0, 63, "Your API keys, by prefix — the full key is never shown"),
        (82.5, 84, "Revoke a key without a shell into the database"),
    ]
    pins = ""
    for i, (left, top, _) in enumerate(marks, 1):
        pins += f"""
        <div style="position:absolute;left:{left}%;top:{top}%;transform:translate(-50%,-50%);
                    width:23px;height:23px;border-radius:50%;background:{GOLD};color:{BG};
                    font-size:12.5px;font-weight:700;display:flex;align-items:center;
                    justify-content:center;font-family:'IBM Plex Mono','DejaVu Sans Mono',monospace;
                    box-shadow:0 0 0 3px rgba(5,5,5,0.85);">{i}</div>"""

    legend = "".join(
        f"""<div style="display:flex;gap:11px;align-items:baseline;margin-bottom:7px;">
              <span style="color:{GOLD};font-weight:700;font-size:12.5px;width:12px;flex:none;">{i}</span>
              <span style="color:rgba(224,221,213,0.7);font-size:13.5px;">{label}</span>
            </div>"""
        for i, (_, _, label) in enumerate(marks, 1)
    )

    html = f"""
    <div style="padding:30px;">
      <div style="position:relative;width:{width}px;height:{crop_h}px;overflow:hidden;
                  border:1px solid rgba(224,221,213,0.12);border-radius:3px;">
        <img src="{shot}" width="{width}">
        {pins}
      </div>
      <div style="margin-top:20px;">{legend}</div>
    </div>
    """
    return render(html, DEMO / "annotated_dashboard.png", width + 60, crop_h + 190)


BUILDERS = {
    "before_after": build_before_after,
    "quick_tour": build_quick_tour,
    "annotated_dashboard": build_annotated,
}


def main() -> int:
    ap = argparse.ArgumentParser(description="Rebuild the README montages.")
    ap.add_argument("--only", action="append", default=[], choices=sorted(BUILDERS))
    args = ap.parse_args()

    targets = args.only or list(BUILDERS)
    print(f"[*] building {len(targets)} montage(s) into demo/")
    ok = sum(1 for name in targets if BUILDERS[name]())
    print(f"[+] {ok}/{len(targets)} built")
    return 0 if ok == len(targets) else 1


if __name__ == "__main__":
    raise SystemExit(main())
