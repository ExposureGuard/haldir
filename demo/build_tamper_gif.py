#!/usr/bin/env python3
"""
Build the tamper-detection GIF used as the README hero.

Haldir's whole claim is that the audit log is tamper-evident, and the product
already ships a live demo of exactly that at /demo/tamper: it renders a real
audit log, a real RFC 6962 Merkle root, and a signed tree head, then lets you
rewrite a log row and watch the verdict flip.

This drives that page through its own endpoints — GET /demo/tamper,
POST /demo/tamper/mutate, POST /demo/tamper/reset — and assembles the two
states into a short loop. Nothing is staged: the banner text, the row badge,
the cost and the root hash are all whatever the live app computes.

Usage
-----
    pip install Pillow
    python3 demo/build_tamper_gif.py

Requires Chrome/Chromium (as capture.py does) and Pillow for the GIF
assembly. Pillow belongs in requirements-dev.txt rather than
requirements.txt — nothing at runtime needs it.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from capture import find_chrome, free_port, shoot, start_server, wait_healthy  # noqa: E402

DEMO = Path(__file__).resolve().parent
OUT_PNG = DEMO / "hero_tamper.png"
OUT_GIF = DEMO / "hero_tamper.gif"

# The band worth showing: the verdict banner, the controls, the audit table
# with the rewritten row, and the top of the signed tree head whose root hash
# changes under it. Cropping off the preamble above keeps the loop focused and
# the file small.
#
# These are full-frame pixels from the 2800x1800 capture, not coordinates from
# a scaled-down view of it — sizing this from a preview is how the first
# attempt cut the banner off mid-sentence.
CROP = (400, 480, 2450, 1800)         # left, top, right, bottom
TARGET_W = 1160                        # output width; GitHub renders ~880px

STEP_MS = 1700                         # how long each state holds
FADE_STEPS = 4                         # frames spent cross-fading between states


def _post(base: str, path: str) -> None:
    """Drive one of the demo's own state endpoints. It 303s back to the page."""
    req = urllib.request.Request(base + path, method="POST", data=b"")
    try:
        urllib.request.urlopen(req, timeout=15).read()
    except urllib.error.HTTPError:
        pass  # the redirect target is fetched by the next screenshot anyway


def capture_states(base: str, chrome: str, tmp: Path) -> list[Path]:
    """Screenshot the page in each state, in the order the story runs."""
    frames: list[Path] = []
    script = [
        ("clean", "/demo/tamper/reset"),
        ("tampered", "/demo/tamper/mutate"),
        ("reset", "/demo/tamper/reset"),
    ]
    for name, action in script:
        _post(base, action)
        out = tmp / f"tamper_{name}.png"
        if not shoot(chrome, base + "/demo/tamper", out):
            sys.exit(f"[-] could not capture the {name} state")
        frames.append(out)
    return frames


def build_gif(frames: list[Path], out: Path) -> None:
    from PIL import Image

    cropped = []
    for p in frames:
        img = Image.open(p).convert("RGB").crop(CROP)
        h = int(img.height * TARGET_W / img.width)
        cropped.append(img.resize((TARGET_W, h), Image.LANCZOS))

    # Hold each state, then cross-fade into the next, so the change reads as a
    # transition rather than a jump cut. The fade is what makes the root hash
    # visibly swap instead of blinking.
    sequence = []
    for i, img in enumerate(cropped):
        sequence.extend([img] * 2)
        nxt = cropped[(i + 1) % len(cropped)]
        if nxt is not img:
            for step in range(1, FADE_STEPS):
                sequence.append(Image.blend(img, nxt, step / FADE_STEPS))

    # One palette for the whole loop: re-quantising per frame makes the dark
    # background shimmer, which is very visible on a nearly-black UI.
    palette = sequence[0].quantize(colors=128, method=Image.MEDIANCUT)
    quantised = [f.quantize(palette=palette, dither=Image.NONE) for f in sequence]

    quantised[0].save(
        out,
        save_all=True,
        append_images=quantised[1:],
        duration=STEP_MS // 2,
        loop=0,
        optimize=True,
        disposal=1,
    )
    size = out.stat().st_size
    print(f"    [+] {out.name}  {quantised[0].width}x{quantised[0].height}, "
          f"{len(quantised)} frames, {size / 1024:.0f} KB")


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the tamper-detection hero GIF.")
    ap.add_argument("--png-only", action="store_true",
                    help="also keep a still of the tampered state (a GIF fallback "
                         "for places that don't animate)")
    args = ap.parse_args()

    chrome = find_chrome()
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    tmp = Path("/tmp/haldir_hero")
    tmp.mkdir(exist_ok=True)

    print(f"[*] booting a scratch instance on {base}")
    proc = start_server(port)
    try:
        if not wait_healthy(base):
            print("[-] instance never became healthy")
            return 1
        states = capture_states(base, chrome, tmp)
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass

    print("[*] assembling")
    build_gif(states, OUT_GIF)

    if args.png_only:
        from PIL import Image
        img = Image.open(states[1]).convert("RGB").crop(CROP)
        h = int(img.height * TARGET_W / img.width)
        img.resize((TARGET_W, h), Image.LANCZOS).save(OUT_PNG, optimize=True)
        print(f"    [+] {OUT_PNG.name}  {img.width}x{img.height}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
