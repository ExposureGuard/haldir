#!/usr/bin/env python3
"""
Build the one-file demo binary.

    python build_demo.py

Produces `dist/haldir-demo` (`haldir-demo.exe` on Windows): Python, Haldir and
the served content in one file, so a tester needs nothing installed.

Written in Python rather than shell for one reason that matters at build time:
PyInstaller's `--add-data` separator is `:` on POSIX and `;` on Windows. A
build script that hardcodes either one silently produces a wheel-sized archive
of nothing on the other platform — the add-data entries are just skipped when
the separator does not match. `os.pathsep` is the same value PyInstaller is
using, so this cannot differ.

Run from the repository root. Requires `pip install pyinstaller` and the
package's own dependencies.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

# Content the app reads off disk with a bare open() relative to the package
# directory. Without these the bundled copy answers 404 where a checkout
# serves pages — the same failure the 0.3.0 wheel shipped.
DATA_DIRS = ("landing", "demo", "blog", "docs", ".well-known")
DATA_FILES = (
    "llms.txt", "llms-full.txt", "robots.txt", "sitemap.xml", "ai-plugin.json",
    "AGENTS.md", "THREAT_MODEL.md", "SECURITY.md", "HOW_IT_WORKS.md",
    "SELF_HOSTING.md", "CONTRIBUTING.md", "CHANGELOG.md", "DEMO.md", "CLI.md",
    "dashboard.html", "dashboard.js", "demo_gallery.html", "quickstart.html",
)

# Imported dynamically somewhere PyInstaller's static analysis cannot see, or
# reached through a string. Named explicitly so the bundle is complete.
HIDDEN_IMPORTS = (
    "cli", "api", "haldir_probes", "haldir_mcp_server", "demo_quickstart",
)
COLLECT_SUBMODULES = ("haldir_gate", "haldir_vault", "haldir_watch", "sdk")


def main() -> int:
    sep = os.pathsep          # ':' on POSIX, ';' on Windows — same as PyInstaller
    args: list[str] = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--noconfirm", "--clean",
        "--name", "haldir-demo",
        "--distpath", os.path.join(ROOT, "dist"),
        "--workpath", os.path.join(ROOT, "build", "pyinstaller"),
        "--specpath", os.path.join(ROOT, "build"),
    ]

    for name in COLLECT_SUBMODULES:
        args += ["--collect-submodules", name]
    for name in HIDDEN_IMPORTS:
        args += ["--hidden-import", name]

    added = 0
    for d in DATA_DIRS:
        src = os.path.join(ROOT, d)
        if os.path.isdir(src):
            args += ["--add-data", f"{src}{sep}{d}"]
            added += 1
    for f in DATA_FILES:
        src = os.path.join(ROOT, f)
        if os.path.isfile(src):
            args += ["--add-data", f"{src}{sep}."]
            added += 1

    # A build that added nothing produces a binary that starts and then 404s
    # every page, which looks like an application bug rather than a build one.
    if added < len(DATA_DIRS):
        print(f"[-] only {added} data entries found; expected at least "
              f"{len(DATA_DIRS)} directories. Run this from the repo root and "
              f"check the checkout is complete.", file=sys.stderr)
        return 1

    args.append(os.path.join(ROOT, "demo_quickstart.py"))

    print(f"[*] building for {sys.platform} ({added} data entries)", flush=True)
    r = subprocess.run(args, cwd=ROOT)
    if r.returncode != 0:
        return r.returncode

    out = os.path.join(ROOT, "dist", "haldir-demo")
    if os.name == "nt":
        out += ".exe"
    if not os.path.exists(out):
        print(f"[-] expected {out} and it is not there", file=sys.stderr)
        return 1

    size = os.path.getsize(out) / (1024 * 1024)
    print(f"[+] {out}  ({size:.1f} MB)")

    # Keep the tree clean: the spec dir and work dir are intermediates.
    for junk in ("build", "haldir-demo.spec"):
        p = os.path.join(ROOT, junk)
        if os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
        elif os.path.isfile(p):
            os.remove(p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
