"""
One version, stated in five places, must be five identical strings.

The version is written down in pyproject.toml, the OpenAPI default, the MCP
server banner, the webhook User-Agent, and the tracing tracer name. Nothing
compared them, so a bump could update the package and leave the others
claiming the previous release — which is how a support conversation starts
with "which version are you on" and gets four different answers.

This is the same drift that let Pro be 25 agents on one page and 10 in the
code; a version is just another constant that lives in more than one file.
The real fix is one definition that the rest import, and this test is what
makes the duplication safe until that happens.

Run: python -m pytest tests/test_version.py -v
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel: str) -> str:
    return open(os.path.join(_ROOT, rel), encoding="utf-8").read()


def _package_version() -> str:
    m = re.search(r'^version = "([^"]+)"', _read("pyproject.toml"), re.M)
    assert m, "pyproject.toml has no version"
    return m.group(1)


def _stated_versions() -> dict[str, str]:
    """Every other place the version is written as a literal."""
    found: dict[str, str] = {}
    patterns = {
        # The machine-readable discovery surface. These are what an agent or
        # a registry reads to work out what Haldir is and which version it
        # is talking to, and they had drifted to four different answers
        # (0.1.0, 0.2.0, 0.3.1, 0.3.1) across four files.
        # The FIRST version field only — agent.json lists integration packages
        # further down, each with its own independent version, and a
        # pattern without re.M would happily compare those instead.
        ".well-known/agent.json":              r'^  "version": "([^"]+)"',
        ".well-known/mcp/server-card.json":    r'"version": "([^"]+)"',
        ".well-known/mcp/mcp.json":            r'"version": "([^"]+)"',
        "haldir_openapi.py":    r'version: str = "([^"]+)"',
        "haldir_mcp_server.py": r'SERVER_VERSION = "([^"]+)"',
        "haldir_watch/webhooks.py": r'Haldir/([0-9][^"]*)',
        "haldir_tracing.py":    r'"haldir", "([^"]+)"',
    }
    for rel, pat in patterns.items():
        m = re.search(pat, _read(rel), re.M)
        if m:
            found[rel] = m.group(1)
    return found


def test_every_stated_version_matches_the_package() -> None:
    want = _package_version()
    stated = _stated_versions()
    assert stated, "no version literals found — the patterns in this test need updating"
    wrong = {f: v for f, v in stated.items() if v != want}
    assert not wrong, (
        f"pyproject.toml says {want!r} but these say otherwise: {wrong}. A "
        f"bump that misses one leaves a component reporting the previous "
        f"release."
    )


def test_the_version_looks_like_a_release() -> None:
    """A stray dev suffix or a missing digit makes the tag and the artifact
    disagree, and PyPI rejects the upload after the tag is already public."""
    v = _package_version()
    assert re.fullmatch(r"\d+\.\d+\.\d+", v), f"version {v!r} is not X.Y.Z"
