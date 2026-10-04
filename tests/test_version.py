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

import pytest

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
        # The public module. `haldir.__version__` is what a user reads off
        # before writing a bug report, so it disagreeing with the package is
        # the same failure this test exists to prevent.
        "haldir.py":            r'^__version__ = "([^"]+)"',
        # The quickstart animation. It opens the README and sits at the top of
        # /demo, and it advertised `haldir-0.3.0` for two releases — an install
        # line naming a version nobody could get. It is now generated from
        # pyproject.toml, and this asserts the generated file was regenerated
        # rather than edited by hand.
        "demo/quickstart.svg":  r"haldir-([0-9][0-9.]*)",
        # The marketing page's schema.org block — what a crawler reads to
        # learn which version this is. It sat at 0.3.0 through 0.3.1 and
        # 0.3.2 with nothing comparing it, because every discovery-surface
        # pattern above points at `.well-known/` and this one is not there.
        "landing/index.html":   r'"softwareVersion":\s*"([^"]+)"',
        # The official MCP registry entry — the file an MCP client reads to
        # decide what it can install. It was published to the registry once,
        # in April, at 0.1.0, and stayed there for six releases while the
        # package moved to 0.4.x, because nothing compared the two. The
        # workflow that republishes it is
        # `.github/workflows/publish-mcp-registry.yml`; this pattern is what
        # keeps the file it publishes honest in the meantime.
        "server.json":          r'^  "version": "([^"]+)"',
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


def test_the_cli_answers_which_version(capsys: pytest.CaptureFixture[str]) -> None:
    """The first question in any bug report, asked from a terminal.

    Every other surface states the version — the module, the MCP banner, the
    OpenAPI default, the webhook User-Agent, the tracer name — and the one a
    person actually types did not: `haldir --version` was "unrecognized
    arguments". It was found by installing the published wheel and using it,
    which is the only place it shows: importing the library was always right.

    The CLI imports `haldir.__version__` rather than repeating the literal, so
    this asserts the wiring rather than a fifth copy of the number.
    """
    import cli

    with pytest.raises(SystemExit) as exit_info:
        cli.build_parser().parse_args(["--version"])
    assert exit_info.value.code == 0, (
        "`haldir --version` exited non-zero; argparse's version action exits 0"
    )

    printed = capsys.readouterr().out.strip()
    assert _package_version() in printed, (
        f"`haldir --version` printed {printed!r}, which does not contain the "
        f"package version {_package_version()!r}"
    )


# Version-looking strings in api.py that are deliberately not this product's
# version. The Prometheus text exposition format carries its own version
# number, and it appears twice — in the docstring and in the Content-Type
# header of /metrics. Those two are not claims about Haldir.
_NOT_THIS_PRODUCTS_VERSION = {"0.0.4"}


def test_every_version_literal_in_api_py_matches() -> None:
    """All of them, not the first.

    `_stated_versions` above uses `re.search`, so it can only ever see the
    first literal in a file. api.py states the version four times — the MCP
    server handshake, /healthz, /v1, and the landing fallback — so the helper
    was structurally unable to notice the other three.

    All four sat at 0.1.0 while the package was 0.3.2. An MCP client doing its
    handshake, an operator curling /healthz before opening a support thread,
    and anyone reading /v1 were each told a version three releases old — which
    is the exact conversation this file opens by describing.
    """
    want = _package_version()
    src = _read("api.py")

    # Every `"version": "x"` — the JSON surfaces.
    found = set(re.findall(r'"version":\s*"([^"]+)"', src))
    assert found, "no version literals found in api.py — the pattern needs updating"

    # And every other version-looking string, because the JSON-key pattern
    # cannot see one written into a page. The `/docs` subtitle read
    # "v0.1.0 — the guardian layer for AI agents" for six releases while this
    # test passed, on the page the CLI prints as the API reference.
    #
    # The pattern excludes a match that is part of a longer dotted run, so an
    # address like 0.0.0.0 is not a version.
    found |= set(re.findall(r"(?<![\d.])v?(\d+\.\d+\.\d+)(?![\d.])", src))
    found -= _NOT_THIS_PRODUCTS_VERSION

    wrong = sorted(v for v in found if v != want)
    assert not wrong, (
        f"api.py states the version as {wrong} but the package is {want!r}. "
        f"A version string on a page or in a payload is a claim about this "
        f"release; anything else here is drift."
    )
