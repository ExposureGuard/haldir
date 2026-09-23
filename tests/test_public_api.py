"""
The public import surface.

Every published example — the README, the integration READMEs, six blog posts,
the CHANGELOG, the SDK's own docstring — tells users to write
`from haldir import ...`. Nothing checked that, and it did not work: the
distribution is named `haldir` but shipped no module by that name, so each of
those examples raised ModuleNotFoundError on its first line.

The test that came closest to catching it lived in test_webhook_delivery.py
and only did `import sdk` while its docstring claimed to check the public
name. A test that describes one thing and asserts another is worse than no
test: it reports as coverage.

This file is the guard, and it is a guard rather than three literal imports
because haldir.py's export list is maintained by hand. Anything `sdk` gains
and `haldir` does not is a name the documentation may already promise.

Run: python -m pytest tests/test_public_api.py -v
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import haldir  # noqa: E402
import sdk  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_the_public_module_exports_everything_sdk_does() -> None:
    """The list in haldir.py is hand-maintained, so it can fall behind."""
    missing = sorted(set(sdk.__all__) - set(haldir.__all__))
    assert not missing, (
        f"sdk exports these and the public module does not: {missing}. "
        f"Add each to haldir.py's import block and its __all__."
    )


def test_the_public_names_are_the_same_objects() -> None:
    """Identity, not equality.

    A re-export written as a wrapper — or shadowed by a local definition —
    passes an import test and then drifts from the implementation it claims
    to be. `is` is the assertion that cannot be satisfied by a copy.
    """
    for name in sdk.__all__:
        assert getattr(haldir, name) is getattr(sdk, name), (
            f"haldir.{name} is not the same object as sdk.{name}; one of them "
            f"is a copy and the two can now diverge"
        )


def test_the_imports_the_documentation_uses_all_resolve() -> None:
    """Verbatim from the published prose, so a doc edit that invents a name
    fails here rather than in a reader's terminal."""
    from haldir import HaldirClient, HaldirPermissionError  # noqa: F401
    from haldir import (  # noqa: F401
        verify_inclusion_proof,
        verify_consistency_proof,
        verify_sth,
    )
    from haldir import verify_webhook_signature  # noqa: F401


def test_the_public_module_is_importable_by_its_distribution_name() -> None:
    """The bug in one line: the distribution is `haldir`, so the import must
    be `haldir`. If this fails, `pip install haldir` shipped something users
    cannot import by the name the docs use."""
    assert haldir.__name__ == "haldir"


# ── The assets, read rather than listed ─────────────────────────────────
#
# `test_the_imports_the_documentation_uses_all_resolve` above is a hand-written
# list, so it only checks the names somebody remembered to add. The quickstart
# animation — the first thing on the README, and the top of /demo — told
# readers `from haldir import Haldir` for two releases. No test read it, so the
# sweep that fixed every other surface walked straight past the most-seen one.
#
# These read the assets instead of a list.

_ASSETS = (
    "demo/gen_quickstart.py",   # the animation's source
    "demo/quickstart.svg",      # and its generated form
    "README.md",
    "quickstart.html",
)


def _names_imported_from_haldir(text: str) -> set[str]:
    names: set[str] = set()
    pattern = r"from\s+haldir\s+import\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)"
    for m in re.finditer(pattern, text):
        names |= {n.strip() for n in m.group(1).split(",") if n.strip()}
    return names


def test_the_asset_scanner_can_actually_fail() -> None:
    """A guard that cannot fail is not a guard.

    This feeds the scanner the exact line the animation shipped, so the tests
    below are known to be reading something rather than passing vacuously.
    """
    names = _names_imported_from_haldir(
        ">>> from haldir import Haldir\n>>> h = Haldir()"
    )
    assert names == {"Haldir"}, f"scanner did not read the line: {names!r}"
    assert not hasattr(haldir, "Haldir"), (
        "haldir now exports `Haldir` — update this test to a name that does "
        "not exist, or it stops proving anything"
    )


def test_every_name_the_assets_import_from_haldir_exists() -> None:
    found: dict[str, set[str]] = {}
    for rel in _ASSETS:
        path = os.path.join(_ROOT, rel)
        if os.path.exists(path):
            names = _names_imported_from_haldir(open(path, encoding="utf-8").read())
            if names:
                found[rel] = names

    assert found, (
        "no `from haldir import ...` found in any asset — the file list in "
        "this test has gone stale and it is now checking nothing"
    )

    missing = {
        rel: sorted(names - set(dir(haldir)))
        for rel, names in found.items()
        if names - set(dir(haldir))
    }
    assert not missing, (
        f"these assets import names the package does not export: {missing}. "
        f"Anyone who copies the example gets ImportError on the first line — "
        f"which is what the whole file above was written about."
    )
