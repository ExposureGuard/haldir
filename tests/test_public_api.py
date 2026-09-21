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
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import haldir  # noqa: E402
import sdk  # noqa: E402


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
