"""The configuration reference is complete, or this fails.

`.env.example` documented eight of the forty-six `HALDIR_*` names the code
reads; the rest were discoverable only by grepping the modules that use them.
That is the same failure as a stale version literal or a missing packaging
entry — a fact that lives in one place and is checked in none — so this scans
the tree the way a reader would have to, and fails when a variable is read but
not listed in `CONFIGURATION.md`.

Only the code → documentation direction is enforced. The reverse would fail
legitimately: a variable can be documented in the release that adds it while
this branch does not read it yet, and a reference that mentions a name ahead
of its code is not a defect.

`tests/` is skipped: it sets variables to exercise code paths, and a name only
a test mentions is not configuration.

Run: python -m pytest tests/test_configuration_docs.py -v
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "CONFIGURATION.md"

# Directories that are not the shipped product: test code, vendored trees,
# build output, and a checkout's own virtualenv if one lives inside the repo.
_SKIP_DIRS = {
    ".git", "tests", "node_modules", "venv", ".venv",
    "build", "dist", "__pycache__", ".mypy_cache", ".pytest_cache",
}

# A variable name that stands alone as a string literal: `os.environ.get("X")`,
# `os.environ["X"]`, and module constants that hold a name for a later lookup
# (`ALLOW_PRIVATE_ENV = "X"`, then `os.environ.get(var)`). Requiring the quotes
# on both sides is what keeps this honest: a name inside a longer message
# ("set X to enable") is prose, and a Python identifier that happens to look
# like a variable (`from haldir import __version__ as HALDIR_VERSION`) is not
# configuration. Both were false positives the first time this ran.
_NAME_IN_CODE = re.compile(r"""["'](HALDIR_[A-Z0-9_]+)["']""")

# In the document the names appear in backticks and prose, so the check on
# that side is simply "is it mentioned".
_NAME_IN_DOC = re.compile(r"HALDIR_[A-Z0-9_]+")


def _documented_names() -> set[str]:
    return set(_NAME_IN_DOC.findall(_DOC.read_text(encoding="utf-8")))


def _names_the_code_reads() -> dict[str, str]:
    """Every `HALDIR_*` literal in shipped Python, mapped to one file that
    names it — the file is what makes a failure actionable."""
    found: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(_ROOT):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            path = Path(dirpath) / filename
            text = path.read_text(encoding="utf-8", errors="replace")
            for name in _NAME_IN_CODE.findall(text):
                found.setdefault(name, str(path.relative_to(_ROOT)))
    return found


def test_the_scan_sees_the_tree() -> None:
    """Guards the guard: a moved source tree or a bad prune would otherwise
    make the test below pass by finding nothing."""
    names = _names_the_code_reads()
    assert len(names) > 30, f"the scan found only {len(names)} variables — it is not looking at the code"
    assert "HALDIR_ENCRYPTION_KEY" in names
    assert _DOC.exists(), "CONFIGURATION.md is missing"


def test_every_variable_the_code_reads_is_documented() -> None:
    documented = _documented_names()
    read = _names_the_code_reads()
    missing = {name: where for name, where in read.items() if name not in documented}
    assert not missing, (
        "these environment variables are read by the code but are missing from "
        "CONFIGURATION.md: "
        + ", ".join(f"{name} ({where})" for name, where in sorted(missing.items()))
    )
