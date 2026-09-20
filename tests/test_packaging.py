"""
What `pip install haldir` actually delivers.

The published 0.3.0 wheel contained `haldir_gate`, `haldir_vault`,
`haldir_watch` and `sdk` — and nothing else. `cli.py`, `haldir_db.py` and
`haldir_mcp_server.py` were named in an `include = [...]` that hatchling
silently ignores whenever `packages = [...]` is also set, because `packages` is
a shorthand that *replaces* it.

The result: nobody who has ever run `pip install haldir` has been able to start
it. The first command in the README, `pip install haldir && haldir overview`,
dies on `ModuleNotFoundError: No module named 'cli'`.

Nothing caught it because every test runs against the source tree, where the
modules are simply present. The only thing that would have caught it is a test
that asks what the *package* contains — which is what this file does.

Deliberately checks the declared build configuration rather than building a
wheel: building takes seconds and needs an isolated environment, and the
mistake being guarded against is a misconfiguration of the file, not a
hatchling bug. `tests/test_dockerfile.py` keeps the same shape.
"""

from __future__ import annotations

import ast
import fnmatch
import glob
import os
import re
import sys
import tomllib

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def pyproject() -> dict:
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as fh:
        return tomllib.load(fh)


def _wheel_include(pyproject: dict) -> list[str]:
    return pyproject["tool"]["hatch"]["build"]["targets"]["wheel"].get("include", [])


def _is_covered(module: str, include: list[str]) -> bool:
    """Is top-level module `module` inside the wheel?

    Three ways to be covered: named directly (`cli.py`), matched by a glob
    (`haldir_*.py` — which is how the modules are listed, deliberately, so the
    list cannot go stale), or living inside a directory that is included
    (`haldir_gate/`). `module` may be dotted; only the head has to be present
    at the wheel root.
    """
    head = module.split(".")[0]
    return any(
        fnmatch.fnmatch(f"{head}.py", pattern) or fnmatch.fnmatch(head, pattern)
        for pattern in include
    )


# ── The regression itself ────────────────────────────────────────────

def test_every_console_script_module_is_in_the_wheel(pyproject) -> None:
    """`haldir` and `haldir-mcp` are the two ways in. If either module is
    missing from the wheel, the installed package cannot be started at all."""
    scripts = pyproject["project"]["scripts"]
    include = _wheel_include(pyproject)

    missing = [
        f"{name} -> {target.split(':')[0]}"
        for name, target in scripts.items()
        if not _is_covered(target.split(":")[0], include)
    ]
    assert not missing, (
        f"these console scripts point at modules the wheel does not ship, so "
        f"`pip install haldir` produces a package whose entry points all fail: "
        f"{missing}"
    )


def test_the_wheel_ships_every_local_module_the_entry_points_import(pyproject) -> None:
    """Follow the imports one level: an entry point that *is* shipped still
    fails if the modules it imports are not.

    `cli.py` imports `haldir_db`, and so does everything else. Shipping
    `cli.py` alone would move the ModuleNotFoundError rather than fix it.
    """
    include = _wheel_include(pyproject)
    entry_modules = {
        target.split(":")[0] for target in pyproject["project"]["scripts"].values()
    }

    needed: set[str] = set()
    for mod in entry_modules:
        path = os.path.join(ROOT, f"{mod}.py")
        if not os.path.exists(path):
            continue
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                needed.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                needed.add(node.module.split(".")[0])

    # Keep only names that are actually local files in this repository —
    # third-party imports are the installer's problem, not the wheel's.
    local = {
        n for n in needed
        if os.path.exists(os.path.join(ROOT, f"{n}.py"))
        or os.path.isdir(os.path.join(ROOT, n))
    }

    missing = sorted(n for n in local if not _is_covered(n, include))
    assert not missing, (
        f"the entry points import these local modules, but the wheel does not "
        f"ship them: {missing}. Installing would succeed and running would not."
    )


# ── The guards that keep the list honest ─────────────────────────────

def test_the_include_list_names_things_that_exist(pyproject) -> None:
    """A typo in the include list drops a module from the wheel as surely as
    omitting it, and hatchling does not complain about a pattern that matches
    nothing."""
    # A pattern is checked by resolving it rather than by os.path.exists,
    # since a glob is not a path. Either way, an entry that matches nothing is
    # a silent hole: hatchling does not warn about it.
    matches_nothing = [
        entry for entry in _wheel_include(pyproject)
        if not (os.path.exists(os.path.join(ROOT, entry))
                or glob.glob(os.path.join(ROOT, entry)))
    ]
    assert not matches_nothing, (
        f"the wheel include list names paths and patterns that match nothing, "
        f"so whatever they were meant to ship is missing from the package: "
        f"{matches_nothing}"
    )


def test_no_build_target_uses_the_packages_shorthand_alongside_include(pyproject) -> None:
    """The specific trap, asserted directly.

    Hatchling's `packages` is documented as a convenience for `include`, but
    setting both means `packages` wins and `include` is discarded without a
    warning. That is not obvious from reading the file, which is why it shipped
    a broken package for months. If someone reintroduces `packages`, this fails
    and points them at the reason.
    """
    wheel = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert not ("packages" in wheel and "include" in wheel), (
        "both `packages` and `include` are set on the wheel target. Hatchling "
        "lets `packages` replace `include`, silently dropping everything "
        "named only in the latter — which is how the published 0.3.0 wheel "
        "came to contain no cli.py. Use one or the other."
    )


def test_the_sdist_ships_the_modules_too(pyproject) -> None:
    """A source distribution that omits them is the same failure for anyone
    who installs from sdist rather than a wheel."""
    sdist = pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    for entry in pyproject["project"]["scripts"].values():
        mod = entry.split(":")[0]
        assert any(m.startswith(mod) for m in sdist), (
            f"the sdist include list does not cover the entry-point module "
            f"{mod!r}"
        )


# ── The two manifests must agree ─────────────────────────────────────

def _requirement_names(specs) -> set[str]:
    return {re.split(r"[<>=!~\[; ]", s)[0].strip().lower() for s in specs if s.strip()}


def _requirements_txt() -> list[str]:
    out = []
    for line in open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8"):
        line = line.split("#")[0].strip()
        if line and not line.startswith("-"):
            out.append(line)
    return out


def test_pyproject_and_requirements_declare_the_same_packages(pyproject) -> None:
    """`pip install haldir` and `pip install -r requirements.txt` must install
    the same thing.

    They did not, and it is why two separate breakages reached PyPI: five
    runtime dependencies were declared only in requirements.txt, and `mcp` was
    bounded there but unbounded in pyproject. CI installs requirements.txt and
    stayed green through both.
    """
    in_pyproject = _requirement_names(pyproject["project"]["dependencies"])
    in_requirements = _requirement_names(_requirements_txt())

    only_requirements = in_requirements - in_pyproject
    assert not only_requirements, (
        f"these packages are installed by requirements.txt but not declared in "
        f"pyproject.toml, so `pip install haldir` does not get them: "
        f"{sorted(only_requirements)}"
    )

    only_pyproject = in_pyproject - in_requirements
    assert not only_pyproject, (
        f"these packages are declared in pyproject.toml but missing from "
        f"requirements.txt, so CI never exercises them: "
        f"{sorted(only_pyproject)}"
    )


def test_every_dependency_has_an_upper_bound(pyproject) -> None:
    """An unbounded dependency is a promise that the next major release of
    somebody else's library will not break this one.

    `mcp>=1.27.0` was exactly that. A fresh `pip install haldir` resolved mcp
    2.x, which removed the `@server.list_tools()` decorator the MCP server is
    built on, and every installed copy died on startup.
    """
    unbounded = [
        spec for spec in pyproject["project"]["dependencies"]
        if "<" not in spec
    ]
    assert not unbounded, (
        f"these dependencies have no upper bound, so a future major release "
        f"can be installed and break this package: {unbounded}"
    )
