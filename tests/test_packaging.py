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
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

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


def test_the_sdist_ships_everything_the_wheel_does(pyproject) -> None:
    """The sdist list is the load-bearing one.

    `python -m build` builds the sdist first and then builds the *wheel from
    the sdist*. Anything the sdist omits is missing from the wheel too, whatever
    the wheel target says.

    That is what made this take two rounds to find. The wheel's include list
    was corrected twice — a glob, then an explicit enumeration — and the CI job
    failed identically both times, because the wheel was being built out of an
    sdist that listed three modules. Checking the entry-point modules alone was
    not enough; haldir_logging.py and haldir_tracing.py are imported by
    haldir_db and the three packages, not named by a console script.
    """
    sdist = set(pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]["include"])
    wheel = set(_wheel_include(pyproject))

    # Every wheel entry must be reachable from the sdist. Directory globs
    # cover their contents; explicit files must be named.
    missing = sorted(
        entry for entry in wheel
        if entry not in sdist
        and not any(entry.startswith(d.rstrip("*").rstrip("/"))
                    for d in sdist if d.endswith("/**"))
    )
    assert not missing, (
        f"the wheel includes these but the sdist does not, so `python -m "
        f"build` would produce a wheel missing them — the wheel is built from "
        f"the sdist: {missing}"
    )


def test_the_sdist_lists_every_module_on_disk(pyproject) -> None:
    """Same staleness guard as the wheel, for the list that actually decides."""
    on_disk = {os.path.basename(p) for p in glob.glob(os.path.join(ROOT, "haldir_*.py"))}
    sdist = set(pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]["include"])
    missing = sorted(on_disk - sdist)
    assert not missing, (
        f"these modules are not in the sdist include list, so a wheel built "
        f"from the sdist would not contain them: {missing}"
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


def test_every_top_level_module_on_disk_is_in_the_wheel(pyproject) -> None:
    """The wheel lists its modules explicitly, so the list can go stale.

    That is the whole risk of enumerating: add `haldir_foo.py`, forget the
    list, and the package installs without it. This test is what makes the
    explicit list safe — it fails the moment a module exists that the wheel
    would not carry.

    The list is explicit rather than a glob because a glob built the right
    wheel locally and the wrong one in CI.
    """
    on_disk = {
        os.path.basename(p)
        for p in glob.glob(os.path.join(ROOT, "haldir_*.py"))
    }
    assert on_disk, "no haldir_*.py modules found — is ROOT right?"

    include = set(_wheel_include(pyproject))
    missing = sorted(on_disk - include)
    assert not missing, (
        f"these modules exist but the wheel would not ship them, so an "
        f"installed Haldir could not import whatever depends on them: "
        f"{missing}. Add them to the wheel include list in pyproject.toml."
    )


def test_the_wheel_does_not_ship_development_scripts(pyproject) -> None:
    """The other direction: a build script or a benchmark in the shipped
    package is dead weight, and `bench_merkle.py` imports matplotlib."""
    include = set(_wheel_include(pyproject))
    for script in ("build_deck.py", "build_deck_pptx.py", "bench_merkle.py"):
        assert script not in include, (
            f"{script} is a development script and should not ship"
        )


# ── Content the application serves from its own directory ────────────

# Every HTTP route in api.py that does `open(os.path.dirname(__file__)/...)`
# is serving a file that has to be in the wheel. These are not documentation:
# without them an installed Haldir answers 500 on /llms.txt,
# /.well-known/agent.json, /AGENTS.md, /robots.txt, /sitemap.xml, /docs, the
# blog and the demo.
#
# The discovery ones matter most. They are how an agent or a registry works
# out that Haldir exists at all, so an installed copy was invisible to
# precisely the audience the product is built for — and 500 rather than 404,
# which reads as a broken server rather than a missing file.
SERVED_CONTENT = (
    "llms.txt",
    "llms-full.txt",
    "robots.txt",
    "sitemap.xml",
    "ai-plugin.json",
    "AGENTS.md",
    "THREAT_MODEL.md",
    "SECURITY.md",
    "dashboard.html",
    "demo_gallery.html",
    "quickstart.html",
)


_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_served_content_files_exist_on_disk() -> None:
    """If one of these is absent the route 404s in every installation,
    including the source tree, where it is easiest to notice."""
    missing = [f for f in SERVED_CONTENT if not os.path.isfile(os.path.join(_ROOT, f))]
    assert not missing, f"the app serves these but they are not in the tree: {missing}"


def test_served_content_is_listed_for_packaging(pyproject) -> None:
    include = _wheel_include(pyproject)
    missing = [f for f in SERVED_CONTENT if f not in include]
    assert not missing, (
        f"these are served by the app but not packaged, so every installed "
        f"copy answers 500 on their routes: {missing}"
    )


# ── Read from disk at runtime, by module path rather than by HTTP ────

# `haldir_migrate` discovers NNN_*.sql beside its own module and applies
# whatever the database has not recorded yet. The directory was not packaged,
# so an installed Haldir had no migrations at all: the runner found nothing,
# logged "no migration files found", and the tables that only the migrations
# create were never created.
#
# The visible result was a 500 on /v1/audit/sth-log — the Signed Tree Head
# log, the transparency surface the tamper-evidence claim rests on — and
# "no such table: sth_mirror_receipts" from the Rekor mirror. Both worked in
# the checkout, where the directory exists, and in no installation. Same shape
# as 0.3.0 shipping four modules of twenty-seven, and 0.3.1 shipping no
# application content: present for the developer, absent for the user.
MIGRATIONS_DIR = "migrations"


def _sdist_include(pyproject: dict) -> list[str]:
    return pyproject["tool"]["hatch"]["build"]["targets"]["sdist"].get("include", [])


def test_the_migrations_directory_holds_sql() -> None:
    d = os.path.join(ROOT, MIGRATIONS_DIR)
    assert os.path.isdir(d), f"{MIGRATIONS_DIR}/ does not exist, so nothing applies"
    sql = sorted(f for f in os.listdir(d) if f.endswith(".sql"))
    assert sql, f"{MIGRATIONS_DIR}/ holds no .sql files, so nothing applies"


def test_migrations_are_packaged(pyproject) -> None:
    """Both lists, because the wheel is built *from* the sdist.

    A directory missing from the sdist is missing from the wheel regardless of
    what the wheel target says — which is why two earlier rounds of fixing only
    the wheel's include list changed nothing at all.
    """
    for target, include in (
        ("wheel", _wheel_include(pyproject)),
        ("sdist", _sdist_include(pyproject)),
    ):
        assert MIGRATIONS_DIR in include, (
            f"{MIGRATIONS_DIR}/ is read at runtime by haldir_migrate but is not "
            f"in the {target} include list, so an installed Haldir applies no "
            f"migrations and the tables only they create never exist"
        )


# ── The general form of that mistake ─────────────────────────────────

# The three packaging failures above are one mistake made three times: code
# opens a path beside its own module, the file is in the checkout, and nobody
# asks whether it is in the package. Each was fixed with an explicit list plus
# a test for that list — which guards the instance, not the mistake.
#
# This finds the instances. It reads every module the package ships, collects
# the literal path segment each opens relative to its own directory, and
# requires that segment to be packaged. A new
# `open(os.path.join(os.path.dirname(__file__), "templates"))` fails here when
# it is written, instead of in a stranger's terminal a release later.


def _shipped_modules(include: list[str]) -> list[str]:
    """The .py files the include list actually ships.

    Derived from the packaging configuration rather than from a directory
    listing, so this scan cannot drift from what is really packaged.
    """
    found: list[str] = []
    for entry in include:
        path = os.path.join(ROOT, entry)
        if entry.endswith(".py") and os.path.isfile(path):
            found.append(path)
        elif os.path.isdir(path):
            for dirpath, _dirnames, filenames in os.walk(path):
                found.extend(
                    os.path.join(dirpath, name)
                    for name in filenames
                    if name.endswith(".py")
                )
    return found


def _paths_opened_beside_the_module(py_file: str) -> set[str]:
    """Top-level path segments opened relative to `py_file`'s own directory.

    Matches `os.path.join(os.path.dirname(<... __file__ ...>), "seg", ...)` and
    keeps `seg` — the part that has to appear in the include lists.
    """
    with open(py_file, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())

    segments: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "join"):
            continue
        # The first argument has to be the module's own directory.
        if not any(
            isinstance(n, ast.Name) and n.id == "__file__"
            for n in ast.walk(node.args[0])
        ):
            continue
        for arg in node.args[1:]:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                segments.add(arg.value)
                break
    return segments


def test_every_path_a_shipped_module_opens_is_packaged(pyproject) -> None:
    wheel = _wheel_include(pyproject)
    sdist = _sdist_include(pyproject)

    opened: dict[str, set[str]] = {}
    for module in _shipped_modules(wheel):
        for segment in _paths_opened_beside_the_module(module):
            opened.setdefault(segment, set()).add(os.path.relpath(module, ROOT))

    assert opened, (
        "no module-relative opens were found at all, which means this scan has "
        "stopped matching how the code opens files — not that the code became "
        "safer"
    )

    missing = sorted(s for s in opened if s not in wheel or s not in sdist)
    assert not missing, (
        "opened beside a shipped module, but absent from the packaging include "
        "lists — so they exist for the developer and not for the user: "
        + "; ".join(
            f"{s} (opened by {', '.join(sorted(opened[s]))})" for s in missing
        )
    )


def test_served_content_directories_are_packaged(pyproject) -> None:
    """The dot-directory is the one that got missed.

    `.well-known` is where the agent card, the MCP server card, security.txt
    and ai.txt live — the whole machine-readable discovery surface.
    """
    include = _wheel_include(pyproject)
    for d in (".well-known", "landing", "blog", "demo", "docs"):
        assert d in include, (
            f"{d}/ is served by the app but not packaged, so its routes 404 "
            f"in every installed copy"
        )


def test_a_missing_content_file_is_404_not_500() -> None:
    """The status line should say what is true.

    These routes did a bare open() relative to the package directory, so a
    file that was not packaged raised FileNotFoundError and the client got a
    500 — "the server is broken" — for a file that simply was not installed.
    """
    import api

    # Inside a request context, because _serve_content returns jsonify() on
    # the missing path and jsonify needs one — which is also the only way it
    # is ever called in production.
    with api.app.test_request_context("/llms.txt"):
        result = api._serve_content("definitely-not-a-real-file.txt")
    # A 2-tuple: Flask takes (body, status) as well as (body, status, headers).
    assert result[1] == 404, f"expected 404, got {result[1]!r}"
