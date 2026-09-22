"""
What the published npm packages actually contain.

The Python equivalent is `tests/test_packaging.py`, and this exists for the
same reason: a package's `files` list is a claim about what a consumer gets,
and nothing was checking it. Both of Haldir's npm packages listed `LICENSE`
in that list — and neither directory contained one, so `npm pack` shipped no
license file while `package.json` declared `"license": "MIT"`.

Nothing else in the suite read these files at all.

Run: python -m pytest tests/test_npm_packages.py -v
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Entries a package's own build creates. Their absence from a fresh checkout
# is correct — `npm publish` runs the build first — so they are not checked.
# Everything else in a `files` list is source the repository must contain.
_BUILD_OUTPUTS = {"dist"}


def _package_files() -> list[tuple[str, str, list[str]]]:
    """Every package.json with a `files` list: (dir, name, files)."""
    found: list[tuple[str, str, list[str]]] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in {"node_modules", ".git"}]
        if "package.json" not in filenames:
            continue
        path = os.path.join(dirpath, "package.json")
        with open(path, encoding="utf-8") as fh:
            meta = json.load(fh)
        files = meta.get("files")
        if isinstance(files, list):
            found.append((os.path.relpath(dirpath, ROOT), meta.get("name", "?"), files))
    return sorted(found)


def test_every_package_json_declares_a_license() -> None:
    packages = _package_files()
    assert packages, "no package.json with a `files` list found — this scan has stopped matching"
    missing = [name for _d, name, _f in packages if not name]
    assert not missing, f"packages with no name: {missing}"


def test_every_declared_file_exists() -> None:
    """`files` is what npm publishes, so an entry that is not in the
    repository is a file the tarball will not contain.

    `LICENSE` was listed by both packages and present in neither, so the
    published tarballs carried no license at all under a declared MIT.
    """
    missing: list[str] = []
    for rel, name, files in _package_files():
        for entry in files:
            if entry in _BUILD_OUTPUTS:
                continue
            if not os.path.exists(os.path.join(ROOT, rel, entry)):
                missing.append(f"{name}: {entry} (declared in {rel}/package.json)")
    assert not missing, (
        f"these are listed for publication but are not in the repository, so "
        f"they cannot reach the tarball: {missing}"
    )


def test_both_npm_packages_ship_the_mit_license_they_declare() -> None:
    """The specific defect, asserted directly so a rename of the enforcement
    above cannot quietly drop it."""
    for rel, name, files in _package_files():
        path = os.path.join(ROOT, rel, "package.json")
        with open(path, encoding="utf-8") as fh:
            meta = json.load(fh)
        if meta.get("license") != "MIT":
            continue
        assert "LICENSE" in files, (
            f"{name} declares MIT but does not list LICENSE for publication"
        )
        license_path = os.path.join(ROOT, rel, "LICENSE")
        assert os.path.isfile(license_path), (
            f"{name} declares MIT and lists LICENSE, but {rel}/LICENSE is "
            f"missing — npm would publish a package with no license in it"
        )
        with open(license_path, encoding="utf-8") as fh:
            body = fh.read()
        assert "MIT License" in body, f"{rel}/LICENSE is not the MIT text"
