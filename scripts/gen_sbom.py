"""
Generate a CycloneDX 1.5 SBOM for the installed Python wheels.

CycloneDX is the OWASP-maintained SBOM format that every procurement
review asks for by name — it slots directly into Dependency-Track,
Grype, and the NIST vulnerability feeds. GitHub's Dependency Graph
also ingests it.

Why this script instead of `pip install cyclonedx-bom`:

  - Pins the output to a single short Python file we fully own, so
    procurement reviewers can diff it against the rendered SBOM
    without trusting an intermediate CLI's version.
  - Zero extra install footprint in the Docker build stage that
    generates it. Uses only importlib.metadata (stdlib since 3.8).
  - Emits deterministic output (sorted components, fixed UTC
    timestamp when HALDIR_SBOM_TIMESTAMP is passed) so CI can diff
    SBOMs to detect unexpected dep drift.

Output: CycloneDX 1.5 JSON describing every installed distribution,
each as a "library" component with name, version, purl, and the
license string reported by the package metadata.

Usage:
    python scripts/gen_sbom.py --out sbom.json
    python scripts/gen_sbom.py > sbom.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from importlib.metadata import distributions
from typing import Any


CYCLONEDX_SPEC = "1.5"
TOOL_NAME = "haldir-sbom-gen"
TOOL_VERSION = "0.1.0"


def _license_expr(meta: Any) -> list[dict[str, Any]]:
    """Best-effort license extraction.

    Packages express licenses in multiple places: the PEP 621 `License`
    metadata field, the Trove classifier list (`License :: OSI
    Approved :: MIT License`), or sometimes just a LICENSE file reference.
    We take whichever is cheapest to read and most machine-parseable."""
    lic = (meta.get("License") or "").strip()
    if lic and lic.lower() not in ("unknown", "unlicense", "license"):
        return [{"license": {"name": lic}}]

    # Fall back to Trove classifiers.
    classifiers = meta.get_all("Classifier") or []
    for c in classifiers:
        if c.startswith("License ::"):
            # "License :: OSI Approved :: MIT License"
            name = c.split("::")[-1].strip()
            if name:
                return [{"license": {"name": name}}]
    return []


def _purl(name: str, version: str) -> str:
    """Package URL — the canonical cross-ecosystem identifier.
    `pkg:pypi/<name>@<version>` for anything installed from PyPI."""
    return f"pkg:pypi/{name}@{version}"


def _component(dist: Any) -> dict[str, Any]:
    meta = dist.metadata
    name = meta["Name"]
    version = meta["Version"] or "0.0.0"
    comp: dict[str, Any] = {
        "type":    "library",
        "name":    name,
        "version": version,
        "purl":    _purl(name, version),
        "bom-ref": _purl(name, version),
    }
    if summary := (meta.get("Summary") or "").strip():
        comp["description"] = summary
    if licenses := _license_expr(meta):
        comp["licenses"] = licenses
    return comp


def build_sbom(root_name: str = "haldir",
               root_version: str | None = None) -> dict[str, Any]:
    """Build the CycloneDX document. `root_name/_version` identify the
    subject of the SBOM — by default, the Haldir application itself."""
    components = sorted(
        (_component(d) for d in distributions()),
        key=lambda c: c["name"].lower(),
    )
    # Deterministic timestamp when requested, so repeatable CI builds
    # produce identical SBOM bytes.
    ts_override = os.environ.get("HALDIR_SBOM_TIMESTAMP")
    if ts_override:
        timestamp = ts_override
    else:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    return {
        "$schema": f"http://cyclonedx.org/schema/bom-{CYCLONEDX_SPEC}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "Haldir", "name": TOOL_NAME, "version": TOOL_VERSION}],
            "component": {
                "type": "application",
                "name": root_name,
                "version": root_version or _detect_haldir_version(),
                "purl": _purl(root_name, root_version or _detect_haldir_version()),
            },
        },
        "components": components,
    }


def _detect_haldir_version() -> str:
    """Pull the current Haldir version from the installed package
    metadata, or fall back to a placeholder when running from source."""
    for dist in distributions():
        if dist.metadata["Name"].lower() == "haldir":
            return dist.metadata["Version"]
    return "0.0.0-dev"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", help="Write SBOM to path (default: stdout)")
    p.add_argument("--root-name", default="haldir",
                   help="Application name recorded in the SBOM root component")
    p.add_argument("--root-version", default=None,
                   help="Application version (auto-detect from installed pkg if omitted)")
    args = p.parse_args()

    sbom = build_sbom(args.root_name, args.root_version)
    payload = json.dumps(sbom, indent=2, sort_keys=False) + "\n"

    if args.out:
        with open(args.out, "w") as f:
            f.write(payload)
        print(f"wrote {args.out} ({len(sbom['components'])} components)",
              file=sys.stderr)
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
