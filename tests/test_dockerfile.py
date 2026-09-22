"""
Lint tests for the production Dockerfile.

These exist because we hit a multi-hour outage on 2026-04-19: a v0.3.0
Dockerfile change introduced `VOLUME ["/data"]`, which Railway silently
rejects with `The VOLUME keyword is banned in Dockerfiles`. Every
auto-deploy from main failed for hours before anyone noticed because
the previous successful deploy kept serving traffic happily.

These tests are the regression net. They run with the rest of the
suite, so a future Dockerfile edit that re-introduces a banned
directive trips CI red before it ever hits Railway.

Run: python -m pytest tests/test_dockerfile.py -v
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


DOCKERFILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "Dockerfile",
)


def _read() -> str:
    with open(DOCKERFILE) as f:
        return f.read()


def _instructions() -> list[tuple[int, str, str]]:
    """Return [(line_no, instruction, args), ...] skipping comments
    and continuations. Tolerant about leading whitespace."""
    out: list[tuple[int, str, str]] = []
    for i, raw in enumerate(_read().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Continuation lines start with whitespace OR follow a `\` —
        # for our checks we only care about the leading instruction.
        m = re.match(r"^([A-Z]+)\s*(.*)", line)
        if m:
            out.append((i, m.group(1), m.group(2)))
    return out


# ── Railway-banned directives ────────────────────────────────────────

def test_no_volume_directive() -> None:
    """Railway bans VOLUME — its volume system is configured per-service
    in their UI, not in Dockerfile directives. Re-introducing this
    instruction breaks every auto-deploy with a non-obvious build
    error."""
    for line_no, instr, _args in _instructions():
        assert instr != "VOLUME", (
            f"Dockerfile line {line_no}: VOLUME directive present. "
            "Railway rejects builds containing VOLUME — use Railway "
            "volumes via their UI or bind-mount via `docker run -v`."
        )


def test_no_maintainer_directive() -> None:
    """MAINTAINER is deprecated since Docker 1.13. Use LABEL
    org.opencontainers.image.authors instead. Some scanners flag
    images with MAINTAINER as out-of-date."""
    for line_no, instr, _args in _instructions():
        assert instr != "MAINTAINER", (
            f"Dockerfile line {line_no}: MAINTAINER is deprecated. "
            "Use LABEL org.opencontainers.image.authors=..."
        )


# ── Production hygiene we shipped in v0.3.0 ──────────────────────────

def test_runs_as_non_root_user() -> None:
    """The runtime stage must drop privileges to a non-root user.
    Required for procurement security reviews + most managed-K8s
    PodSecurityPolicy regimes."""
    instrs = _instructions()
    user_lines = [args.strip() for _, instr, args in instrs if instr == "USER"]
    assert user_lines, "Dockerfile must contain a USER directive"
    last = user_lines[-1]
    assert "root" not in last and last != "0", (
        f"Last USER directive resolves to root: {last!r}"
    )


def test_has_healthcheck() -> None:
    """Container probe presence prevents orchestrators from routing
    traffic into a wedged process. /livez is the right target."""
    src = _read()
    assert "HEALTHCHECK" in src, "Dockerfile must declare a HEALTHCHECK"
    assert "/livez" in src or "/healthz" in src, (
        "HEALTHCHECK must hit a probe endpoint (/livez preferred)"
    )


def test_has_multistage_build() -> None:
    """Build tools must not ship in the runtime image. Multi-stage
    keeps gcc + libpq-dev out of the attack surface."""
    instrs = _instructions()
    from_lines = [args for _, instr, args in instrs if instr == "FROM"]
    assert len(from_lines) >= 2, (
        "Dockerfile must use multi-stage build (>=2 FROM directives) "
        "to keep build tools out of the runtime image. Got: "
        f"{from_lines!r}"
    )


def test_python_version_matches_ci() -> None:
    """CI tests run on Python 3.12. The runtime image must match so
    `it works in CI` => `it works in prod`."""
    src = _read()
    assert "python:3.12" in src, (
        "Runtime image must be python:3.12-slim — CI matrix is pinned "
        "to 3.12 and the image must match for prod parity."
    )


# ── The build context ────────────────────────────────────────────────

# Material that must never reach a published image. `.gitignore` keeps it out
# of the repository; the build context is the *working directory*, not the git
# tree, so `.dockerignore` has to exclude it independently.
#
# This list had drifted. `.dockerignore` covered the investor one-pagers but
# not the working notes, the funding plans, the conversation log, `drafts/`
# or the editor transcripts — every one of which sits in the repo root and was
# being copied in by the `COPY . .` at the end of the Dockerfile, into an
# image the header of that file says is built so "nothing sensitive sneaks
# into a layer".
PRIVATE_PATHS = (
    # The glob, not the two filenames individually: the pattern is what the
    # file has to carry, and naming the instances would let the glob be
    # dropped while the test still passed.
    ".mcpregistry_*",
    "SESSION_CONTEXT.md",
    "CONVERSATION_HISTORY.md",
    "USER_CONVERSATIONS.md",
    "SOUL.md",
    "FUNDING_PATH.md",
    "FUNDING_OPTIONS.md",
    "AGENTIC_MARKET_SUBMISSION.md",
    "OFFICE_PLAN.md",
    "SEED_FUNDING_PLAN.md",
    "drafts/",
    ".aider*",
)


def _dockerignore_patterns() -> set[str]:
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        ".dockerignore",
    )
    with open(path) as f:
        return {
            line.strip()
            for line in f
            if line.strip() and not line.lstrip().startswith("#")
        }


# Dockerfiles besides the one above. Listed explicitly so adding another is a
# deliberate act rather than something this guard silently does not cover.
OTHER_DOCKERFILES = ("Dockerfile.glama",)


def test_every_dockerfile_starts_a_module_that_exists() -> None:
    """A `CMD ["python", "-m", X]` names X as a string, and nothing else in
    the suite resolves it — so a module that was renamed or deleted is only
    discovered when the container exits on start.

    `Dockerfile.glama` pointed at `mcp_server` for as long as it has existed.
    There has never been a module by that name — `pyproject.toml` records
    that it was removed — so the Glama container died on `ModuleNotFoundError`
    every time it was built, while `smithery.yaml` named the right module
    throughout. Caught by an independent review, not by CI: no test read this
    file.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bad = []
    for name in ("Dockerfile",) + OTHER_DOCKERFILES:
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            text = f.read()
        for mod in re.findall(r'"-m",\s*"([A-Za-z_][\w.]*)"', text):
            head = mod.split(".")[0]
            exists = (
                os.path.isfile(os.path.join(root, head + ".py"))
                or os.path.isdir(os.path.join(root, head))
            )
            if not exists:
                bad.append(f"{name} runs `-m {mod}`, and {head} does not exist")
    assert not bad, (
        "these Dockerfiles start a module the repository does not contain, so "
        "the container exits on import: " + "; ".join(bad)
    )


def test_private_material_is_kept_out_of_the_build_context() -> None:
    """Every path `.gitignore` protects must also be excluded from the image.

    Listing them here rather than deriving them from `.gitignore` is
    deliberate: the two files legitimately differ (the image needs `blog/`,
    `demo/`, `landing/` and `.well-known/`, which git tracks), so an
    automatic comparison would have to guess which differences are intended.
    An explicit list fails loudly when a new private file appears without a
    line here, which is the moment the gap is cheap to close.
    """
    patterns = _dockerignore_patterns()
    missing = [p for p in PRIVATE_PATHS if p not in patterns]
    assert not missing, (
        f"`.dockerignore` does not exclude {missing}, so `COPY . .` copies "
        f"them into the published image. Add them to the build context's "
        f"exclusion list."
    )
