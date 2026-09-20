"""
The first run: does `pip install haldir && haldir serve` actually work?

Every other test in this suite starts from a working installation. These start
from nothing and assert the things a person evaluating Haldir needs to be true
in the first two minutes:

  * a fresh install reports itself healthy, not degraded;
  * `serve` produces a usable instance without Docker, Postgres, or an account;
  * the command it tells you to run next works;
  * and when the server is unreachable, the error explains rather than dumping
    someone else's JSON at you.

Run: python -m pytest tests/test_first_run.py -v
"""

from __future__ import annotations

import argparse
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cli  # noqa: E402
import haldir_status  # noqa: E402


@pytest.fixture
def serve_args(tmp_path):
    return argparse.Namespace(
        host="127.0.0.1", port=8899,
        data_dir=str(tmp_path / "data"), db="", no_key=False,
    )


@pytest.fixture
def stubbed_server(monkeypatch):
    """Stop cmd_serve from blocking in app.run, and keep it away from the
    real ~/.haldir/config.json."""
    import api
    calls = {}
    monkeypatch.setattr(api.app, "run", lambda **kw: calls.update(kw))
    monkeypatch.setattr(cli, "save_config", lambda c: calls.update(config=c))
    monkeypatch.setattr(cli, "load_config", lambda: {})
    return calls


# ── A fresh install is healthy ───────────────────────────────────────

def test_a_fresh_install_reports_ok_not_degraded(tmp_path) -> None:
    """Optional components that were never configured must not drag the
    banner down.

    Stripe has no key and no MCP upstream has been registered on a brand-new
    install. Both were reported as `degraded`, so a completely healthy
    instance announced itself as "Status ● degraded" — which reads as a broken
    product at exactly the moment someone is deciding whether it works.
    """
    from haldir_db import init_db

    db = str(tmp_path / "fresh.db")
    init_db(db)

    components = haldir_status.all_components(db)
    states = {c.name: c.state for c in components}

    assert states["api"] == "ok"
    assert states["database"] == "ok"
    assert haldir_status.overall_state(components) == "ok", (
        f"a fresh install reports {haldir_status.overall_state(components)}; "
        f"component states were {states}"
    )


def test_an_unconfigured_component_is_neutral_not_ok(tmp_path) -> None:
    """`off` must stay distinguishable from `ok` — otherwise a genuinely
    misconfigured deployment looks identical to a deliberately minimal one."""
    from haldir_db import init_db

    db = str(tmp_path / "fresh.db")
    init_db(db)
    states = {c.name: c.state for c in haldir_status.all_components(db)}
    assert states["billing"] == "off"


def test_a_real_failure_still_degrades(tmp_path) -> None:
    """The other direction: the neutral state must not swallow real trouble."""
    from haldir_status import ComponentStatus, overall_state

    components = [
        ComponentStatus(name="api", state="ok", message="", checked_at=0),
        ComponentStatus(name="database", state="degraded", message="", checked_at=0),
        ComponentStatus(name="billing", state="off", message="", checked_at=0),
    ]
    assert overall_state(components) == "degraded"

    components[1].state = "down"
    assert overall_state(components) == "down"


def test_off_is_never_returned_as_the_overall_state() -> None:
    """A page whose only component is unconfigured is not an "off" system —
    it is a system with nothing switched on, and `ok` is the honest answer."""
    from haldir_status import ComponentStatus, overall_state

    assert overall_state([
        ComponentStatus(name="billing", state="off", message="", checked_at=0),
    ]) == "ok"


# ── serve builds a working instance ──────────────────────────────────

def test_serve_creates_a_key_database_and_config(serve_args, stubbed_server) -> None:
    cli.cmd_serve(serve_args)

    data = serve_args.data_dir
    assert os.path.exists(os.path.join(data, "encryption.key")), (
        "no encryption key was written, so every secret would be lost on restart"
    )
    assert os.path.exists(os.path.join(data, "haldir.db")), "no database was created"

    config = stubbed_server.get("config", {})
    assert config.get("api_key", "").startswith("hld_"), (
        f"serve did not point the CLI at itself: {config}"
    )
    assert config.get("base_url", "").endswith(str(serve_args.port))
    assert stubbed_server.get("port") == serve_args.port


def test_serve_keeps_the_key_across_restarts(serve_args, stubbed_server,
                                             monkeypatch) -> None:
    """The key must be reused, not regenerated.

    api.py generates a throwaway key when none is set and warns that secrets
    will be lost on restart. That is true, and it is a terrible thing to
    discover after storing a production credential.

    Both environment variables are cleared with monkeypatch rather than by
    writing to os.environ, because cmd_serve sets them globally and a bare pop
    leaves the next test in this file inheriting whatever a previous one
    happened to point at — which is how this passed alone and failed in a
    full-file run.
    """
    monkeypatch.delenv("HALDIR_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("HALDIR_DB_PATH", raising=False)

    cli.cmd_serve(serve_args)
    first = open(os.path.join(serve_args.data_dir, "encryption.key")).read().strip()

    monkeypatch.delenv("HALDIR_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("HALDIR_DB_PATH", raising=False)

    cli.cmd_serve(serve_args)
    second = open(os.path.join(serve_args.data_dir, "encryption.key")).read().strip()

    assert first == second, "serve regenerated the encryption key on restart"


def test_serve_does_not_touch_the_config_when_asked_not_to(serve_args, stubbed_server) -> None:
    """--no-key exists so `serve` can be run without repointing anyone's CLI."""
    serve_args.no_key = True
    cli.cmd_serve(serve_args)
    assert "config" not in stubbed_server


def test_serve_reports_when_it_repoints_an_existing_config(monkeypatch, tmp_path) -> None:
    """Someone with a working hosted setup who runs `serve` once must be told
    their CLI moved, not discover it on the next command."""
    saved = {}
    monkeypatch.setattr(cli, "save_config", lambda c: saved.update(c))
    monkeypatch.setattr(cli, "load_config",
                        lambda: {"base_url": "https://haldir.xyz", "api_key": "hld_old"})

    note = cli._write_local_config("http://127.0.0.1:8000", "hld_new")

    assert saved["base_url"] == "http://127.0.0.1:8000"
    assert "haldir.xyz" in note, "the previous base_url was not mentioned"


def test_serve_says_nothing_when_nothing_changed(monkeypatch) -> None:
    monkeypatch.setattr(cli, "save_config", lambda c: None)
    monkeypatch.setattr(cli, "load_config",
                        lambda: {"base_url": "http://127.0.0.1:8000"})
    assert cli._write_local_config("http://127.0.0.1:8000", "hld_new") == ""


# ── Failures explain themselves ──────────────────────────────────────

def test_a_platform_404_is_not_mistaken_for_a_haldir_response() -> None:
    """Railway answers with status/code/message. Matching on any of those
    would treat "Application not found" as an API response and print it
    verbatim at the user."""
    railway = {"status": "error", "code": 404,
               "message": "Application not found", "request_id": "abc"}
    assert cli._looks_like_haldir(railway) is False

    ours = {"error": "Secret 'x' not found"}
    assert cli._looks_like_haldir(ours) is True


def test_serve_is_a_registered_command() -> None:
    """The README's first instruction is `haldir serve`; if the subcommand
    is not wired up, the documented path is a usage error."""
    parser = cli.build_parser()
    actions = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    names = set()
    for a in actions:
        names.update(a.choices.keys())
    assert "serve" in names, f"serve is not registered. Commands: {sorted(names)}"
