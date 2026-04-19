"""
Tests for the new CLI commands shipped this tranche:

  haldir overview              — calls /v1/admin/overview, formats it
  haldir status                — calls /v1/status, formats it
  haldir ready                 — exits 0/1 against /readyz
  haldir audit export          — streams /v1/audit/export
  haldir audit verify          — calls /v1/audit/verify
  haldir webhooks deliveries   — table of /v1/webhooks/deliveries
  haldir migrate up/status     — wraps haldir_migrate

HTTP-touching commands are tested with httpx.MockTransport so the CLI
exercise path is real but no network is touched. The migrate command
runs against a tmp-path SQLite DB with its own migrations dir.

Run: python -m pytest tests/test_cli_commands.py -v
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sqlite3
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
import httpx  # noqa: E402

import cli  # noqa: E402


# ── httpx mock plumbing ────────────────────────────────────────────────

@pytest.fixture
def mock_transport(monkeypatch):
    """Install a httpx MockTransport that the CLI's APIClient (and its
    httpx.stream / httpx.get calls) will route through. Tests register
    URL → response handlers via `add_route()`."""
    routes: dict[tuple[str, str], httpx.Response] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        # Strip query string; tests assert on path only for simplicity.
        key = (req.method, req.url.path)
        if key not in routes:
            return httpx.Response(404, json={"error": f"no mock for {key}"})
        return routes[key]

    transport = httpx.MockTransport(handler)

    # Patch httpx.request, httpx.get, httpx.stream — the three call
    # sites the CLI uses.
    real_client = httpx.Client

    def fake_request(method: str, url: str, **kwargs: Any) -> httpx.Response:
        with httpx.Client(transport=transport) as c:
            return c.request(method, url, **kwargs)

    def fake_get(url: str, **kwargs: Any) -> httpx.Response:
        with httpx.Client(transport=transport) as c:
            return c.get(url, **kwargs)

    class _StreamCtx:
        def __init__(self, method: str, url: str, **kw: Any):
            self._c = httpx.Client(transport=transport)
            self._cm = self._c.stream(method, url, **kw)

        def __enter__(self):
            return self._cm.__enter__()

        def __exit__(self, *a: Any) -> None:
            self._cm.__exit__(*a)
            self._c.close()

    monkeypatch.setattr(httpx, "request", fake_request)
    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(httpx, "stream", _StreamCtx)

    class _Routes:
        def add(self, method: str, path: str, *,
                status: int = 200, json_body: Any = None,
                text: str = "") -> None:
            routes[(method, path)] = httpx.Response(
                status,
                json=json_body if json_body is not None else None,
                content=(text.encode() if text else None),
            )

    return _Routes()


@pytest.fixture(autouse=True)
def _force_color_off(monkeypatch):
    """Strip ANSI so test assertions stay readable."""
    monkeypatch.setattr(cli.Color, "_enabled", False)
    for attr in ("RESET", "BOLD", "DIM", "GREEN", "RED",
                 "YELLOW", "CYAN", "MAGENTA", "WHITE"):
        monkeypatch.setattr(cli.Color, attr, "")


@pytest.fixture(autouse=True)
def _bogus_creds(monkeypatch):
    """APIClient lazily reads HALDIR_API_KEY / HALDIR_BASE_URL —
    inject test values so it doesn't try to read ~/.haldir/config.json."""
    monkeypatch.setenv("HALDIR_API_KEY", "hld_test")
    monkeypatch.setenv("HALDIR_BASE_URL", "http://test.invalid")


def _ns(**kw: Any) -> argparse.Namespace:
    return argparse.Namespace(**kw)


# ── overview ───────────────────────────────────────────────────────────

def test_overview_renders_every_section(mock_transport, capsys) -> None:
    mock_transport.add("GET", "/v1/admin/overview", json_body={
        "tenant_id":    "t1",
        "tier":         "pro",
        "generated_at": "2026-04-19T00:00:00+00:00",
        "usage":     {"actions_this_month": 42, "actions_limit": 50000,
                      "actions_pct_used": 0.00084, "spend_usd_this_month": 1.23},
        "sessions":  {"active_count": 3, "agents_active": 2, "agents_limit": 10},
        "vault":     {"secrets_count": 5, "secret_access_count": 12},
        "audit":     {"total_entries": 1000, "flagged_7d": 0,
                      "last_entry_at": "2026-04-19T00:00:00+00:00",
                      "chain_verified": True},
        "webhooks":  {"registered_count": 1, "deliveries_24h": 100,
                      "delivery_success_rate_24h": 0.99, "failed_24h": 1},
        "approvals": {"pending_count": 0},
        "health":    {"status": "ok", "components": []},
    })
    cli.cmd_overview(_ns(json=False, watch=False, interval=5.0))
    out = capsys.readouterr().out
    for marker in (
        "tenant overview", "t1", "pro",
        "Status", "ok",
        "Actions", "42", "50,000",
        "Spend", "$  1.23",
        "Sessions", "3 active",
        "Vault", "5 secrets",
        "Audit", "1,000 entries",
        "Webhooks", "100 deliveries",
        "Approvals", "0 pending",
    ):
        assert marker in out, f"missing {marker!r}"


def test_overview_json_mode_emits_raw_payload(mock_transport, capsys) -> None:
    payload = {"tenant_id": "t1", "tier": "free", "generated_at": "x",
               "usage": {}, "sessions": {}, "vault": {}, "audit": {},
               "webhooks": {}, "approvals": {}, "health": {}}
    mock_transport.add("GET", "/v1/admin/overview", json_body=payload)
    cli.cmd_overview(_ns(json=True, watch=False, interval=5.0))
    out = capsys.readouterr().out
    assert json.loads(out)["tenant_id"] == "t1"


# ── status ─────────────────────────────────────────────────────────────

def test_status_renders_components_and_metrics(mock_transport, capsys) -> None:
    mock_transport.add("GET", "/v1/status", json_body={
        "status": "ok",
        "components": [
            {"name": "api", "state": "ok", "message": "Serving"},
            {"name": "database", "state": "ok", "message": "Responsive"},
        ],
        "metrics": {
            "success_rate":     {"ratio": 0.999, "total": 100, "errors": 1},
            "latency_seconds":  {"p50": 0.005, "p95": 0.025, "p99": 0.050},
        },
    })
    cli.cmd_status(_ns(json=False))
    out = capsys.readouterr().out
    assert "Haldir status" in out
    assert "api" in out and "database" in out
    assert "99.900%" in out
    assert "p99" in out


# ── ready ──────────────────────────────────────────────────────────────

def test_ready_exits_0_when_ready(mock_transport) -> None:
    mock_transport.add("GET", "/readyz", json_body={
        "ready": True,
        "checks": [
            {"name": "database",   "ok": True,  "message": "ok",       "duration_ms": 1},
            {"name": "migrations", "ok": True,  "message": "1 applied", "duration_ms": 2},
        ],
    })
    with pytest.raises(SystemExit) as exc:
        cli.cmd_ready(_ns(json=False))
    assert exc.value.code == 0


def test_ready_exits_1_when_not_ready(mock_transport) -> None:
    mock_transport.add("GET", "/readyz", status=503, json_body={
        "ready": False,
        "checks": [
            {"name": "database", "ok": False, "message": "down", "duration_ms": 999},
        ],
    })
    with pytest.raises(SystemExit) as exc:
        cli.cmd_ready(_ns(json=False))
    assert exc.value.code == 1


# ── audit export ───────────────────────────────────────────────────────

def test_audit_export_streams_to_stdout(mock_transport, capsys) -> None:
    mock_transport.add("GET", "/v1/audit/export",
                       text='{"entry_id":"a"}\n{"entry_id":"b"}\n')
    cli.cmd_audit_export(_ns(
        format="jsonl", out=None,
        since=None, until=None, session=None, agent=None, tool=None,
    ))
    out = capsys.readouterr().out
    assert '{"entry_id":"a"}' in out
    assert '{"entry_id":"b"}' in out


def test_audit_export_writes_file(mock_transport, tmp_path) -> None:
    mock_transport.add("GET", "/v1/audit/export",
                       text='{"entry_id":"only"}\n')
    out_path = tmp_path / "exp.jsonl"
    cli.cmd_audit_export(_ns(
        format="jsonl", out=str(out_path),
        since=None, until=None, session=None, agent=None, tool=None,
    ))
    assert out_path.read_text() == '{"entry_id":"only"}\n'


# ── audit verify ───────────────────────────────────────────────────────

def test_audit_verify_success(mock_transport, capsys) -> None:
    mock_transport.add("GET", "/v1/audit/verify", json_body={
        "verified": True, "entries_checked": 7,
    })
    cli.cmd_audit_verify(_ns(json=False))
    assert "chain verified" in capsys.readouterr().out


def test_audit_verify_failure_exits_nonzero(mock_transport) -> None:
    mock_transport.add("GET", "/v1/audit/verify", json_body={
        "verified": False, "first_break": "aud_xyz", "entries_checked": 3,
    })
    with pytest.raises(SystemExit) as exc:
        cli.cmd_audit_verify(_ns(json=False))
    assert exc.value.code == 1


# ── webhooks deliveries ────────────────────────────────────────────────

def test_webhooks_deliveries_table(mock_transport, capsys) -> None:
    mock_transport.add("GET", "/v1/webhooks/deliveries", json_body={
        "deliveries": [
            {"delivery_id": "d1", "event_id": "ev_abc12345",
             "webhook_url": "https://hook.example.com/x",
             "event_type":  "anomaly",
             "attempt": 1, "status_code": 200,
             "response_excerpt": "ok",
             "error": "", "duration_ms": 12,
             "created_at": 1745200000.0},
        ],
    })
    cli.cmd_webhooks_deliveries(_ns(event_id=None, limit=20, json=False))
    out = capsys.readouterr().out
    assert "anomaly" in out
    assert "200" in out
    assert "hook.example.com" in out
    # Event id appears (truncated to first 12 chars in the table).
    assert "ev_abc12345" in out


def test_webhooks_deliveries_empty(mock_transport, capsys) -> None:
    mock_transport.add("GET", "/v1/webhooks/deliveries", json_body={
        "deliveries": [],
    })
    cli.cmd_webhooks_deliveries(_ns(event_id=None, limit=20, json=False))
    assert "no deliveries" in capsys.readouterr().out.lower()


# ── migrate (real haldir_migrate against tmp DB) ───────────────────────

def test_migrate_up_then_status(tmp_path, monkeypatch, capsys) -> None:
    migs = tmp_path / "migs"
    migs.mkdir()
    (migs / "001_demo.sql").write_text(
        "CREATE TABLE IF NOT EXISTS demo (x INT);"
    )
    monkeypatch.setenv("HALDIR_MIGRATIONS_DIR", str(migs))
    db = str(tmp_path / "m.db")

    cli.cmd_migrate(_ns(db_path=db, migrate_command="up"))
    out = capsys.readouterr().out
    assert "applied" in out

    cli.cmd_migrate(_ns(db_path=db, migrate_command="status"))
    out2 = capsys.readouterr().out
    assert "001" in out2 and "demo" in out2

    # Verify catches no drift.
    cli.cmd_migrate(_ns(db_path=db, migrate_command="verify"))
    out3 = capsys.readouterr().out
    assert "match" in out3
