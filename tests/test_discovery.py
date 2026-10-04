"""Discovery finds what is on the machine, and redacts what it finds.

The scanner's value is that a person trusts the list enough to act on it, so
the tests are about the two ways that trust breaks:

  * **False positives** — a shell wrapper whose payload mentions `.claude`
    reported as an agent makes every line suspect. Classification is against
    the *command head* (the executable and its first arguments), and the tests
    pin the shapes that must match and the shapes that must not.
  * **Leaked secrets** — command lines carry API keys, and discovery output
    gets pasted into issues and chat windows. Every string that reaches a
    finding goes through redaction, and the tests feed it the real shapes.

Everything runs against synthetic homes and `/proc` trees, so the suite does
not depend on what happens to be installed on the machine running it.

Run: python -m pytest tests/test_discovery.py -v
"""

from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import haldir_console  # noqa: E402
import haldir_discover as discover  # noqa: E402


# ── Reading the clients ────────────────────────────────────────────────

def _fake_home(tmp_path, files: dict):
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return str(tmp_path)


def test_a_configured_client_is_found_with_its_servers(tmp_path) -> None:
    home = _fake_home(tmp_path, {
        ".claude.json": json.dumps({
            "mcpServers": {
                "filesystem": {"command": "npx",
                               "args": ["@modelcontextprotocol/server-filesystem", "/tmp"]},
                "remote-thing": {"url": "https://example.com/mcp"},
            },
        }),
    })
    clients = discover.scan_clients(home)
    assert [c["client"] for c in clients] == ["Claude Code"]
    servers = clients[0]["servers"]
    assert set(servers) == {"filesystem", "remote-thing"}
    assert "server-filesystem" in servers["filesystem"]
    assert "example.com" in servers["remote-thing"]


def test_several_clients_are_found_at_once(tmp_path) -> None:
    home = _fake_home(tmp_path, {
        ".claude.json": json.dumps({"mcpServers": {"a": {"command": "a-cmd"}}}),
        ".cursor/mcp.json": json.dumps({"mcpServers": {"b": {"command": "b-cmd"}}}),
        ".config/Code/User/settings.json": json.dumps({"editor.fontSize": 12}),
    })
    found = {c["client"]: c for c in discover.scan_clients(home)}
    assert set(found) == {"Claude Code", "Cursor", "VS Code"}
    assert set(found["Cursor"]["servers"]) == {"b"}
    assert found["VS Code"]["servers"] == {}, "a client with no servers is still a client"


def test_a_config_that_will_not_parse_is_reported_not_dropped(tmp_path) -> None:
    """The client is installed and pointing at something. "Could not read it"
    is a finding; "nothing here" is a lie."""
    home = _fake_home(tmp_path, {".claude.json": "{ this is not json"})
    client = discover.scan_clients(home)[0]
    assert client["readable"] is False
    assert client["note"].startswith("could not read")
    assert client["servers"] == {}


def test_alternative_server_keys_are_recognised(tmp_path) -> None:
    """Clients disagree on the key — one spelling is how a detector reports
    "nothing configured" on a machine with five servers on it."""
    home = _fake_home(tmp_path, {
        ".cursor/mcp.json": json.dumps({"mcp.servers": {"x": {"command": "x"}}}),
    })
    assert set(discover.scan_clients(home)[0]["servers"]) == {"x"}


# ── Redaction ──────────────────────────────────────────────────────────

def test_flagged_secrets_are_redacted() -> None:
    for raw, secret in (
        ("npx server --api-key sk-abc123def456ghi", "sk-abc123def456ghi"),
        ("server --token=hld_9f8e7d6c5b4a", "hld_9f8e7d6c5b4a"),
        ("env OPENAI_API_KEY=sk-live-0123456789ab node agent.js", "sk-live-0123456789ab"),
        ("aws s3 cp --key AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("client --password hunter2 --url https://x", "hunter2"),
    ):
        cleaned = discover._redact(raw)
        assert secret not in cleaned, f"{secret!r} survived redaction of {raw!r}"
        assert "***" in cleaned


def test_redaction_leaves_ordinary_text_alone() -> None:
    """"server-filesystem /tmp" must not become "server-filesystem ***" —
    over-redaction makes the report useless."""
    for raw in ("npx @modelcontextprotocol/server-filesystem /tmp",
                "ollama serve",
                "python -m crewai run --verbose"):
        assert discover._redact(raw) == raw


# ── Processes ──────────────────────────────────────────────────────────

def _proc_tree(tmp_path, procs: dict):
    root = tmp_path / "proc"
    root.mkdir()
    for pid, cmdline in procs.items():
        d = root / str(pid)
        d.mkdir()
        (d / "cmdline").write_bytes(cmdline.replace(" ", "\x00").encode() + b"\x00")
    (root / "self").mkdir()  # a non-numeric entry, as /proc has
    return str(root)


def test_agents_and_servers_are_found_and_noise_is_not(tmp_path) -> None:
    root = _proc_tree(tmp_path, {
        101: "/usr/local/bin/ollama serve",
        102: "python -m crewai run",
        103: "npx @modelcontextprotocol/server-filesystem /tmp",
        104: "/bin/bash -c source /home/x/.claude/shell-snapshots/s.sh",  # wrapper, not an agent
        105: "grep -r claude /home/x",                                    # a search for one
        106: "/usr/bin/some-unrelated-daemon",
    })
    found: dict[int, dict] = {p["pid"]: p for p in discover.scan_processes(root)}
    assert set(found) == {101, 102, 103}
    assert found[101]["kind"] == "llm-runtime"
    assert found[102]["kind"] == "agent-framework"
    assert found[103]["kind"] == "mcp-server"


def test_classification_uses_the_command_head() -> None:
    """The shapes that must match — and the payload that must not."""
    cases = (
        ("ollama serve", "llm-runtime"),
        ("python -m crewai run", "agent-framework"),
        ("npx @modelcontextprotocol/server-filesystem /tmp", "mcp-server"),
        ("uvx mcp-server-git", "mcp-server"),
        ("claude", "coding-agent"),
        ("/home/anon/Desktop/D/Haldir/haldir serve", "governed"),
    )
    for cmdline, expected in cases:
        got = discover._classify(discover._command_head(cmdline))
        assert got and got[0] == expected, f"{cmdline!r} classified as {got}"

    for cmdline in (
        "/bin/bash -c source /home/x/.claude/snapshots/s.sh",
        'python -c "import langchain"',
        "/home/anon/venv/bin/python -c import haldir_discover",
    ):
        assert discover._classify(discover._command_head(cmdline)) is None, (
            f"{cmdline!r} should not be classified as an agent"
        )


def test_a_missing_proc_root_is_not_an_error(tmp_path) -> None:
    """Non-Linux, or a container without /proc mounted: the scan reports no
    processes rather than raising."""
    assert discover.scan_processes(str(tmp_path / "nope")) == []


# ── The whole payload ──────────────────────────────────────────────────

def test_discover_summarizes_and_stays_local(tmp_path) -> None:
    home = _fake_home(tmp_path, {
        ".claude.json": json.dumps({"mcpServers": {
            "ungoverned": {"command": "thing"},
            "governed": {"url": "https://haldir.xyz/mcp"},
        }}),
    })
    report = discover.discover(home=home, proc_root=str(tmp_path / "none"))
    assert report["summary"] == {
        "clients": 1,
        "configured_servers": 2,
        "processes": 0,
        "governed_processes": 0,
        "ungoverned_servers": 1,   # the haldir one is not counted as ungoverned
        "unreadable_configs": 0,
    }


def test_the_scanner_cannot_reach_the_network() -> None:
    """A static check, not a runtime one: the module must not import anything
    that could send what it reads anywhere. Discovery that phones home is a
    different product with a different consent story."""
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "haldir_discover.py")).read()
    imported = set()
    for node in __import__("ast").walk(__import__("ast").parse(src)):
        if isinstance(node, __import__("ast").Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, __import__("ast").ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {"socket", "urllib", "http", "httpx", "requests", "ftplib", "smtplib"}
    assert not (imported & forbidden), (
        f"the scanner imports {sorted(imported & forbidden)} — it must not be "
        f"able to send anything anywhere"
    )


# ── The console's rows ─────────────────────────────────────────────────

def test_rows_group_and_carry_a_next_step() -> None:
    discovery = {
        "clients": [{"client": "Claude Code", "config_path": "/home/x/.claude.json",
                     "readable": True, "servers": {"thing": "thing-cmd"}}],
        "processes": [{"pid": 7, "kind": "coding-agent", "label": "Cursor",
                       "command": "cursor"}],
    }
    register = {"agents": [
        {"agent_id": "ledger-bot", "kind": "agent", "default_scopes": ["read"],
         "sessions": {"total": 2}, "activity": {"cost_usd": 1.5, "flagged": 1},
         "card_id": None},
        {"agent_id": "payer", "kind": "agent", "default_scopes": ["spend"],
         "sessions": {"total": 1}, "activity": {"cost_usd": 0.0, "flagged": 0},
         "card_id": "card_abc"},
    ]}
    rows = haldir_console.build_rows(discovery, register)
    # One row per thing, so the group label repeats; what matters is the order
    # the groups first appear in.
    seen: list[str] = []
    for row in rows:
        if row["group"] not in seen:
            seen.append(row["group"])
    assert seen == ["MCP clients", "MCP servers they launch",
                    "Running now", "Governed by Haldir"]
    by_name = {r["name"]: r for r in rows}
    # The client row offers the on-ramp, with the snippet to paste.
    assert "haldir" in by_name["Claude Code"]["snippet"]
    assert by_name["thing"]["suggestion"].startswith("Ungoverned")
    assert by_name["Cursor #7"]["kind"] == "coding-agent"
    # A published card is called out; an unpublished one gets the nudge.
    assert "capability card is published" in by_name["payer"]["suggestion"]
    assert "haldir publish" in by_name["ledger-bot"]["suggestion"]


def test_a_server_already_pointed_at_haldir_is_not_called_ungoverned() -> None:
    discovery = {
        "clients": [{"client": "Claude Code", "config_path": "p", "readable": True,
                     "servers": {"haldir": "https://haldir.xyz/mcp"}}],
        "processes": [],
    }
    row = next(r for r in haldir_console.build_rows(discovery)
               if r["name"] == "haldir")
    assert row["suggestion"] == "Already routed through Haldir."
    assert row["snippet"] == ""


def test_the_console_reports_no_display_instead_of_crashing(monkeypatch) -> None:
    """`open_console` on a headless box must say so — not raise a TclError
    from three frames down, and not hang."""
    import tkinter
    def no_display(*_a, **_k):
        raise tkinter.TclError("no display name and no $DISPLAY environment variable")
    monkeypatch.setattr(tkinter, "Tk", no_display)

    import pytest
    with pytest.raises(RuntimeError) as excinfo:
        haldir_console.open_console([{"group": "MCP clients", "name": "x", "kind": "client",
                                      "detail": "", "suggestion": "", "snippet": ""}])
    assert "haldir discover" in str(excinfo.value)


def test_the_text_render_is_what_the_terminal_shows() -> None:
    rows = haldir_console.build_rows({
        "clients": [{"client": "Claude Code", "config_path": "/h/.claude.json",
                     "readable": True, "servers": {}}],
        "processes": [],
    })
    text = haldir_console.render_rows_text(rows)
    assert "MCP CLIENTS" in text and "Claude Code" in text
    assert summarize_has(text)


def summarize_has(text: str) -> bool:
    return bool(re.search(r"Claude Code", text))
