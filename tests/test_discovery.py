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


# ── The console, on the web ────────────────────────────────────────────

def _auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


SAMPLE_PASTE = {
    "clients": [{"client": "Claude Code", "config_path": "/home/you/.claude.json",
                 "readable": True, "servers": {"exposureguard": "exposureguard-mcp"}}],
    "processes": [{"pid": 1316, "kind": "llm-runtime", "label": "Ollama",
                   "command": "/usr/local/bin/ollama serve"}],
}


def test_the_paste_is_sanitized_before_it_is_rendered() -> None:
    """The paste is untrusted browser input: a list where a dict belongs
    raises three frames down inside build_rows, and unknown keys are the
    browser's business, not the renderer's."""
    assert haldir_console.sanitize_discovery("not a dict") == {"clients": [], "processes": []}
    assert haldir_console.sanitize_discovery(None) == {"clients": [], "processes": []}

    cleaned = haldir_console.sanitize_discovery({
        "clients": ["a string, not a client", {"client": "C" * 999, "surprise": object()}],
        "processes": [{"pid": "not an int", "kind": "x", "label": "y", "command": "z"}],
        "something-else": {"a": 1},
    })
    assert set(cleaned) == {"clients", "processes"}
    assert len(cleaned["clients"]) == 1, "a non-dict entry is skipped, not rendered"
    assert len(cleaned["clients"][0]["client"]) == 300, "strings are capped"
    assert "surprise" not in cleaned["clients"][0], "unknown keys are dropped"
    assert cleaned["processes"][0]["pid"] == -1


def test_the_web_summary_describes_the_rendered_rows() -> None:
    """It is computed from the lists, not from a `summary` block the
    sanitizer drops — which is how it reported "0 clients" next to a list of
    them the first time the page ran."""
    raw = dict(SAMPLE_PASTE)
    web = haldir_console.sanitize_discovery(raw)
    assert haldir_console.summarize(raw) == haldir_console.summarize(web)
    assert "1 client" in haldir_console.summarize(web)
    assert "1 ungoverned" in haldir_console.summarize(web)
    assert "2 governed agents" in haldir_console.summarize(web, {"summary": {"agents": 2}})


def test_the_console_endpoint_merges_the_paste_with_the_register(
    haldir_client, bootstrap_key, tmp_path
) -> None:
    import api
    tenant = haldir_client.get(
        "/v1/admin/overview", headers=_auth(bootstrap_key)
    ).get_json()["tenant_id"]
    api.gate.create_session("web-console-agent", scopes=["read"], tenant_id=tenant)

    r = haldir_client.post("/v1/console/rows",
                           json={"discovery": SAMPLE_PASTE},
                           headers=_auth(bootstrap_key))
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert set(body) == {"summary", "snippet", "rows"}
    names = {row["name"] for row in body["rows"]}
    assert {"Claude Code", "exposureguard", "Ollama #1316", "web-console-agent"} <= names
    assert body["snippet"].startswith('{"mcpServers"')


def test_the_console_endpoint_works_without_a_paste(haldir_client, bootstrap_key) -> None:
    """No paste means "show me what Haldir governs" — the page's default
    state, and the only half a website can see by itself."""
    body = haldir_client.post("/v1/console/rows", json={},
                              headers=_auth(bootstrap_key)).get_json()
    assert body["rows"], "the register should still render"
    assert all(row["group"] == "Governed by Haldir" for row in body["rows"])


def test_a_junk_paste_is_empty_not_an_error(haldir_client, bootstrap_key) -> None:
    for junk in ("lol", 42, [], {"clients": "nope"}):
        r = haldir_client.post("/v1/console/rows", json={"discovery": junk},
                               headers=_auth(bootstrap_key))
        assert r.status_code == 200, f"{junk!r} should not 500"
        assert isinstance(r.get_json()["rows"], list)


def test_an_oversize_paste_is_refused_before_it_is_parsed(haldir_client, bootstrap_key) -> None:
    huge = {"clients": [{"client": "x" * 1000, "config_path": "y" * 1000,
                         "servers": {f"s{i}": "z" * 900 for i in range(400)}}]}
    # Assert the fixture is actually over the limit: the first version of this
    # test was 200 KB against a 256 KB cap, and passed for the wrong reason.
    assert len(json.dumps(huge)) > haldir_console.MAX_PASTE_BYTES

    r = haldir_client.post("/v1/console/rows", json={"discovery": huge},
                           headers=_auth(bootstrap_key))
    assert r.status_code == 413
    assert r.get_json()["code"] == "payload_too_large"


def test_the_console_endpoint_needs_a_key(haldir_client) -> None:
    assert haldir_client.post("/v1/console/rows", json={}).status_code == 401


def test_the_console_page_needs_a_valid_key(haldir_client, bootstrap_key) -> None:
    assert haldir_client.get("/console").status_code == 302
    assert haldir_client.get("/console?key=not-a-key").status_code == 302
    page = haldir_client.get(f"/console?key={bootstrap_key}")
    assert page.status_code == 200
    body = page.data.decode()
    assert "haldir discover --json" in body, "the paste hint is the whole on-ramp"
    assert "noindex" in body, "the page carries a key in its URL"
    assert "/v1/console/rows" in body


def test_the_console_page_reads_fields_the_endpoint_returns(
    haldir_client, bootstrap_key
) -> None:
    """The same contract the dashboard pages are held to: the page renders
    whatever the endpoint returns, so a rename on either side must fail here
    rather than blanking a column."""
    page = haldir_client.get(f"/console?key={bootstrap_key}").data.decode()
    reads = set(re.findall(r"\brow\.([a-zA-Z_]+)", page))
    assert reads, "the parse found no row fields — the page's script moved"

    body = haldir_client.post("/v1/console/rows", json={"discovery": SAMPLE_PASTE},
                              headers=_auth(bootstrap_key)).get_json()
    keys = set(body["rows"][0])
    missing = reads - keys
    assert not missing, f"the console page reads {sorted(missing)}, which /v1/console/rows does not return"
