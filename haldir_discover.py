"""Find the AI agents and MCP servers already on this machine.

Why this exists
---------------
The register lists agents that have *acted through Haldir*. That is the right
answer to "what is governed" and the wrong answer to "what do I even have" —
and until someone can answer the second, the first has nothing to attach to.
So this scans the machine: the MCP clients configured on it, the servers those
clients are told to launch, and the processes that look like agents.

When it runs, one of the findings is a suggestion to bring each ungoverned
server in through Haldir. That is the product's on-ramp, and it only works if
the scan is trustworthy first.

Design rules
------------
* **Read-only.** Nothing here writes, launches, or connects to anything.
  Discovery that starts processes is a different feature with a different
  consent story.
* **Stdlib only**, like `haldir top`. A scanner that needs a dependency tree
  before it can tell you what you have is not a scanner people run.
* **Redacted.** Command lines carry API keys in practice — an MCP server
  launched with `--token sk-...` is the common case, not the exotic one. Every
  string that reaches a finding goes through `_redact`, because discovery
  output gets pasted into issues and chat windows.
* **Known locations, not a filesystem crawl.** The clients that exist have
  defined config paths per platform. Sweeping a home directory for "anything
  that looks like JSON" is slow, noisy, and reads files that are none of its
  business.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

# ── Where the clients keep their configuration ─────────────────────────
#
# `{home}` is substituted; a path that does not exist is simply skipped. The
# list is deliberately short: a client is here because its config path is
# documented and stable, and a wrong guess costs a false "not found".
MCP_CLIENT_CONFIGS: tuple[dict[str, str], ...] = (
    {"client": "Claude Code", "path": "{home}/.claude.json"},
    {"client": "Claude Desktop",
     "path": "{home}/.config/Claude/claude_desktop_config.json"},
    {"client": "Claude Desktop (macOS)",
     "path": "{home}/Library/Application Support/Claude/claude_desktop_config.json"},
    {"client": "Cursor", "path": "{home}/.cursor/mcp.json"},
    {"client": "Cursor (global)", "path": "{home}/.cursor/mcp-global.json"},
    {"client": "Windsurf", "path": "{home}/.codeium/windsurf/mcp_config.json"},
    {"client": "Zed", "path": "{home}/.config/zed/settings.json"},
    {"client": "VS Code", "path": "{home}/.config/Code/User/settings.json"},
    {"client": "VS Code (Insiders)", "path": "{home}/.config/Code - Insiders/User/settings.json"},
    {"client": "Cline (VS Code)", "path": "{home}/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"},
)

#: Keys a config may nest its servers under. Clients disagree, and guessing
#: one spelling is how a detector reports "nothing configured" on a machine
#: with five servers on it.
_SERVER_KEYS = ("mcpServers", "mcp_servers", "servers", "mcp.servers")

# ── Process classification ─────────────────────────────────────────────
#
# Matched case-insensitively against the command line. Order matters: the
# first hit wins, so the more specific patterns come first.
_PROCESS_PATTERNS: tuple[tuple[str, str, str], ...] = (
    # (needle,                      kind,             label)
    ("@modelcontextprotocol/",     "mcp-server",     "MCP server (official SDK)"),
    ("mcp-server-",                "mcp-server",     "MCP server"),
    ("mcp_server",                 "mcp-server",     "MCP server"),
    ("haldir serve",               "governed",       "Haldir (already governed)"),
    ("haldir_mcp_server",          "governed",       "Haldir MCP server"),
    ("haldir_mcp_proxy",           "governed",       "Haldir MCP proxy"),
    ("claude",                     "coding-agent",   "Claude"),
    ("codex",                      "coding-agent",   "Codex CLI"),
    ("opencode",                   "coding-agent",   "opencode"),
    ("cursor",                     "coding-agent",   "Cursor"),
    ("windsurf",                   "coding-agent",   "Windsurf"),
    ("cline",                      "coding-agent",   "Cline"),
    ("roo-code",                   "coding-agent",   "Roo Code"),
    ("aider",                      "coding-agent",   "Aider"),
    ("goose",                      "coding-agent",   "Goose"),
    ("continue",                   "coding-agent",   "Continue"),
    ("langgraph",                  "agent-framework", "LangGraph"),
    ("langchain",                  "agent-framework", "LangChain"),
    ("crewai",                     "agent-framework", "CrewAI"),
    ("autogen",                    "agent-framework", "AutoGen"),
    ("llamaindex",                 "agent-framework", "LlamaIndex"),
    ("llama_index",                "agent-framework", "LlamaIndex"),
    ("smolagents",                 "agent-framework", "smolagents"),
    ("pydantic_ai",                "agent-framework", "Pydantic AI"),
    ("openai-agents",              "agent-framework", "OpenAI Agents SDK"),
    ("ollama",                     "llm-runtime",    "Ollama"),
    ("llama-server",               "llm-runtime",    "llama.cpp server"),
    ("vllm",                       "llm-runtime",    "vLLM"),
    ("text-generation-server",     "llm-runtime",    "TGI"),
    ("lmstudio",                   "llm-runtime",    "LM Studio"),
)

#: Command lines that contain these are tools, shells or editors — noise the
#: scanner would otherwise report as agents on a developer's machine.
_NOISE = (
    # Ourselves — as a script path *or* as an import inside a `-c` payload,
    # which is how this scanner classified itself as an agent the first time
    # it ran.
    "haldir_discover", "haldir_console",
    "grep", "rg ", "find ", "ps ", "top ", "htop",
)

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # KEY=value / --key value / "key": "value" — the flag names that hold
    # credentials, whatever the value looks like.
    (re.compile(r"(?i)\b([\w-]*(?:api[_-]?key|token|secret|password|passwd|bearer)[\w-]*)([=:\s]+)([^\s,;\"']+)"),
     r"\1\2***"),
    # Recognisable token shapes, for values not preceded by a flag name.
    (re.compile(r"\b(sk|pk|ghp|gho|ghs|xoxb|xoxp|hld)_[A-Za-z0-9_\-]{6,}"), r"\1_***"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA***"),
)


def _redact(text: str) -> str:
    """Strip credentials from a string that is about to be reported.

    Discovery output ends up in issues, chat messages and screenshots. A
    command line is exactly where an API key lives.
    """
    out = text
    for pattern, replacement in _SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def _looks_like_noise(cmdline: str) -> bool:
    low = cmdline.lower()
    return any(n in low for n in _NOISE)


def _servers_from_config(data: Any) -> dict[str, str]:
    """Pull `name -> redacted command` out of whatever shape a client uses.

    A value that is a plain string (some clients accept a URL) is kept as-is;
    a dict is rendered from its `command`/`args`/`url` fields; anything else is
    reported as configured-but-unreadable rather than dropped — a server the
    operator added and the scanner silently ignores is a worse answer than one
    it reports as opaque.
    """
    if not isinstance(data, dict):
        return {}
    for key in _SERVER_KEYS:
        servers = data.get(key)
        if isinstance(servers, dict):
            out: dict[str, str] = {}
            for name, spec in servers.items():
                if isinstance(spec, str):
                    out[str(name)] = _redact(spec)
                elif isinstance(spec, dict):
                    parts = [str(spec.get("command", ""))]
                    args = spec.get("args")
                    if isinstance(args, list):
                        parts.extend(str(a) for a in args)
                    url = spec.get("url") or spec.get("serverUrl")
                    if url:
                        parts.append(str(url))
                    out[str(name)] = _redact(" ".join(p for p in parts if p).strip()) or "(configured)"
                else:
                    out[str(name)] = "(configured, unrecognised shape)"
            return out
    return {}


def scan_clients(home: str) -> list[dict[str, Any]]:
    """The MCP clients configured on this machine, and what they can launch."""
    found: list[dict[str, Any]] = []
    for entry in MCP_CLIENT_CONFIGS:
        path = entry["path"].format(home=home)
        if not os.path.isfile(path):
            continue
        record: dict[str, Any] = {
            "client": entry["client"],
            "config_path": path,
            "readable": False,
            "servers": {},
            "note": "",
        }
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
            record["readable"] = True
            record["servers"] = _servers_from_config(data)
        except (OSError, ValueError) as err:
            # A config that will not parse is a finding, not an error: the
            # client is installed and pointing at something, and the operator
            # should know the scanner could not read it.
            record["note"] = f"could not read: {type(err).__name__}"
        found.append(record)
    return found


def _command_head(cmdline: str, tokens: int = 3) -> str:
    """The first few tokens of a command line — what is being *run*.

    Matching against the whole line is how a shell wrapper whose `-c` payload
    mentions `.claude/shell-snapshots` gets reported as an agent, and how a
    `python -c "import langchain"` one-liner does too. The executable and its
    first arguments are the signal; the rest is a payload, a path, or a
    heredoc. Three tokens covers the shapes that matter — `ollama serve`,
    `python -m crewai`, `npx @modelcontextprotocol/server-x`, `uvx mcp-server-y`.
    """
    parts = cmdline.split()
    head = parts[:tokens]
    # `/usr/local/bin/ollama serve` should be recognised as `ollama`.
    if head:
        head[0] = os.path.basename(head[0])
    return " ".join(head)


def _classify(command_head: str) -> tuple[str, str] | None:
    low = command_head.lower()
    for needle, kind, label in _PROCESS_PATTERNS:
        if needle in low:
            return kind, label
    return None


def scan_processes(proc_root: str = "/proc", limit: int = 400) -> list[dict[str, Any]]:
    """Processes that look like agents or MCP servers.

    `proc_root` is a parameter so the scanner can be tested against a synthetic
    tree — the alternative is a test that only passes on Linux with the right
    processes running, which is a test that passes for the wrong reasons.
    """
    found: list[dict[str, Any]] = []
    try:
        pids = sorted(p for p in os.listdir(proc_root) if p.isdigit())
    except OSError:
        return found

    for pid in pids:
        if len(found) >= limit:
            break
        try:
            with open(os.path.join(proc_root, pid, "cmdline"), "rb") as fh:
                raw = fh.read()
        except OSError:
            continue  # a process that exited, or not ours to read
        if not raw:
            continue
        cmdline = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        if not cmdline or _looks_like_noise(cmdline):
            continue
        classified = _classify(_command_head(cmdline))
        if not classified:
            continue
        kind, label = classified
        found.append({
            "pid": int(pid),
            "kind": kind,
            "label": label,
            "command": _redact(cmdline[:300]),
        })
    return found


def discover(
    home: str | None = None,
    proc_root: str = "/proc",
    clients: bool = True,
    processes: bool = True,
) -> dict[str, Any]:
    """Everything the scanner can see, in one payload.

    Local only. No network call, no Haldir instance required — the console
    combines this with the register when one is configured, but the scan
    itself has to work on a machine that has never heard of Haldir.
    """
    home = home or os.path.expanduser("~")
    out: dict[str, Any] = {
        "home": home,
        "clients": scan_clients(home) if clients else [],
        "processes": scan_processes(proc_root) if processes else [],
    }
    servers = sum(len(c["servers"]) for c in out["clients"])
    out["summary"] = {
        "clients": len(out["clients"]),
        "configured_servers": servers,
        "processes": len(out["processes"]),
        "governed_processes": sum(1 for p in out["processes"] if p["kind"] == "governed"),
        "ungoverned_servers": sum(
            1 for c in out["clients"] for spec in c["servers"].values()
            if "haldir" not in spec.lower()
        ),
        "unreadable_configs": sum(1 for c in out["clients"] if not c["readable"]),
    }
    return out
