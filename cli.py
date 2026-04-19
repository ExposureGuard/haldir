#!/usr/bin/env python3
"""
Haldir CLI — command-line interface for the Haldir agent governance API.

Manage sessions, secrets, payments, audit, and proxy from the terminal.

Usage:
    python3 cli.py <command> <subcommand> [options]
    haldir <command> <subcommand> [options]          # if installed via pip

Examples:
    haldir login
    haldir session create --agent my-bot --scopes read,browse --budget 50
    haldir secret store STRIPE_KEY sk_live_xxx
    haldir audit trail --agent my-bot --limit 20
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

# ── Config ──

CONFIG_DIR = Path.home() / ".haldir"
CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_BASE_URL = "https://haldir.xyz"


def load_config() -> dict:
    """Load config from ~/.haldir/config.json, return empty dict if missing."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_config(config: dict) -> None:
    """Write config to ~/.haldir/config.json, creating the directory if needed."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2) + "\n")
    # Restrict permissions — config contains the API key
    CONFIG_FILE.chmod(0o600)


def get_api_key() -> str:
    """Resolve API key from env var, then config file."""
    key = os.environ.get("HALDIR_API_KEY", "")
    if key:
        return key
    config = load_config()
    return config.get("api_key", "")


def get_base_url() -> str:
    """Resolve base URL from env var, then config file, then default."""
    url = os.environ.get("HALDIR_BASE_URL", "")
    if url:
        return url.rstrip("/")
    config = load_config()
    return config.get("base_url", DEFAULT_BASE_URL).rstrip("/")


# ── Terminal colors ──

class Color:
    """ANSI color codes. Disabled when stdout is not a TTY."""
    _enabled = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    RESET = "\033[0m" if _enabled else ""
    BOLD = "\033[1m" if _enabled else ""
    DIM = "\033[2m" if _enabled else ""

    GREEN = "\033[32m" if _enabled else ""
    RED = "\033[31m" if _enabled else ""
    YELLOW = "\033[33m" if _enabled else ""
    CYAN = "\033[36m" if _enabled else ""
    MAGENTA = "\033[35m" if _enabled else ""
    WHITE = "\033[97m" if _enabled else ""


def success(msg: str) -> None:
    print(f"{Color.GREEN}{Color.BOLD}[+]{Color.RESET} {msg}")


def error(msg: str) -> None:
    print(f"{Color.RED}{Color.BOLD}[-]{Color.RESET} {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"{Color.YELLOW}{Color.BOLD}[!]{Color.RESET} {msg}")


def info(msg: str) -> None:
    print(f"{Color.CYAN}[*]{Color.RESET} {msg}")


def mono(value: str) -> str:
    """Wrap a value in bold white for monospace emphasis."""
    return f"{Color.WHITE}{Color.BOLD}{value}{Color.RESET}"


def label(key: str, value: Any) -> None:
    """Print a key-value pair with dim key and bold value."""
    print(f"  {Color.DIM}{key}:{Color.RESET} {Color.WHITE}{value}{Color.RESET}")


def print_json_table(data: dict, indent: int = 2) -> None:
    """Print a dict as a clean labeled table."""
    prefix = " " * indent
    for k, v in data.items():
        if isinstance(v, dict):
            print(f"{prefix}{Color.DIM}{k}:{Color.RESET}")
            print_json_table(v, indent + 2)
        elif isinstance(v, list):
            print(f"{prefix}{Color.DIM}{k}:{Color.RESET} {Color.WHITE}{', '.join(str(i) for i in v) if v else '(none)'}{Color.RESET}")
        elif isinstance(v, bool):
            color = Color.GREEN if v else Color.RED
            print(f"{prefix}{Color.DIM}{k}:{Color.RESET} {color}{v}{Color.RESET}")
        elif isinstance(v, float):
            print(f"{prefix}{Color.DIM}{k}:{Color.RESET} {Color.WHITE}{v:.2f}{Color.RESET}")
        else:
            print(f"{prefix}{Color.DIM}{k}:{Color.RESET} {Color.WHITE}{v}{Color.RESET}")


# ── HTTP client ──

class APIClient:
    """Thin wrapper around httpx for Haldir API calls."""

    def __init__(self, api_key: str = "", base_url: str = ""):
        self.api_key = api_key or get_api_key()
        self.base_url = base_url or get_base_url()

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def request(self, method: str, path: str, **kwargs: Any) -> dict:
        """Make a request, return parsed JSON. Exits on error."""
        url = f"{self.base_url}{path}"
        try:
            resp = httpx.request(
                method, url,
                headers=self._headers(),
                timeout=30.0,
                **kwargs,
            )
        except httpx.ConnectError:
            error(f"Cannot connect to {self.base_url}")
            error("Is the Haldir server running? Check your base_url config.")
            sys.exit(1)
        except httpx.TimeoutException:
            error(f"Request timed out: {method} {path}")
            sys.exit(1)

        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text}

        if resp.status_code >= 400:
            msg = body.get("error") or body.get("reason") or resp.text
            if resp.status_code == 401:
                error(f"Authentication failed: {msg}")
                warn("Run 'haldir login' to set your API key.")
            elif resp.status_code == 403:
                error(f"Permission denied: {msg}")
            elif resp.status_code == 404:
                error(f"Not found: {msg}")
            elif resp.status_code == 429:
                error(f"Rate limited: {msg}")
                retry = body.get("retry_after")
                if retry:
                    warn(f"Retry after {retry}s")
            else:
                error(f"API error ({resp.status_code}): {msg}")
            sys.exit(1)

        return body

    def get(self, path: str, **kwargs: Any) -> dict:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> dict:
        return self.request("POST", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> dict:
        return self.request("DELETE", path, **kwargs)


# ── Commands ──

def cmd_login(args: argparse.Namespace) -> None:
    """Prompt for API key and save to config."""
    config = load_config()

    print(f"{Color.BOLD}Haldir Login{Color.RESET}")
    print()

    if args.key:
        api_key = args.key
    else:
        api_key = getpass.getpass("API key (hld_...): ").strip()

    if not api_key:
        error("No API key provided.")
        sys.exit(1)

    if not api_key.startswith("hld_"):
        warn("Key does not start with 'hld_' — are you sure this is correct?")

    # Optionally set base URL
    base_url = args.url or config.get("base_url", DEFAULT_BASE_URL)

    # Verify the key works
    info(f"Verifying key against {base_url}...")
    client = APIClient(api_key=api_key, base_url=base_url)
    try:
        result = client.get("/v1/usage")
        tier = result.get("tier", "unknown")
        success(f"Authenticated! Tier: {mono(tier)}")
    except SystemExit:
        error("Key verification failed. Saving anyway in case the server is down.")

    config["api_key"] = api_key
    config["base_url"] = base_url
    save_config(config)
    success(f"Config saved to {mono(str(CONFIG_FILE))}")


def cmd_keys_create(args: argparse.Namespace) -> None:
    """Create a new API key with optional per-key scopes."""
    client = APIClient()
    payload: dict[str, Any] = {"name": args.name}
    if args.tier:
        payload["tier"] = args.tier
    if args.scopes:
        # Comma-separated for ergonomics; the API accepts both list
        # and string form (haldir_scopes.parse() normalizes either).
        payload["scopes"] = [s.strip() for s in args.scopes.split(",") if s.strip()]

    result = client.post("/v1/keys", json=payload)

    success("API key created")
    print()
    label("Key", result["key"])
    label("Prefix", result.get("prefix", ""))
    label("Name", result.get("name", ""))
    label("Tier", result.get("tier", ""))
    if result.get("scopes"):
        label("Scopes", ", ".join(result["scopes"]))
    print()
    warn("Save this key now — it will not be shown again.")


# ── Session commands ──

def cmd_session_create(args: argparse.Namespace) -> None:
    """Create an agent session."""
    client = APIClient()
    payload: dict[str, Any] = {"agent_id": args.agent}

    if args.scopes:
        payload["scopes"] = [s.strip() for s in args.scopes.split(",")]
    if args.ttl:
        payload["ttl"] = args.ttl
    if args.budget is not None:
        payload["spend_limit"] = args.budget

    result = client.post("/v1/sessions", json=payload)

    success("Session created")
    print()
    label("Session ID", result["session_id"])
    label("Agent", result["agent_id"])
    label("Scopes", ", ".join(result.get("scopes", [])))
    label("Spend Limit", result.get("spend_limit") or "unlimited")
    label("TTL", f"{result.get('ttl', 3600)}s")
    expires = result.get("expires_at")
    if expires:
        label("Expires", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(expires)))


def cmd_session_get(args: argparse.Namespace) -> None:
    """Get session details."""
    client = APIClient()
    result = client.get(f"/v1/sessions/{args.session_id}")

    valid = result.get("is_valid", False)
    status_color = Color.GREEN if valid else Color.RED
    status_text = "ACTIVE" if valid else "EXPIRED/REVOKED"

    print(f"{Color.BOLD}Session{Color.RESET} {mono(result['session_id'])}")
    print(f"  {Color.DIM}Status:{Color.RESET} {status_color}{Color.BOLD}{status_text}{Color.RESET}")
    label("Agent", result["agent_id"])
    label("Scopes", ", ".join(result.get("scopes", [])))
    label("Spend Limit", result.get("spend_limit") or "unlimited")
    label("Spent", f"${result.get('spent', 0):.2f}")
    remaining = result.get("remaining_budget")
    if remaining is not None:
        label("Remaining", f"${remaining:.2f}")
    expires = result.get("expires_at")
    if expires:
        label("Expires", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(expires)))


def cmd_session_revoke(args: argparse.Namespace) -> None:
    """Revoke a session."""
    client = APIClient()
    client.delete(f"/v1/sessions/{args.session_id}")
    success(f"Session {mono(args.session_id)} revoked")


def cmd_session_check(args: argparse.Namespace) -> None:
    """Check if a session has a specific permission."""
    client = APIClient()
    result = client.post(
        f"/v1/sessions/{args.session_id}/check",
        json={"scope": args.scope},
    )

    allowed = result.get("allowed", False)
    if allowed:
        success(f"Session has {mono(args.scope)} permission")
    else:
        error(f"Session does NOT have {mono(args.scope)} permission")


# ── Secret commands ──

def cmd_secret_store(args: argparse.Namespace) -> None:
    """Store a secret in the vault."""
    client = APIClient()
    payload: dict[str, Any] = {"name": args.name, "value": args.value}
    if args.scope:
        payload["scope_required"] = args.scope

    client.post("/v1/secrets", json=payload)
    success(f"Secret {mono(args.name)} stored")


def cmd_secret_get(args: argparse.Namespace) -> None:
    """Retrieve a secret from the vault."""
    client = APIClient()
    headers = {}
    if args.session:
        headers["X-Session-ID"] = args.session

    result = client.request("GET", f"/v1/secrets/{args.name}", headers=headers)

    print(f"{Color.BOLD}Secret{Color.RESET} {mono(result['name'])}")
    label("Value", result["value"])


def cmd_secret_list(args: argparse.Namespace) -> None:
    """List all secrets in the vault."""
    client = APIClient()
    result = client.get("/v1/secrets")

    secrets_list = result.get("secrets", [])
    count = result.get("count", len(secrets_list))

    info(f"{count} secret(s) in vault")
    if secrets_list:
        print()
        for name in secrets_list:
            print(f"  {Color.MAGENTA}*{Color.RESET} {mono(name)}")


def cmd_secret_delete(args: argparse.Namespace) -> None:
    """Delete a secret from the vault."""
    client = APIClient()
    client.delete(f"/v1/secrets/{args.name}")
    success(f"Secret {mono(args.name)} deleted")


# ── Payment commands ──

def cmd_pay_authorize(args: argparse.Namespace) -> None:
    """Authorize a payment against a session's budget."""
    client = APIClient()
    payload: dict[str, Any] = {
        "session_id": args.session_id,
        "amount": args.amount,
    }
    if args.currency:
        payload["currency"] = args.currency
    if args.description:
        payload["description"] = args.description

    result = client.post("/v1/payments/authorize", json=payload)

    authorized = result.get("authorized", False)
    if authorized:
        success(f"Payment of ${args.amount:.2f} authorized")
        remaining = result.get("remaining_budget")
        if remaining is not None:
            label("Remaining Budget", f"${remaining:.2f}")
    else:
        error(f"Payment of ${args.amount:.2f} denied")
        reason = result.get("reason", "")
        if reason:
            label("Reason", reason)


# ── Audit commands ──

def cmd_audit_log(args: argparse.Namespace) -> None:
    """Log an auditable action."""
    client = APIClient()
    payload: dict[str, Any] = {
        "session_id": args.session_id,
        "action": args.action,
    }
    if args.tool:
        payload["tool"] = args.tool
    if args.cost is not None:
        payload["cost_usd"] = args.cost
    if args.details:
        try:
            payload["details"] = json.loads(args.details)
        except json.JSONDecodeError:
            error("--details must be valid JSON")
            sys.exit(1)

    result = client.post("/v1/audit", json=payload)

    success(f"Action logged: {mono(result.get('entry_id', 'ok'))}")
    if result.get("flagged"):
        warn(f"FLAGGED: {result.get('flag_reason', 'anomaly detected')}")


def cmd_audit_trail(args: argparse.Namespace) -> None:
    """Query the audit trail."""
    client = APIClient()
    params: dict[str, Any] = {}
    if args.session:
        params["session_id"] = args.session
    if args.agent:
        params["agent_id"] = args.agent
    if args.tool:
        params["tool"] = args.tool
    if args.flagged:
        params["flagged"] = "true"
    if args.limit:
        params["limit"] = args.limit

    result = client.get("/v1/audit", params=params)

    entries = result.get("entries", [])
    count = result.get("count", len(entries))

    info(f"{count} audit entries")
    print()

    if not entries:
        print(f"  {Color.DIM}(no entries){Color.RESET}")
        return

    for entry in entries:
        ts = entry.get("timestamp", 0)
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)) if ts else "?"
        flagged = entry.get("flagged", False)
        flag_marker = f" {Color.RED}FLAGGED{Color.RESET}" if flagged else ""

        tool_str = entry.get("tool", "")
        action_str = entry.get("action", "")
        cost = entry.get("cost_usd", 0)

        print(f"  {Color.DIM}{ts_str}{Color.RESET}  "
              f"{mono(entry.get('entry_id', '')[:12])}  "
              f"{Color.CYAN}{entry.get('agent_id', '')}{Color.RESET}  "
              f"{tool_str}:{action_str}"
              f"{f'  ${cost:.2f}' if cost else ''}"
              f"{flag_marker}")


def cmd_audit_spend(args: argparse.Namespace) -> None:
    """Get spend summary."""
    client = APIClient()
    params: dict[str, Any] = {}
    if args.session:
        params["session_id"] = args.session
    if args.agent:
        params["agent_id"] = args.agent

    result = client.get("/v1/audit/spend", params=params)

    total = result.get("total_usd", 0)
    print(f"{Color.BOLD}Spend Summary{Color.RESET}")
    print()
    label("Total", f"${total:.2f}")

    by_tool = result.get("by_tool", {})
    if by_tool:
        print()
        print(f"  {Color.DIM}By tool:{Color.RESET}")
        for tool, amount in by_tool.items():
            print(f"    {Color.MAGENTA}{tool}{Color.RESET}: ${amount:.2f}")


# ── Proxy commands ──

def cmd_proxy_register(args: argparse.Namespace) -> None:
    """Register an upstream MCP server."""
    client = APIClient()
    result = client.post("/v1/proxy/upstreams", json={
        "name": args.name,
        "url": args.url,
    })

    healthy = result.get("healthy", False)
    tools_count = result.get("tools_discovered", 0)

    if healthy:
        success(f"Upstream {mono(args.name)} registered ({tools_count} tools discovered)")
    else:
        warn(f"Upstream {mono(args.name)} registered but is NOT healthy")
        err = result.get("error")
        if err:
            error(f"  {err}")

    tool_names = result.get("tool_names", [])
    if tool_names:
        print()
        info("Discovered tools:")
        for name in tool_names:
            print(f"  {Color.MAGENTA}*{Color.RESET} {mono(name)}")


def cmd_proxy_tools(args: argparse.Namespace) -> None:
    """List all tools available through the proxy."""
    client = APIClient()
    result = client.get("/v1/proxy/tools")

    tools = result.get("tools", [])
    count = result.get("count", len(tools))

    info(f"{count} tool(s) available")
    print()

    if not tools:
        print(f"  {Color.DIM}(no tools — register an upstream first){Color.RESET}")
        return

    for tool in tools:
        upstream = tool.get("upstream", "")
        desc = tool.get("description", "")
        print(f"  {Color.MAGENTA}*{Color.RESET} {mono(tool['name'])}"
              f"{Color.DIM} ({upstream}){Color.RESET}"
              f"{f' — {desc[:60]}' if desc else ''}")


def cmd_proxy_call(args: argparse.Namespace) -> None:
    """Call a tool through the Haldir proxy."""
    client = APIClient()

    arguments = {}
    if args.args:
        try:
            arguments = json.loads(args.args)
        except json.JSONDecodeError:
            error("--args must be valid JSON")
            sys.exit(1)

    result = client.post("/v1/proxy/call", json={
        "tool": args.tool,
        "arguments": arguments,
        "session_id": args.session,
    })

    is_error = result.get("isError", False)
    content = result.get("content", [])

    if is_error:
        error("Tool call blocked or failed")
        for item in content:
            text = item.get("text", "")
            try:
                parsed = json.loads(text)
                if "error" in parsed:
                    error(f"  {parsed['error']}")
                else:
                    print(json.dumps(parsed, indent=2))
            except json.JSONDecodeError:
                print(f"  {text}")
    else:
        success("Tool call succeeded")
        for item in content:
            text = item.get("text", "")
            try:
                parsed = json.loads(text)
                print(json.dumps(parsed, indent=2))
            except json.JSONDecodeError:
                print(text)


def cmd_proxy_policy_add(args: argparse.Namespace) -> None:
    """Add a governance policy to the proxy."""
    client = APIClient()
    payload: dict[str, Any] = {"type": args.type}

    if args.tool:
        payload["tool"] = args.tool
    if args.tools:
        payload["tools"] = [t.strip() for t in args.tools.split(",")]
    if args.max is not None:
        payload["max"] = args.max
    if args.max_per_minute is not None:
        payload["max_per_minute"] = args.max_per_minute
    if args.start_hour is not None:
        payload["start_hour"] = args.start_hour
    if args.end_hour is not None:
        payload["end_hour"] = args.end_hour

    client.post("/v1/proxy/policies", json=payload)
    success(f"Policy {mono(args.type)} added")


# ── Metrics ──

def cmd_metrics(args: argparse.Namespace) -> None:
    """Show platform metrics."""
    client = APIClient()
    result = client.get("/v1/metrics")

    print(f"{Color.BOLD}Haldir Metrics{Color.RESET}")
    print()
    print_json_table(result)


# ── Overview / status / ready (the screenshot moments) ──────────────

def _state_pill(state: str) -> str:
    """Render an inline status pill: ●  with color matching the state."""
    color = {
        "ok":       Color.GREEN,
        "ready":    Color.GREEN,
        "alive":    Color.GREEN,
        "degraded": Color.YELLOW,
        "down":     Color.RED,
    }.get(state, Color.DIM)
    return f"{color}●{Color.RESET} {state}"


def _bar(pct: float, width: int = 20) -> str:
    """Inline progress bar — 20 cells, color shifts as you approach 1.0."""
    pct = max(0.0, min(1.0, pct))
    filled = int(round(pct * width))
    color = (
        Color.GREEN  if pct < 0.7 else
        Color.YELLOW if pct < 0.9 else
        Color.RED
    )
    return f"{color}{'█' * filled}{Color.DIM}{'░' * (width - filled)}{Color.RESET}"


def _render_overview(o: dict) -> None:
    """Pretty-print the /v1/admin/overview payload. The screenshot
    moment for the README + tweets — every value is laid out in the
    visual hierarchy a reader would scan top-down."""
    print()
    print(f"  {Color.BOLD}Haldir tenant overview{Color.RESET}")
    print(f"  {Color.DIM}{o.get('tenant_id', '?')}  ·  tier "
          f"{Color.WHITE}{o.get('tier', '?')}{Color.RESET}{Color.DIM}  ·  "
          f"{o.get('generated_at', '')}{Color.RESET}")

    h = o.get("health", {})
    print()
    print(f"  {Color.DIM}Status{Color.RESET}     {_state_pill(h.get('status', 'ok'))}")

    u = o.get("usage", {})
    pct = float(u.get("actions_pct_used", 0.0))
    print(f"  {Color.DIM}Actions{Color.RESET}    {Color.WHITE}{u.get('actions_this_month', 0):>7,}{Color.RESET}"
          f" {Color.DIM}/{Color.RESET} {u.get('actions_limit', 0):,}"
          f"   {_bar(pct)}  {Color.DIM}{pct * 100:5.1f}%{Color.RESET}")
    print(f"  {Color.DIM}Spend{Color.RESET}      {Color.WHITE}${u.get('spend_usd_this_month', 0.0):>6.2f}{Color.RESET}"
          f" {Color.DIM}this month{Color.RESET}")

    s = o.get("sessions", {})
    print(f"  {Color.DIM}Sessions{Color.RESET}   {Color.WHITE}{s.get('active_count', 0):>7}{Color.RESET}"
          f" {Color.DIM}active  ·  {s.get('agents_active', 0)}/"
          f"{s.get('agents_limit', 0)} agents{Color.RESET}")

    v = o.get("vault", {})
    print(f"  {Color.DIM}Vault{Color.RESET}      {Color.WHITE}{v.get('secrets_count', 0):>7}{Color.RESET}"
          f" {Color.DIM}secrets  ·  {v.get('secret_access_count', 0)} accesses this month{Color.RESET}")

    a = o.get("audit", {})
    chain = "✓" if a.get("chain_verified") else "✗"
    chain_color = Color.GREEN if a.get("chain_verified") else Color.RED
    print(f"  {Color.DIM}Audit{Color.RESET}      {Color.WHITE}{a.get('total_entries', 0):>7,}{Color.RESET}"
          f" {Color.DIM}entries  ·  {a.get('flagged_7d', 0)} flagged (7d)  ·  "
          f"chain {chain_color}{chain}{Color.RESET}")

    w = o.get("webhooks", {})
    rate = float(w.get("delivery_success_rate_24h", 1.0))
    rate_color = Color.GREEN if rate >= 0.99 else (Color.YELLOW if rate >= 0.95 else Color.RED)
    print(f"  {Color.DIM}Webhooks{Color.RESET}   {Color.WHITE}{w.get('registered_count', 0):>7}{Color.RESET}"
          f" {Color.DIM}registered  ·  {w.get('deliveries_24h', 0)} deliveries (24h)  ·  "
          f"{rate_color}{rate * 100:.2f}%{Color.RESET}{Color.DIM} success{Color.RESET}")

    ap = o.get("approvals", {})
    pending = ap.get("pending_count", 0)
    pending_color = Color.YELLOW if pending else Color.DIM
    print(f"  {Color.DIM}Approvals{Color.RESET}  {pending_color}{pending:>7}{Color.RESET}"
          f" {Color.DIM}pending{Color.RESET}")

    c = o.get("compliance", {})
    next_due = c.get("next_due_at") or "—"
    sched_color = Color.GREEN if c.get("active_count") else Color.DIM
    print(f"  {Color.DIM}Compliance{Color.RESET} {sched_color}{c.get('active_count', 0):>7}{Color.RESET}"
          f" {Color.DIM}schedules  ·  next pack {next_due}{Color.RESET}")
    print()


def cmd_overview(args: argparse.Namespace) -> None:
    """Single-call tenant dashboard (calls /v1/admin/overview)."""
    client = APIClient()

    def _once() -> None:
        o = client.get("/v1/admin/overview")
        if getattr(args, "json", False):
            print(json.dumps(o, indent=2))
        else:
            _render_overview(o)

    if not getattr(args, "watch", False):
        _once()
        return

    # Live-refresh mode: redraw every interval seconds, top-style.
    interval = max(1.0, float(args.interval or 5.0))
    try:
        while True:
            sys.stdout.write("\033[2J\033[H")  # clear + home
            _once()
            sys.stdout.write(f"  {Color.DIM}refreshing every {interval:.0f}s — Ctrl+C to exit{Color.RESET}\n")
            sys.stdout.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        print()


def cmd_status(args: argparse.Namespace) -> None:
    """System health (calls /v1/status)."""
    client = APIClient()
    s = client.get("/v1/status")
    if getattr(args, "json", False):
        print(json.dumps(s, indent=2))
        return
    print()
    print(f"  {Color.BOLD}Haldir status{Color.RESET}    {_state_pill(s.get('status', 'ok'))}")
    print()
    for c in s.get("components", []):
        print(f"  {Color.DIM}{c['name']:10}{Color.RESET} {_state_pill(c['state'])}")
        print(f"             {Color.DIM}{c.get('message', '')}{Color.RESET}")
    print()
    m = s.get("metrics", {})
    sr = m.get("success_rate", {})
    lat = m.get("latency_seconds", {})
    print(f"  {Color.DIM}Success rate{Color.RESET} "
          f"{Color.WHITE}{sr.get('ratio', 1.0) * 100:.3f}%{Color.RESET} "
          f"{Color.DIM}({sr.get('total', 0)} requests){Color.RESET}")
    if lat.get("p95"):
        print(f"  {Color.DIM}Latency p95{Color.RESET}  "
              f"{Color.WHITE}{lat['p95'] * 1000:.0f} ms{Color.RESET}"
              f"   {Color.DIM}p99 {lat.get('p99', 0) * 1000:.0f} ms{Color.RESET}")
    print()


def cmd_ready(args: argparse.Namespace) -> None:
    """One-shot readiness check. Exits 0 if ready, 1 if not — useful
    for CI / pre-deploy gates."""
    client = APIClient()
    try:
        r = httpx.get(
            f"{client.base_url}/readyz",
            headers=client._headers(), timeout=5.0,
        )
        body = r.json()
    except Exception as e:
        error(f"Could not reach /readyz: {e}")
        sys.exit(2)
    if getattr(args, "json", False):
        print(json.dumps(body, indent=2))
        sys.exit(0 if body.get("ready") else 1)
    if body.get("ready"):
        success("ready")
    else:
        error("not ready")
    for c in body.get("checks", []):
        mark = f"{Color.GREEN}✓{Color.RESET}" if c["ok"] else f"{Color.RED}✗{Color.RESET}"
        print(f"  {mark} {c['name']:16} {Color.DIM}{c['message']}  ({c['duration_ms']} ms){Color.RESET}")
    sys.exit(0 if body.get("ready") else 1)


# ── Audit export + verify ────────────────────────────────────────────

def cmd_audit_export(args: argparse.Namespace) -> None:
    """Stream the audit trail to stdout (or --out FILE)."""
    client = APIClient()
    fmt = (args.format or "jsonl").lower()
    if fmt not in ("csv", "jsonl"):
        error(f"format must be csv or jsonl, got {fmt!r}")
        sys.exit(2)

    params: dict[str, str] = {"format": fmt}
    if args.since:
        params["since"] = args.since
    if args.until:
        params["until"] = args.until
    if args.session:
        params["session_id"] = args.session
    if args.agent:
        params["agent_id"] = args.agent
    if args.tool:
        params["tool"] = args.tool

    url = f"{client.base_url}/v1/audit/export"
    out = open(args.out, "w") if args.out else sys.stdout
    try:
        with httpx.stream("GET", url, params=params,
                          headers=client._headers(),
                          timeout=120.0) as r:
            if r.status_code != 200:
                error(f"export failed: HTTP {r.status_code}")
                sys.exit(1)
            for chunk in r.iter_text():
                out.write(chunk)
            if args.out:
                success(f"wrote {args.out}")
    finally:
        if args.out:
            out.close()


def cmd_audit_verify(args: argparse.Namespace) -> None:
    """Verify the hash chain integrity of the audit trail."""
    client = APIClient()
    r = client.get("/v1/audit/verify")
    if getattr(args, "json", False):
        print(json.dumps(r, indent=2))
        return
    verified = r.get("verified", False)
    if verified:
        success(f"chain verified — {r.get('entries_checked', 0)} entries")
    else:
        error(f"chain BROKEN at entry {r.get('first_break', '?')}")
        sys.exit(1)


# ── Webhooks: deliveries log ────────────────────────────────────────

def cmd_webhooks_deliveries(args: argparse.Namespace) -> None:
    """List recent webhook delivery attempts."""
    client = APIClient()
    params: dict[str, str] = {"limit": str(args.limit)}
    if args.event_id:
        params["event_id"] = args.event_id
    r = client.get("/v1/webhooks/deliveries", params=params)
    if getattr(args, "json", False):
        print(json.dumps(r, indent=2))
        return
    deliveries = r.get("deliveries", [])
    if not deliveries:
        info("no deliveries on record")
        return
    # Compact table.
    print()
    print(f"  {Color.DIM}{'when':>20}  {'event':>12}  {'status':>6}  "
          f"{'try':>3}  {'event_id':<12}  url{Color.RESET}")
    for d in deliveries:
        when = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.gmtime(float(d.get("created_at", 0))),
        )
        sc = int(d.get("status_code", 0))
        sc_color = (
            Color.GREEN if 200 <= sc < 300 else
            Color.YELLOW if 400 <= sc < 500 else
            Color.RED
        )
        print(f"  {Color.DIM}{when:>20}{Color.RESET}  "
              f"{Color.WHITE}{d.get('event_type', ''):>12}{Color.RESET}  "
              f"{sc_color}{sc:>6}{Color.RESET}  "
              f"{int(d.get('attempt', 1)):>3}  "
              f"{Color.DIM}{(d.get('event_id') or '')[:12]:<12}{Color.RESET}  "
              f"{Color.DIM}{d.get('webhook_url', '')[:60]}{Color.RESET}")
    print()


# ── Compliance evidence pack ────────────────────────────────────────

def cmd_compliance_schedules_list(args: argparse.Namespace) -> None:
    """List recurring evidence-pack schedules for the authed tenant."""
    client = APIClient()
    r = client.get("/v1/compliance/schedules")
    rows = r.get("schedules", [])
    if getattr(args, "json", False):
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        info("no schedules registered")
        return
    print()
    print(f"  {Color.DIM}{'id':>26}  {'name':<24}  cadence    next due  delivery{Color.RESET}")
    for s in rows:
        next_due = time.strftime(
            "%Y-%m-%d %H:%M",
            time.gmtime(float(s.get("next_due", 0))),
        )
        print(f"  {Color.WHITE}{s['schedule_id']:>26}{Color.RESET}  "
              f"{s['name']:<24}  {s['cadence']:<9}  {next_due}  "
              f"{Color.DIM}{s['delivery']}{Color.RESET}")
    print()


def cmd_compliance_schedules_create(args: argparse.Namespace) -> None:
    """Register a new schedule."""
    client = APIClient()
    r = client.post("/v1/compliance/schedules", json={
        "name":     args.name,
        "cadence":  args.cadence,
        "delivery": args.delivery,
    })
    success(f"schedule created: {r['schedule_id']}")
    label("Cadence",  r["cadence"])
    label("Delivery", r["delivery"])
    label("Next due", "immediately on first scheduler tick (last_run_at=0)")


def cmd_compliance_schedules_delete(args: argparse.Namespace) -> None:
    """Remove a schedule by id."""
    client = APIClient()
    url = f"{client.base_url}/v1/compliance/schedules/{args.schedule_id}"
    r = httpx.delete(url, headers=client._headers(), timeout=10.0)
    if r.status_code == 204:
        success(f"deleted {args.schedule_id}")
    elif r.status_code == 404:
        error("schedule not found")
        sys.exit(1)
    else:
        error(f"delete failed: HTTP {r.status_code} — {r.text}")
        sys.exit(1)


def cmd_compliance_evidence(args: argparse.Namespace) -> None:
    """Pull an auditor-ready proof-of-control pack."""
    client = APIClient()
    fmt = (args.format or "markdown").lower()
    params: dict[str, str] = {"format": fmt}
    if args.since:
        params["since"] = args.since
    if args.until:
        params["until"] = args.until

    url = f"{client.base_url}/v1/compliance/evidence"
    try:
        resp = httpx.get(url, params=params,
                         headers=client._headers(), timeout=60.0)
    except Exception as e:
        error(f"Could not reach /v1/compliance/evidence: {e}")
        sys.exit(2)
    if resp.status_code != 200:
        try:
            err = resp.json().get("error", resp.text)
        except Exception:
            err = resp.text
        error(f"evidence pack failed: HTTP {resp.status_code} — {err}")
        sys.exit(1)

    body = resp.text
    if args.out:
        with open(args.out, "w") as f:
            f.write(body)
        success(f"wrote {args.out}")
        digest = resp.headers.get("X-Haldir-Evidence-Digest", "")
        if digest:
            label("Digest", digest)
    else:
        sys.stdout.write(body)
        if not body.endswith("\n"):
            sys.stdout.write("\n")


# ── Migrations (local; wraps haldir_migrate) ────────────────────────

def cmd_migrate(args: argparse.Namespace) -> None:
    """Apply / inspect schema migrations against the local DB."""
    import haldir_migrate
    db_path = (
        args.db_path
        or os.environ.get("HALDIR_DB_PATH")
        or "haldir.db"
    )
    sub = args.migrate_command
    if sub in (None, "up"):
        s = haldir_migrate.apply_pending(db_path)
        if s["bootstrapped"]:
            success("legacy schema adopted as v1")
        if s["applied"]:
            success(f"applied: {s['applied']}")
        else:
            info(f"nothing to apply ({len(s['skipped'])} already-applied)")
        if s["drift"]:
            warn(f"drift on versions {s['drift']} — file checksums diverged from record")
    elif sub == "status":
        s = haldir_migrate.status(db_path)
        if s["applied"]:
            print(f"{Color.BOLD}applied:{Color.RESET}")
            for a in s["applied"]:
                print(f"  {Color.GREEN}✓{Color.RESET} {a['version']:03d}  {a['name']}")
        else:
            print(f"{Color.DIM}applied: (none){Color.RESET}")
        if s["pending"]:
            print(f"{Color.BOLD}pending:{Color.RESET}")
            for p in s["pending"]:
                print(f"  {Color.YELLOW}○{Color.RESET} {p['version']:03d}  {p['name']}")
        if s["drift"]:
            warn(f"drift: {s['drift']}")
    elif sub == "verify":
        s = haldir_migrate.status(db_path)
        if s["drift"]:
            error(f"drift on versions {s['drift']}")
            sys.exit(2)
        success("all applied migrations match files on disk")


# ── Config ──

def cmd_config_show(args: argparse.Namespace) -> None:
    """Show current configuration."""
    config = load_config()

    print(f"{Color.BOLD}Haldir Configuration{Color.RESET}")
    print(f"  {Color.DIM}File:{Color.RESET} {mono(str(CONFIG_FILE))}")
    print()

    if not config:
        warn("No config file found. Run 'haldir login' to get started.")
        return

    base_url = config.get("base_url", DEFAULT_BASE_URL)
    api_key = config.get("api_key", "")

    label("Base URL", base_url)
    if api_key:
        # Only show prefix for security
        masked = api_key[:12] + "..." if len(api_key) > 12 else api_key
        label("API Key", masked)
    else:
        label("API Key", "(not set)")

    # Show any extra config keys
    for k, v in config.items():
        if k not in ("api_key", "base_url"):
            label(k, v)


# ── Self-host helpers (Supabase-style local dev) ──────────────────────────

def cmd_init(args: argparse.Namespace) -> None:
    """Scaffold a new Haldir project in the current directory (or --target)."""
    import subprocess
    from secrets import token_urlsafe

    import base64

    target = Path(args.target or ".").resolve()
    target.mkdir(parents=True, exist_ok=True)

    env_path = target / ".env"
    compose_path = target / "docker-compose.yml"

    if env_path.exists() and not args.force:
        error(f".env already exists at {env_path}. Use --force to overwrite.")
        sys.exit(1)

    # Generate a 256-bit AES-GCM key, base64url-encoded for env-var friendliness
    encryption_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    bootstrap_token = token_urlsafe(24)

    env_path.write_text(
        f"# Haldir self-host config — generated by `haldir init`\n"
        f"HALDIR_ENCRYPTION_KEY={encryption_key}\n"
        f"HALDIR_BOOTSTRAP_TOKEN={bootstrap_token}\n"
        f"HALDIR_PORT=8000\n"
        f"POSTGRES_USER=haldir\n"
        f"POSTGRES_PASSWORD=haldir\n"
        f"POSTGRES_DB=haldir\n"
    )
    info(f"Wrote {env_path}")

    if not compose_path.exists():
        if subprocess.run(["git", "clone", "--depth", "1",
                           "https://github.com/ExposureGuard/haldir.git",
                           str(target / ".haldir-src")],
                          capture_output=True).returncode == 0:
            src_compose = target / ".haldir-src" / "docker-compose.yml"
            if src_compose.exists():
                compose_path.write_bytes(src_compose.read_bytes())
                info(f"Wrote {compose_path}")
        else:
            warn("Could not fetch docker-compose.yml from GitHub; "
                 "clone https://github.com/ExposureGuard/haldir.git manually.")

    success("Project initialized.")
    print()
    print("Next steps:")
    print(f"  cd {target}")
    print("  haldir dev            # start the local stack (equivalent to: docker compose up -d)")
    print()
    print(f"Your bootstrap token (save it, needed to create your first API key):")
    print(f"  {bootstrap_token}")


def cmd_dev(args: argparse.Namespace) -> None:
    """Start (or stop) the self-host stack via docker compose."""
    import subprocess

    if not Path("docker-compose.yml").exists():
        error("No docker-compose.yml in current directory. Run `haldir init` first "
              "or cd into a Haldir checkout.")
        sys.exit(1)

    if args.down:
        info("Stopping Haldir stack...")
        r = subprocess.run(["docker", "compose", "down"])
        sys.exit(r.returncode)

    if args.reset:
        warn("Wiping Haldir stack and volumes (this deletes all local data)...")
        subprocess.run(["docker", "compose", "down", "-v"])

    info("Starting Haldir stack (API + Postgres)...")
    if args.foreground:
        r = subprocess.run(["docker", "compose", "up", "--build"])
        sys.exit(r.returncode)

    r = subprocess.run(["docker", "compose", "up", "-d", "--build"])
    if r.returncode != 0:
        error("Docker compose failed. Is Docker running?")
        sys.exit(r.returncode)

    success("Haldir is starting on http://localhost:8000")
    print()
    print("  Check health:  curl http://localhost:8000/health")
    print("  View logs:     docker compose logs -f api")
    print("  Stop:          haldir dev --down")


# ── Argument parser ──

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haldir",
        description="Haldir CLI — the guardian layer for AI agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'haldir <command> --help' for subcommand help.",
    )
    parser.add_argument("--url", help="Override base URL (default: https://haldir.xyz)")
    parser.add_argument("--key", help="Override API key (or set HALDIR_API_KEY)")

    sub = parser.add_subparsers(dest="command", help="Command group")

    # ── login ──
    p_login = sub.add_parser("login", help="Authenticate and save API key")
    p_login.add_argument("--key", dest="key", help="API key (or prompted interactively)")
    p_login.add_argument("--url", dest="url", help="Base URL for the Haldir API")
    p_login.set_defaults(func=cmd_login)

    # ── keys ──
    p_keys = sub.add_parser("keys", help="Manage API keys")
    keys_sub = p_keys.add_subparsers(dest="keys_command")

    p_keys_create = keys_sub.add_parser("create", help="Create a new API key")
    p_keys_create.add_argument("--name", required=True, help="Name for the key")
    p_keys_create.add_argument("--tier", help="Key tier (free, pro, enterprise)")
    p_keys_create.add_argument(
        "--scopes",
        help="Comma-separated scopes (e.g. 'audit:read,sessions:read'). "
             "Default '*' (full access). Resources: sessions, vault, audit, "
             "payments, webhooks, proxy, approvals, admin.",
    )
    p_keys_create.set_defaults(func=cmd_keys_create)

    # ── session ──
    p_session = sub.add_parser("session", help="Manage agent sessions (Gate)")
    session_sub = p_session.add_subparsers(dest="session_command")

    p_sess_create = session_sub.add_parser("create", help="Create an agent session")
    p_sess_create.add_argument("--agent", required=True, help="Agent ID")
    p_sess_create.add_argument("--scopes", help="Comma-separated scopes (e.g. read,browse,spend)")
    p_sess_create.add_argument("--ttl", type=int, help="Time-to-live in seconds (default: 3600)")
    p_sess_create.add_argument("--budget", type=float, help="Spend limit in USD")
    p_sess_create.set_defaults(func=cmd_session_create)

    p_sess_get = session_sub.add_parser("get", help="Get session details")
    p_sess_get.add_argument("session_id", help="Session ID")
    p_sess_get.set_defaults(func=cmd_session_get)

    p_sess_revoke = session_sub.add_parser("revoke", help="Revoke a session")
    p_sess_revoke.add_argument("session_id", help="Session ID")
    p_sess_revoke.set_defaults(func=cmd_session_revoke)

    p_sess_check = session_sub.add_parser("check", help="Check a session permission")
    p_sess_check.add_argument("session_id", help="Session ID")
    p_sess_check.add_argument("--scope", required=True, help="Scope to check (e.g. read, browse, spend)")
    p_sess_check.set_defaults(func=cmd_session_check)

    # ── secret ──
    p_secret = sub.add_parser("secret", help="Manage secrets (Vault)")
    secret_sub = p_secret.add_subparsers(dest="secret_command")

    p_sec_store = secret_sub.add_parser("store", help="Store a secret")
    p_sec_store.add_argument("name", help="Secret name")
    p_sec_store.add_argument("value", help="Secret value")
    p_sec_store.add_argument("--scope", help="Required scope to read this secret (default: read)")
    p_sec_store.set_defaults(func=cmd_secret_store)

    p_sec_get = secret_sub.add_parser("get", help="Retrieve a secret")
    p_sec_get.add_argument("name", help="Secret name")
    p_sec_get.add_argument("--session", help="Session ID for scope-gated access")
    p_sec_get.set_defaults(func=cmd_secret_get)

    p_sec_list = secret_sub.add_parser("list", help="List all secrets")
    p_sec_list.set_defaults(func=cmd_secret_list)

    p_sec_delete = secret_sub.add_parser("delete", help="Delete a secret")
    p_sec_delete.add_argument("name", help="Secret name")
    p_sec_delete.set_defaults(func=cmd_secret_delete)

    # ── pay ──
    p_pay = sub.add_parser("pay", help="Payment authorization")
    pay_sub = p_pay.add_subparsers(dest="pay_command")

    p_pay_auth = pay_sub.add_parser("authorize", help="Authorize a payment")
    p_pay_auth.add_argument("session_id", help="Session ID")
    p_pay_auth.add_argument("amount", type=float, help="Amount in USD")
    p_pay_auth.add_argument("--description", default="", help="Payment description")
    p_pay_auth.add_argument("--currency", default="USD", help="Currency code (default: USD)")
    p_pay_auth.set_defaults(func=cmd_pay_authorize)

    # ── audit ──
    p_audit = sub.add_parser("audit", help="Audit trail and spend tracking (Watch)")
    audit_sub = p_audit.add_subparsers(dest="audit_command")

    p_audit_log = audit_sub.add_parser("log", help="Log an action")
    p_audit_log.add_argument("session_id", help="Session ID")
    p_audit_log.add_argument("--tool", help="Tool name")
    p_audit_log.add_argument("--action", required=True, help="Action name")
    p_audit_log.add_argument("--cost", type=float, help="Cost in USD")
    p_audit_log.add_argument("--details", help="JSON details object")
    p_audit_log.set_defaults(func=cmd_audit_log)

    p_audit_trail = audit_sub.add_parser("trail", help="Query the audit trail")
    p_audit_trail.add_argument("--session", help="Filter by session ID")
    p_audit_trail.add_argument("--agent", help="Filter by agent ID")
    p_audit_trail.add_argument("--tool", help="Filter by tool name")
    p_audit_trail.add_argument("--flagged", action="store_true", help="Show only flagged entries")
    p_audit_trail.add_argument("--limit", type=int, default=20, help="Max entries (default: 20)")
    p_audit_trail.set_defaults(func=cmd_audit_trail)

    p_audit_spend = audit_sub.add_parser("spend", help="Get spend summary")
    p_audit_spend.add_argument("--session", help="Filter by session ID")
    p_audit_spend.add_argument("--agent", help="Filter by agent ID")
    p_audit_spend.set_defaults(func=cmd_audit_spend)

    # ── proxy ──
    p_proxy = sub.add_parser("proxy", help="MCP proxy management")
    proxy_sub = p_proxy.add_subparsers(dest="proxy_command")

    p_prx_register = proxy_sub.add_parser("register", help="Register an upstream MCP server")
    p_prx_register.add_argument("name", help="Upstream server name")
    p_prx_register.add_argument("url", help="Upstream server URL")
    p_prx_register.set_defaults(func=cmd_proxy_register)

    p_prx_tools = proxy_sub.add_parser("tools", help="List tools from all upstreams")
    p_prx_tools.set_defaults(func=cmd_proxy_tools)

    p_prx_call = proxy_sub.add_parser("call", help="Call a tool through the proxy")
    p_prx_call.add_argument("tool", help="Tool name")
    p_prx_call.add_argument("--args", help="JSON arguments for the tool")
    p_prx_call.add_argument("--session", required=True, help="Session ID")
    p_prx_call.set_defaults(func=cmd_proxy_call)

    p_prx_policy = proxy_sub.add_parser("policy", help="Manage proxy policies")
    policy_sub = p_prx_policy.add_subparsers(dest="policy_command")

    p_pol_add = policy_sub.add_parser("add", help="Add a governance policy")
    p_pol_add.add_argument("--type", required=True, help="Policy type (block_tool, allow_list, deny_list, spend_limit, rate_limit, time_window)")
    p_pol_add.add_argument("--tool", help="Tool name (for block_tool)")
    p_pol_add.add_argument("--tools", help="Comma-separated tool names (for allow_list/deny_list)")
    p_pol_add.add_argument("--max", type=float, help="Max spend per call (for spend_limit)")
    p_pol_add.add_argument("--max-per-minute", type=int, dest="max_per_minute", help="Max calls per minute (for rate_limit)")
    p_pol_add.add_argument("--start-hour", type=int, dest="start_hour", help="UTC start hour (for time_window)")
    p_pol_add.add_argument("--end-hour", type=int, dest="end_hour", help="UTC end hour (for time_window)")
    p_pol_add.set_defaults(func=cmd_proxy_policy_add)

    # ── metrics ──
    p_metrics = sub.add_parser("metrics", help="Show platform metrics")
    p_metrics.set_defaults(func=cmd_metrics)

    # ── overview / status / ready ──
    p_over = sub.add_parser("overview", help="One-call tenant dashboard (the screenshot moment)")
    p_over.add_argument("--json", action="store_true", help="Emit raw JSON")
    p_over.add_argument("--watch", action="store_true", help="Refresh continuously, top-style")
    p_over.add_argument("--interval", type=float, default=5.0, help="Refresh interval (with --watch)")
    p_over.set_defaults(func=cmd_overview)

    p_status = sub.add_parser("status", help="System health (calls /v1/status)")
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=cmd_status)

    p_ready = sub.add_parser("ready", help="Readiness check; exits 0/1 (CI-friendly)")
    p_ready.add_argument("--json", action="store_true")
    p_ready.set_defaults(func=cmd_ready)

    # ── audit export / verify (extend existing audit subparser) ──
    p_audit_export = audit_sub.add_parser("export", help="Stream the audit trail (CSV or JSONL)")
    p_audit_export.add_argument("--format", default="jsonl", choices=("jsonl", "csv"))
    p_audit_export.add_argument("--out", help="Write to file (default: stdout)")
    p_audit_export.add_argument("--since", help="Lower bound (ISO 8601 or unix seconds)")
    p_audit_export.add_argument("--until", help="Upper bound (ISO 8601 or unix seconds)")
    p_audit_export.add_argument("--session", help="Filter by session_id")
    p_audit_export.add_argument("--agent", help="Filter by agent_id")
    p_audit_export.add_argument("--tool", help="Filter by tool name")
    p_audit_export.set_defaults(func=cmd_audit_export)

    p_audit_verify = audit_sub.add_parser("verify", help="Verify the hash chain integrity")
    p_audit_verify.add_argument("--json", action="store_true")
    p_audit_verify.set_defaults(func=cmd_audit_verify)

    # ── webhooks deliveries ──
    p_wh = sub.add_parser("webhooks", help="Webhook delivery inspection")
    wh_sub = p_wh.add_subparsers(dest="webhooks_command")
    p_wh_dlv = wh_sub.add_parser("deliveries", help="Recent webhook delivery attempts")
    p_wh_dlv.add_argument("--event-id", dest="event_id", help="Narrow to one event UUID")
    p_wh_dlv.add_argument("--limit", type=int, default=20, help="Max rows (default: 20)")
    p_wh_dlv.add_argument("--json", action="store_true")
    p_wh_dlv.set_defaults(func=cmd_webhooks_deliveries)

    # ── compliance ──
    p_comp = sub.add_parser("compliance", help="Compliance evidence pack (SOC2/ISO/AI Act)")
    comp_sub = p_comp.add_subparsers(dest="compliance_command")

    p_comp_evi = comp_sub.add_parser("evidence", help="Generate a proof-of-control pack")
    p_comp_evi.add_argument("--format", default="markdown",
                             choices=("markdown", "md", "json"),
                             help="Output format (default: markdown)")
    p_comp_evi.add_argument("--out", help="Write to file (default: stdout)")
    p_comp_evi.add_argument("--since", help="Period start (ISO 8601 or unix seconds)")
    p_comp_evi.add_argument("--until", help="Period end (ISO 8601 or unix seconds)")
    p_comp_evi.set_defaults(func=cmd_compliance_evidence)

    # Schedules — recurring auto-delivery of evidence packs.
    p_comp_sch = comp_sub.add_parser("schedules",
                                       help="Manage recurring evidence-pack schedules")
    sch_sub = p_comp_sch.add_subparsers(dest="schedules_command")

    p_sch_ls = sch_sub.add_parser("list", help="List schedules for the authed tenant")
    p_sch_ls.add_argument("--json", action="store_true")
    p_sch_ls.set_defaults(func=cmd_compliance_schedules_list)

    p_sch_new = sch_sub.add_parser("create", help="Register a recurring schedule")
    p_sch_new.add_argument("--name", required=True, help="Friendly id (e.g. monthly-board-prep)")
    p_sch_new.add_argument("--cadence", required=True,
                             choices=("daily", "weekly", "monthly", "quarterly"))
    p_sch_new.add_argument("--delivery", required=True,
                             help="Target (e.g. webhook:wh_abc123)")
    p_sch_new.set_defaults(func=cmd_compliance_schedules_create)

    p_sch_del = sch_sub.add_parser("delete", help="Remove a schedule by id")
    p_sch_del.add_argument("schedule_id", help="Schedule id (e.g. sched_xxx)")
    p_sch_del.set_defaults(func=cmd_compliance_schedules_delete)

    # ── migrate (local; wraps haldir_migrate) ──
    p_mig = sub.add_parser("migrate", help="Apply / inspect schema migrations on the local DB")
    p_mig.add_argument("--db-path", dest="db_path", help="Override DB path (default: HALDIR_DB_PATH)")
    mig_sub = p_mig.add_subparsers(dest="migrate_command")
    mig_sub.add_parser("up",     help="Apply pending migrations")
    mig_sub.add_parser("status", help="List applied + pending migrations")
    mig_sub.add_parser("verify", help="Detect file-vs-record checksum drift")
    p_mig.set_defaults(func=cmd_migrate)

    # ── config ──
    p_config = sub.add_parser("config", help="View configuration")
    config_sub = p_config.add_subparsers(dest="config_command")

    p_config_show = config_sub.add_parser("show", help="Show current config")
    p_config_show.set_defaults(func=cmd_config_show)

    # Also allow bare 'haldir config' to show config
    p_config.set_defaults(func=cmd_config_show)

    # ── init (scaffold a self-host project) ──
    p_init = sub.add_parser("init", help="Scaffold a new self-host project (.env + docker-compose.yml)")
    p_init.add_argument("target", nargs="?", help="Target directory (default: current directory)")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing .env")
    p_init.set_defaults(func=cmd_init)

    # ── dev (run/stop/reset the local stack) ──
    p_dev = sub.add_parser("dev", help="Start the local Haldir stack (Docker compose)")
    p_dev.add_argument("--down", action="store_true", help="Stop the stack instead of starting it")
    p_dev.add_argument("--reset", action="store_true", help="Wipe volumes before starting (deletes all local data)")
    p_dev.add_argument("--foreground", "-f", action="store_true", help="Run in foreground (stream logs to terminal)")
    p_dev.set_defaults(func=cmd_dev)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Apply global overrides
    if hasattr(args, "url") and args.url and args.command != "login":
        os.environ["HALDIR_BASE_URL"] = args.url
    if hasattr(args, "key") and args.key and args.command != "login":
        os.environ["HALDIR_API_KEY"] = args.key

    if not hasattr(args, "func") or args.func is None:
        # Show help if no command given, or if subcommand missing
        if args.command:
            # Find the subparser and print its help
            parser.parse_args([args.command, "--help"])
        else:
            parser.print_help()
        sys.exit(0)

    try:
        args.func(args)
    except KeyboardInterrupt:
        print()
        sys.exit(130)


if __name__ == "__main__":
    main()
