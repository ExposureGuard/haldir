#!/usr/bin/env python3
"""
Capture Haldir's demo screenshots from a real, running instance.

Why this exists
---------------
The images in ``demo/screenshots/`` used to be captured by hand, and they
drifted away from the product without anything noticing. Two examples that
shipped in README.md and demo_gallery.html:

  * ``04_cloud_overview.png`` — captioned "Cloud dashboard", actually a
    screenshot of the **sign-in page**. The annotated variant drawn on top
    of it pointed its labels at empty black space.
  * ``06_cloud_audit.png`` — captioned "Audit Trail", actually a JSON error
    body: ``{"code": "not_found", "error": "Endpoint not found"}``.

Nothing in the repository could regenerate them, so nothing could detect the
drift. This script boots a throwaway instance, seeds it with realistic
activity, and drives headless Chrome over every page the README and gallery
show. Re-run it after any UI change; the screenshots are then whatever the
product actually looks like.

Usage
-----
    python3 demo/capture.py                 # capture every page
    python3 demo/capture.py --only audit    # just one page
    python3 demo/capture.py --keep          # leave the server running and print its URL
    python3 demo/capture.py --list          # show the page names

Requires Chrome or Chromium on PATH. The instance runs on its own port
against a scratch database, so it will not touch a dev server you already
have running.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCREENSHOT_DIR = ROOT / "demo" / "screenshots"
SCRATCH_DB = Path("/tmp/haldir_capture.db")

# Rendered at 1400x900 and captured at 2x, so the PNGs stay legible when
# scaled down inside a README column. The previous set was captured at 1x and
# then shrunk into montage panels ~300px wide, which made every label
# unreadable — a large part of why the montages looked so poor.
VIEWPORT = (1400, 900)
SCALE = 2

# Pages the README and demo gallery reference. `hash` is the client-side
# route the dashboard shell understands.
PAGES: list[dict[str, str]] = [
    {"name": "01_landing", "url": "/", "hash": ""},
    {"name": "02_docs", "url": "/docs", "hash": ""},
    {"name": "03_openapi", "url": "/openapi.json", "hash": ""},
    # The dashboard's default view IS the Account page — dashboard.js has no
    # "overview" page, so requesting /cloud/overview with no fragment lands on
    # account. Capturing both produced two byte-identical files and a gallery
    # showing the same screenshot twice under different captions.
    {"name": "04_cloud_overview", "url": "/cloud/overview", "hash": ""},
    # The tamper demo is a separate surface (and the product's core claim), so
    # it takes the slot — captured in its untampered state.
    {"name": "05_tamper_demo", "url": "/demo/tamper", "hash": ""},
    {"name": "06_cloud_audit", "url": "/cloud/overview", "hash": "#/audit"},
    {"name": "07_cloud_compliance", "url": "/cloud/overview", "hash": "#/compliance"},
    {"name": "08_cloud_settings", "url": "/cloud/overview", "hash": "#/settings"},
    {"name": "09_cloud_approvals", "url": "/cloud/overview", "hash": "#/approvals"},
    {"name": "10_cloud_webhooks", "url": "/cloud/overview", "hash": "#/webhooks"},
    {"name": "11_cloud_sessions", "url": "/cloud/overview", "hash": "#/sessions"},
    {"name": "12_cloud_quotas", "url": "/cloud/overview", "hash": "#/quotas"},
    {"name": "13_tamper_demo", "url": "/demo", "hash": ""},
]

# Everything under /cloud/ needs to be signed in, and the dashboard is a
# client-side SPA, so the key travels in the querystring and the sub-page in
# the fragment.
#
# Deriving this from `hash` rather than from the URL is how the original
# screenshots rotted: the overview page has no fragment, so it never got a
# key, so it captured the sign-in page instead of the dashboard. Anything
# served under /cloud/ must be listed here.
CLOUD_PAGES = {p["name"] for p in PAGES if p["url"].startswith("/cloud/")}


def assert_authenticated(base: str, key: str) -> None:
    """Fail loudly if the cloud pages are not actually reachable.

    The previous screenshots were captured while unauthenticated and nobody
    noticed for months, because a sign-in page looks plausible in a grid of
    thumbnails. A capture run that cannot reach the dashboard is a broken
    capture run, not a set of pictures — so refuse to produce either.
    """
    status, body = request(base, f"/cloud/overview?key={key}")
    if status != 200 or not isinstance(body, str):
        sys.exit(f"[-] /cloud/overview returned {status}; refusing to capture.")
    if "Sign in with your API key" in body:
        sys.exit(
            "[-] /cloud/overview served the sign-in page, not the dashboard. "
            "The key is missing or no longer valid — a capture from here "
            "would silently produce login screenshots."
        )
    for marker in ("sidebar", "sessions", "audit"):
        if marker not in body:
            sys.exit(f"[-] dashboard HTML is missing {marker!r}; refusing to capture.")


def find_chrome() -> str:
    for candidate in (
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "chrome",
    ):
        found = shutil.which(candidate)
        if found:
            return found
    sys.exit(
        "[-] No Chrome/Chromium found on PATH. Install one, or capture the "
        "screenshots on a machine that has it."
    )


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def request(
    base: str,
    path: str,
    payload: dict[str, Any] | None = None,
    key: str = "",
    method: str | None = None,
) -> tuple[int, Any]:
    """Minimal JSON client. Stdlib only, so this script has no install step."""
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        base + path,
        data=data,
        method=method or ("POST" if payload is not None else "GET"),
    )
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read().decode()
            try:
                return r.status, json.loads(body)
            except json.JSONDecodeError:
                return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]


def start_server(port: int, env_extra: dict[str, str] | None = None) -> subprocess.Popen:
    SCRATCH_DB.unlink(missing_ok=True)
    env = dict(os.environ)
    env.update(
        {
            "HALDIR_DB_PATH": str(SCRATCH_DB),
            # Without this the scratch DB gets the base schema only, and
            # migration-created tables (sth_log, transparency) are absent —
            # the same first-run trap that made the test suite order-dependent.
            "HALDIR_AUTO_MIGRATE": "1",
            "PORT": str(port),
            "HALDIR_ENCRYPTION_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
        }
    )
    if env_extra:
        env.update(env_extra)
    proc = subprocess.Popen(
        [sys.executable, "api.py"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )
    return proc


def wait_healthy(base: str, timeout: float = 45.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _ = request(base, "/healthz")
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def seed(base: str, key: str) -> None:
    """Populate the instance so the dashboard has something true to show.

    Every call is reported; a failure is loud but not fatal, so a schema
    change degrades one panel instead of aborting the whole capture.
    """
    created = 0
    failed: list[str] = []

    def call(label: str, path: str, payload: dict[str, Any]) -> Any:
        nonlocal created
        status, body = request(base, path, payload, key)
        if status in (200, 201):
            created += 1
            return body
        failed.append(f"{label} -> {status} {body}")
        return None

    # Sessions: a spread of agents so the sessions table and the agent quota
    # both look like something a team would actually be running.
    agents = [
        ("support-bot", ["read", "browse", "spend:50"], 25.0),
        ("research-agent", ["read", "browse", "spend:200"], 100.0),
        ("billing-agent", ["read", "spend:500"], 500.0),
        ("scraper", ["read", "browse"], 0.0),
    ]
    sessions: dict[str, str] = {}
    for agent_id, scopes, spend in agents:
        body = call(
            f"session {agent_id}",
            "/v1/sessions",
            {"agent_id": agent_id, "scopes": scopes, "ttl": 86400, "spend_limit": spend},
        )
        if body and body.get("session_id"):
            sessions[agent_id] = body["session_id"]

    # Secrets: names only ever appear in the clear; the values stay in the vault.
    for name, scope in [
        ("stripe_key", "read"),
        ("openai_api_key", "read"),
        ("warehouse_dsn", "read"),
    ]:
        call("secret " + name, "/v1/secrets", {"name": name, "value": "sk_live_" + name, "scope_required": scope})

    # Audit entries. `details` carries what the expandable row shows: which
    # tool ran, which upstream it reached, how long it took, and what came
    # back. These are the rows the README calls the thing that makes the
    # product click, so they are worth making realistic.
    audit_rows = [
        ("support-bot", "stripe", "customer.lookup", 0.0,
         {"upstream": "api.stripe.com", "tool": "stripe.lookup_customer",
          "duration_ms": 184, "arguments": {"email": "ada@example.com"},
          "response": {"id": "cus_Q1x", "delinquent": False}}),
        ("support-bot", "stripe", "charge", 29.99,
         {"upstream": "api.stripe.com", "tool": "stripe.charge",
          "duration_ms": 412, "arguments": {"amount": 2999, "currency": "usd"},
          "response": {"status": "succeeded"}}),
        ("research-agent", "browser", "fetch", 0.0,
         {"upstream": "news.ycombinator.com", "tool": "browser.fetch",
          "duration_ms": 903, "arguments": {"url": "https://news.ycombinator.com"},
          "response": {"status": 200, "bytes": 48210}}),
        ("research-agent", "openai", "completion", 0.42,
         {"upstream": "api.openai.com", "tool": "openai.chat",
          "duration_ms": 2311, "arguments": {"model": "gpt-4o", "messages": 3},
          "response": {"tokens": 1840}}),
        ("billing-agent", "stripe", "invoice.create", 0.0,
         {"upstream": "api.stripe.com", "tool": "stripe.invoice",
          "duration_ms": 355, "arguments": {"customer": "cus_Q1x"},
          "response": {"status": "draft"}}),
        ("billing-agent", "warehouse", "query", 0.0,
         {"upstream": "warehouse.internal", "tool": "sql.query",
          "duration_ms": 1204, "arguments": {"table": "invoices", "rows": 500},
          "response": {"rows": 500}}),
        ("scraper", "browser", "fetch", 0.0,
         {"upstream": "example.com", "tool": "browser.fetch",
          "duration_ms": 233, "arguments": {"url": "https://example.com"},
          "response": {"status": 200, "bytes": 1256}}),
        ("support-bot", "slack", "post", 0.0,
         {"upstream": "slack.com", "tool": "slack.post_message",
          "duration_ms": 208, "arguments": {"channel": "#support"},
          "response": {"ok": True}}),
        ("research-agent", "openai", "embedding", 0.11,
         {"upstream": "api.openai.com", "tool": "openai.embed",
          "duration_ms": 640, "arguments": {"model": "text-embedding-3-small"},
          "response": {"vectors": 12}}),
        ("billing-agent", "stripe", "refund", 0.0,
         {"upstream": "api.stripe.com", "tool": "stripe.refund",
          "duration_ms": 388, "arguments": {"charge": "ch_3Px"},
          "response": {"status": "pending"}}),
    ]
    for agent_id, tool, action, cost, details in audit_rows:
        sid = sessions.get(agent_id)
        if not sid:
            continue
        call(f"audit {tool}.{action}", "/v1/audit",
             {"session_id": sid, "tool": tool, "action": action,
              "cost_usd": cost, "details": details})

    # Webhooks: a healthy one and a flaky one, so the delivery-rate column
    # has something to say.
    for url, events in [
        ("https://hooks.example.com/haldir/audit", ["audit.flagged", "session.revoked"]),
        ("https://siem.internal/ingest", ["audit.flagged"]),
    ]:
        call("webhook", "/v1/webhooks", {"url": url, "events": events})

    # Approvals: a rule and a request waiting on a human, which is what makes
    # the approvals page non-empty.
    call("approval rule", "/v1/approvals/rules", {"type": "spend_over", "threshold": 100})
    if sessions.get("billing-agent"):
        call("approval request", "/v1/approvals/request",
             {"session_id": sessions["billing-agent"], "action": "charge",
              "amount": 480.0, "reason": "Q3 overage invoice"})

    print(f"[+] seeded {created} records")
    for f in failed:
        print(f"[-] seed step failed: {f}")


def promote_to_pro(key: str) -> None:
    """Put the demo tenant on a paid tier.

    The API deliberately forces new keys to `free` (only a Stripe webhook can
    upgrade), so the marketing screenshots would otherwise show a free-tier
    dashboard. This writes the subscription row directly — fine here, since
    the scratch DB is ours and about to be thrown away.
    """
    if not SCRATCH_DB.exists():
        return
    conn = sqlite3.connect(SCRATCH_DB)
    try:
        row = conn.execute("SELECT tenant_id FROM api_keys LIMIT 1").fetchone()
        if not row:
            return
        tenant = row[0] or ""
        conn.execute("DELETE FROM subscriptions WHERE tenant_id = ?", (tenant,))
        conn.execute(
            "INSERT INTO subscriptions (tenant_id, tier, status, created_at) VALUES (?, ?, ?, ?)",
            (tenant, "pro", "active", time.time()),
        )
        conn.commit()
    except Exception as e:
        print(f"[-] could not set tier: {e}")
    finally:
        conn.close()


def shoot(chrome: str, url: str, out: Path) -> bool:
    """One full-page screenshot via headless Chrome.

    `--virtual-time-budget` matters: the dashboard is a SPA that fetches its
    tables after load, and a plain --screenshot fires before the data lands,
    which is how screenshots end up showing empty panels.
    """
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        chrome,
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--hide-scrollbars",
        "--force-device-scale-factor=" + str(SCALE),
        f"--window-size={VIEWPORT[0]},{VIEWPORT[1]}",
        "--virtual-time-budget=8000",
        f"--screenshot={out}",
        url,
    ]
    proc = subprocess.run(cmd, capture_output=True, timeout=90)
    ok = out.exists() and out.stat().st_size > 2000
    if not ok:
        tail = proc.stderr.decode()[-200:] if proc.stderr else ""
        print(f"[-] {out.name}: capture failed ({tail.strip()})")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture Haldir's demo screenshots.")
    parser.add_argument("--only", action="append", default=[], metavar="NAME",
                        help="capture only this page name (repeatable)")
    parser.add_argument("--keep", action="store_true",
                        help="leave the instance running and print its URL")
    parser.add_argument("--list", action="store_true", help="list page names and exit")
    args = parser.parse_args()

    if args.list:
        for p in PAGES:
            print(f"  {p['name']}")
        return 0

    chrome = find_chrome()
    port = free_port()
    base = f"http://127.0.0.1:{port}"

    print(f"[*] starting a scratch instance on {base}")
    proc = start_server(port)
    try:
        if not wait_healthy(base):
            print("[-] instance never became healthy; see it directly with --keep")
            return 1
        print("[+] healthy")

        status, body = request(base, "/v1/keys", {"name": "demo", "tier": "pro"})
        if status not in (200, 201) or not isinstance(body, dict) or "key" not in body:
            print(f"[-] could not mint a key: {status} {body}")
            return 1
        key = body["key"]
        print(f"[+] key {key[:14]}…")

        promote_to_pro(key)
        seed(base, key)
        assert_authenticated(base, key)

        wanted = set(args.only)
        targets = [p for p in PAGES if not wanted or p["name"] in wanted]
        if wanted:
            unknown = wanted - {p["name"] for p in PAGES}
            if unknown:
                print(f"[-] unknown page(s): {', '.join(sorted(unknown))}")
                return 1

        print(f"[*] capturing {len(targets)} page(s) at {VIEWPORT[0]}x{VIEWPORT[1]} @{SCALE}x")
        ok = 0
        for p in targets:
            url = base + p["url"]
            if p["name"] in CLOUD_PAGES:
                url += f"?key={key}{p['hash']}"
            elif p["hash"]:
                url += p["hash"]
            out = SCREENSHOT_DIR / f"{p['name']}.png"
            if shoot(chrome, url, out):
                ok += 1
                print(f"    {p['name']}.png")

        print(f"[+] {ok}/{len(targets)} captured into {SCREENSHOT_DIR.relative_to(ROOT)}")
        if args.keep:
            print(f"[*] --keep: instance still running at {base}")
            print(f"    dashboard: {base}/cloud/overview?key={key}")
            return 0
        return 0 if ok == len(targets) else 1
    finally:
        if not args.keep:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=10)
            except Exception:
                pass
            SCRATCH_DB.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
