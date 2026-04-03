"""
Haldir API Server — REST endpoints for Gate, Vault, Watch.

Minimal Flask app. No frontend. Just API.

Routes:
    POST   /v1/sessions          — Create agent session
    GET    /v1/sessions/:id      — Get session info
    DELETE /v1/sessions/:id      — Revoke session
    POST   /v1/sessions/:id/check — Check permission

    POST   /v1/secrets           — Store a secret
    GET    /v1/secrets/:name     — Retrieve a secret
    DELETE /v1/secrets/:name     — Delete a secret
    GET    /v1/secrets           — List secret names

    POST   /v1/payments/authorize — Authorize a payment

    POST   /v1/audit             — Log an action
    GET    /v1/audit             — Query audit trail
    GET    /v1/audit/spend       — Get spend summary

    POST   /v1/keys              — Create API key (bootstrap)
    GET    /healthz              — Health check
"""

import os
import json
import time
import secrets
import hashlib
from functools import wraps

from flask import Flask, request, jsonify, abort

from haldir_db import init_db, get_db
from haldir_gate.gate import Gate
from haldir_vault.vault import Vault
from haldir_watch.watch import Watch

# ── App setup ──

DB_PATH = os.environ.get("HALDIR_DB_PATH", "/data/haldir.db" if os.path.isdir("/data") else "haldir.db")
ENCRYPTION_KEY = os.environ.get("HALDIR_ENCRYPTION_KEY", "").encode() or None

app = Flask(__name__)

# Init DB on startup
init_db(DB_PATH)

# Init components
gate = Gate(db_path=DB_PATH)
vault = Vault(encryption_key=ENCRYPTION_KEY, db_path=DB_PATH)
watch = Watch(db_path=DB_PATH)

# If no encryption key was set, save the generated one
if not ENCRYPTION_KEY:
    print(f"[!] No HALDIR_ENCRYPTION_KEY set. Generated: {vault.encryption_key.decode()}")
    print(f"[!] Set this as an environment variable to persist secrets across restarts.")


# ── API Key auth ──

def _init_keys_table():
    conn = get_db(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            key_hash TEXT PRIMARY KEY,
            key_prefix TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            tier TEXT NOT NULL DEFAULT 'free',
            created_at REAL NOT NULL,
            last_used REAL NOT NULL DEFAULT 0,
            revoked INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

_init_keys_table()


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not key:
            key = request.headers.get("X-API-Key", "")
        if not key:
            return jsonify({"error": "Missing API key. Pass via Authorization: Bearer <key> or X-API-Key header."}), 401

        key_hash = _hash_key(key)
        conn = get_db(DB_PATH)
        row = conn.execute("SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0", (key_hash,)).fetchone()
        if row:
            conn.execute("UPDATE api_keys SET last_used = ? WHERE key_hash = ?", (time.time(), key_hash))
            conn.commit()
        conn.close()

        if not row:
            return jsonify({"error": "Invalid or revoked API key."}), 401

        request.api_key_tier = row["tier"]
        request.api_key_name = row["name"]
        return f(*args, **kwargs)
    return decorated


# ── Bootstrap: create first API key ──

@app.route("/v1/keys", methods=["POST"])
def create_api_key():
    """Create an API key. First key requires HALDIR_BOOTSTRAP_TOKEN env var."""
    conn = get_db(DB_PATH)
    key_count = conn.execute("SELECT COUNT(*) FROM api_keys WHERE revoked = 0").fetchone()[0]
    conn.close()

    # First key is free; subsequent keys need auth
    if key_count > 0:
        # Need existing key to create new keys
        key = request.headers.get("Authorization", "").replace("Bearer ", "") or request.headers.get("X-API-Key", "")
        bootstrap = os.environ.get("HALDIR_BOOTSTRAP_TOKEN", "")
        if key:
            key_hash = _hash_key(key)
            conn = get_db(DB_PATH)
            row = conn.execute("SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0", (key_hash,)).fetchone()
            conn.close()
            if not row:
                return jsonify({"error": "Invalid API key"}), 401
        elif bootstrap and request.json and request.json.get("bootstrap_token") == bootstrap:
            pass
        else:
            return jsonify({"error": "Authentication required to create additional keys"}), 401

    data = request.json or {}
    name = data.get("name", "default")
    tier = data.get("tier", "free")

    full_key = f"hld_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(full_key)

    conn = get_db(DB_PATH)
    conn.execute(
        "INSERT INTO api_keys (key_hash, key_prefix, name, tier, created_at) VALUES (?, ?, ?, ?, ?)",
        (key_hash, full_key[:12], name, tier, time.time())
    )
    conn.commit()
    conn.close()

    return jsonify({
        "key": full_key,
        "prefix": full_key[:12],
        "name": name,
        "tier": tier,
        "message": "Save this key — it won't be shown again.",
    }), 201


# ── Gate: Sessions ──

@app.route("/v1/sessions", methods=["POST"])
@require_api_key
def create_session():
    data = request.json or {}
    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "agent_id is required"}), 400

    scopes = data.get("scopes", ["read", "browse"])
    ttl = data.get("ttl", 3600)
    spend_limit = data.get("spend_limit")

    gate.register_agent(agent_id, default_scopes=scopes)
    session = gate.create_session(agent_id, scopes=scopes, ttl=ttl, spend_limit=spend_limit)

    return jsonify({
        "session_id": session.session_id,
        "agent_id": session.agent_id,
        "scopes": session.scopes,
        "spend_limit": session.spend_limit,
        "expires_at": session.expires_at,
        "ttl": ttl,
    }), 201


@app.route("/v1/sessions/<session_id>", methods=["GET"])
@require_api_key
def get_session(session_id):
    session = gate.get_session(session_id)
    if not session:
        return jsonify({"error": "Session not found or expired"}), 404

    return jsonify({
        "session_id": session.session_id,
        "agent_id": session.agent_id,
        "scopes": session.scopes,
        "spend_limit": session.spend_limit,
        "spent": session.spent,
        "remaining_budget": session.remaining_budget,
        "is_valid": session.is_valid,
        "created_at": session.created_at,
        "expires_at": session.expires_at,
    })


@app.route("/v1/sessions/<session_id>", methods=["DELETE"])
@require_api_key
def revoke_session(session_id):
    revoked = gate.revoke_session(session_id)
    if not revoked:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({"revoked": True, "session_id": session_id})


@app.route("/v1/sessions/<session_id>/check", methods=["POST"])
@require_api_key
def check_permission(session_id):
    data = request.json or {}
    scope = data.get("scope")
    if not scope:
        return jsonify({"error": "scope is required"}), 400

    allowed = gate.check_permission(session_id, scope)
    return jsonify({"allowed": allowed, "session_id": session_id, "scope": scope})


# ── Vault: Secrets ──

@app.route("/v1/secrets", methods=["POST"])
@require_api_key
def store_secret():
    data = request.json or {}
    name = data.get("name")
    value = data.get("value")
    if not name or not value:
        return jsonify({"error": "name and value are required"}), 400

    scope_required = data.get("scope_required", "read")
    vault.store_secret(name, value, scope_required=scope_required)

    return jsonify({"stored": True, "name": name}), 201


@app.route("/v1/secrets/<name>", methods=["GET"])
@require_api_key
def get_secret(name):
    session_id = request.headers.get("X-Session-ID") or request.args.get("session_id")
    session = None
    if session_id:
        session = gate.get_session(session_id)
        if not session:
            return jsonify({"error": "Invalid or expired session"}), 401

    try:
        value = vault.get_secret(name, session=session)
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403

    if value is None:
        return jsonify({"error": f"Secret '{name}' not found"}), 404

    return jsonify({"name": name, "value": value})


@app.route("/v1/secrets/<name>", methods=["DELETE"])
@require_api_key
def delete_secret(name):
    deleted = vault.delete_secret(name)
    if not deleted:
        return jsonify({"error": f"Secret '{name}' not found"}), 404
    return jsonify({"deleted": True, "name": name})


@app.route("/v1/secrets", methods=["GET"])
@require_api_key
def list_secrets():
    names = vault.list_secrets()
    return jsonify({"secrets": names, "count": len(names)})


# ── Vault: Payments ──

@app.route("/v1/payments/authorize", methods=["POST"])
@require_api_key
def authorize_payment():
    data = request.json or {}
    session_id = data.get("session_id")
    amount = data.get("amount")

    if not session_id or amount is None:
        return jsonify({"error": "session_id and amount are required"}), 400

    session = gate.get_session(session_id)
    if not session:
        return jsonify({"error": "Invalid or expired session"}), 401

    result = vault.authorize_payment(
        session, float(amount),
        currency=data.get("currency", "USD"),
        description=data.get("description", ""),
    )

    status = 200 if result["authorized"] else 403
    return jsonify(result), status


# ── Watch: Audit ──

@app.route("/v1/audit", methods=["POST"])
@require_api_key
def log_action():
    data = request.json or {}
    session_id = data.get("session_id")
    tool = data.get("tool", "")
    action = data.get("action", "")

    if not session_id or not action:
        return jsonify({"error": "session_id and action are required"}), 400

    session = gate.get_session(session_id)
    if not session:
        return jsonify({"error": "Invalid or expired session"}), 401

    entry = watch.log_action(
        session, tool=tool, action=action,
        details=data.get("details"),
        cost_usd=float(data.get("cost_usd", 0)),
    )

    return jsonify({
        "logged": True,
        "entry_id": entry.entry_id,
        "flagged": entry.flagged,
        "flag_reason": entry.flag_reason,
    }), 201


@app.route("/v1/audit", methods=["GET"])
@require_api_key
def get_audit_trail():
    entries = watch.get_audit_trail(
        session_id=request.args.get("session_id"),
        agent_id=request.args.get("agent_id"),
        tool=request.args.get("tool"),
        flagged_only=request.args.get("flagged") == "true",
        limit=int(request.args.get("limit", 100)),
    )

    return jsonify({
        "count": len(entries),
        "entries": [
            {
                "entry_id": e.entry_id,
                "session_id": e.session_id,
                "agent_id": e.agent_id,
                "tool": e.tool,
                "action": e.action,
                "cost_usd": e.cost_usd,
                "flagged": e.flagged,
                "flag_reason": e.flag_reason,
                "timestamp": e.timestamp,
                "details": e.details,
            }
            for e in entries
        ],
    })


@app.route("/v1/audit/spend", methods=["GET"])
@require_api_key
def get_spend():
    return jsonify(watch.get_spend(
        session_id=request.args.get("session_id"),
        agent_id=request.args.get("agent_id"),
    ))


# ── Approvals (Human-in-the-loop) ──

from haldir_gate.approvals import ApprovalEngine, ApprovalStatus
approval_engine = ApprovalEngine(db_path=DB_PATH)

@app.route("/v1/approvals/rules", methods=["POST"])
@require_api_key
def add_approval_rule():
    data = request.json or {}
    rule_type = data.get("type")
    if not rule_type:
        return jsonify({"error": "type is required (spend_over, tool_blocked, destructive, all)"}), 400
    approval_engine.add_rule(
        rule_type=rule_type,
        threshold=float(data.get("threshold", 0)),
        tools=data.get("tools"),
    )
    return jsonify({"added": True, "type": rule_type}), 201


@app.route("/v1/approvals/request", methods=["POST"])
@require_api_key
def request_approval():
    data = request.json or {}
    session_id = data.get("session_id")
    if not session_id:
        return jsonify({"error": "session_id is required"}), 400
    session = gate.get_session(session_id)
    if not session:
        return jsonify({"error": "Invalid or expired session"}), 401

    req = approval_engine.request_approval(
        session=session,
        tool=data.get("tool", ""),
        action=data.get("action", ""),
        amount=float(data.get("amount", 0)),
        reason=data.get("reason", ""),
        details=data.get("details"),
        ttl=int(data.get("ttl", 3600)),
    )
    return jsonify({
        "request_id": req.request_id,
        "status": req.status.value,
        "expires_at": req.expires_at,
    }), 201


@app.route("/v1/approvals/<request_id>", methods=["GET"])
@require_api_key
def check_approval(request_id):
    req = approval_engine.check(request_id)
    if not req:
        return jsonify({"error": "Approval request not found"}), 404
    return jsonify({
        "request_id": req.request_id,
        "status": req.status.value,
        "agent_id": req.agent_id,
        "tool": req.tool,
        "action": req.action,
        "amount": req.amount,
        "reason": req.reason,
        "decided_by": req.decided_by,
        "decision_note": req.decision_note,
    })


@app.route("/v1/approvals/<request_id>/approve", methods=["POST"])
@require_api_key
def approve_request(request_id):
    data = request.json or {}
    ok = approval_engine.approve(
        request_id,
        decided_by=data.get("decided_by", ""),
        note=data.get("note", ""),
    )
    if not ok:
        return jsonify({"error": "Cannot approve — not found, already decided, or expired"}), 400
    return jsonify({"approved": True, "request_id": request_id})


@app.route("/v1/approvals/<request_id>/deny", methods=["POST"])
@require_api_key
def deny_request(request_id):
    data = request.json or {}
    ok = approval_engine.deny(
        request_id,
        decided_by=data.get("decided_by", ""),
        note=data.get("note", ""),
    )
    if not ok:
        return jsonify({"error": "Cannot deny — not found, already decided, or expired"}), 400
    return jsonify({"denied": True, "request_id": request_id})


@app.route("/v1/approvals/pending", methods=["GET"])
@require_api_key
def pending_approvals():
    pending = approval_engine.get_pending(agent_id=request.args.get("agent_id"))
    return jsonify({
        "count": len(pending),
        "requests": [
            {
                "request_id": r.request_id,
                "agent_id": r.agent_id,
                "tool": r.tool,
                "action": r.action,
                "amount": r.amount,
                "reason": r.reason,
                "created_at": r.created_at,
            }
            for r in pending
        ],
    })


# ── Webhooks ──

from haldir_watch.webhooks import WebhookManager
webhook_mgr = WebhookManager(db_path=DB_PATH)

@app.route("/v1/webhooks", methods=["POST"])
@require_api_key
def register_webhook():
    data = request.json or {}
    url = data.get("url")
    if not url:
        return jsonify({"error": "url is required"}), 400
    wh = webhook_mgr.register(
        url=url,
        name=data.get("name", ""),
        events=data.get("events"),
    )
    return jsonify({"registered": True, "url": wh.url, "events": wh.events}), 201


@app.route("/v1/webhooks", methods=["GET"])
@require_api_key
def list_webhooks():
    return jsonify({"webhooks": webhook_mgr.list_webhooks()})


# ── Rate Limiting ──

_rate_limits = {}  # key_hash -> {window_start, count}
RATE_LIMITS = {"free": 100, "pro": 5000, "enterprise": 50000}

@app.before_request
def rate_limit():
    if request.path.startswith("/v1/") and request.path != "/v1/keys":
        key = request.headers.get("Authorization", "").replace("Bearer ", "") or request.headers.get("X-API-Key", "")
        if not key:
            return
        key_hash = _hash_key(key)
        now = time.time()
        window = 3600  # 1 hour
        entry = _rate_limits.get(key_hash, {"start": now, "count": 0})
        if now - entry["start"] > window:
            entry = {"start": now, "count": 0}
        entry["count"] += 1
        _rate_limits[key_hash] = entry

        tier = getattr(request, "api_key_tier", "free")
        limit = RATE_LIMITS.get(tier, 100)
        if entry["count"] > limit:
            return jsonify({
                "error": "Rate limit exceeded",
                "limit": limit,
                "tier": tier,
                "retry_after": int(entry["start"] + window - now),
            }), 429


# ── API Docs ──

@app.route("/docs")
def api_docs():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Haldir API Docs</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500&family=Inter:wght@200;300;400;600&display=swap" rel="stylesheet">
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#050505; color:#e0ddd5; font-family:'Inter',sans-serif; padding:3rem; max-width:800px; margin:0 auto; }
h1 { font-weight:200; font-size:2rem; margin-bottom:0.5rem; }
h2 { font-weight:400; font-size:1.1rem; margin:2.5rem 0 1rem; color:#b8973a; }
h3 { font-weight:400; font-size:0.85rem; margin:1.5rem 0 0.5rem; color:rgba(224,221,213,0.8); }
p, li { font-size:0.85rem; line-height:1.8; color:rgba(224,221,213,0.6); }
code { font-family:'IBM Plex Mono',monospace; font-size:0.78rem; background:rgba(255,255,255,0.05); padding:0.15rem 0.4rem; border-radius:3px; }
pre { font-family:'IBM Plex Mono',monospace; font-size:0.75rem; background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.08); border-radius:6px; padding:1.25rem; margin:0.75rem 0; overflow-x:auto; line-height:1.9; color:rgba(224,221,213,0.5); }
.method { display:inline-block; font-family:'IBM Plex Mono',monospace; font-size:0.65rem; font-weight:500; padding:0.2rem 0.5rem; border-radius:3px; margin-right:0.5rem; letter-spacing:1px; }
.post { background:rgba(34,197,94,0.15); color:#6bbd6b; }
.get { background:rgba(59,130,246,0.15); color:#7ba8e8; }
.delete { background:rgba(239,68,68,0.15); color:#e87b7b; }
a { color:#b8973a; text-decoration:none; }
hr { border:none; border-top:1px solid rgba(255,255,255,0.08); margin:2rem 0; }
.sub { font-family:'IBM Plex Mono',monospace; font-size:0.6rem; color:rgba(224,221,213,0.3); letter-spacing:2px; text-transform:uppercase; }
</style>
</head>
<body>
<h1>Haldir API</h1>
<p class="sub">v0.1.0 — the guardian layer for AI agents</p>
<p style="margin-top:1rem;">Base URL: <code>https://haldir.xyz/v1</code></p>
<p>Auth: <code>Authorization: Bearer hld_your_key</code> or <code>X-API-Key: hld_your_key</code></p>

<h2>Authentication</h2>
<h3><span class="method post">POST</span> /v1/keys</h3>
<p>Create an API key. First key requires no auth.</p>
<pre>curl -X POST https://haldir.xyz/v1/keys \\
  -H "Content-Type: application/json" \\
  -d '{"name": "my-app", "tier": "pro"}'</pre>

<hr>
<h2>Gate — Sessions</h2>

<h3><span class="method post">POST</span> /v1/sessions</h3>
<p>Create a scoped agent session.</p>
<pre>curl -X POST https://haldir.xyz/v1/sessions \\
  -H "Authorization: Bearer hld_xxx" \\
  -H "Content-Type: application/json" \\
  -d '{"agent_id": "my-bot", "scopes": ["read", "browse", "spend:50"], "ttl": 3600}'</pre>

<h3><span class="method get">GET</span> /v1/sessions/:id</h3>
<p>Get session info including remaining budget.</p>

<h3><span class="method delete">DELETE</span> /v1/sessions/:id</h3>
<p>Revoke a session immediately.</p>

<h3><span class="method post">POST</span> /v1/sessions/:id/check</h3>
<p>Check if a session has a permission. Body: <code>{"scope": "write"}</code></p>

<hr>
<h2>Vault — Secrets</h2>

<h3><span class="method post">POST</span> /v1/secrets</h3>
<p>Store an encrypted secret.</p>
<pre>curl -X POST https://haldir.xyz/v1/secrets \\
  -H "Authorization: Bearer hld_xxx" \\
  -H "Content-Type: application/json" \\
  -d '{"name": "stripe_key", "value": "sk_live_xxx", "scope_required": "read"}'</pre>

<h3><span class="method get">GET</span> /v1/secrets/:name</h3>
<p>Retrieve a secret. Pass <code>X-Session-ID</code> header for scope enforcement.</p>

<h3><span class="method get">GET</span> /v1/secrets</h3>
<p>List all secret names (never values).</p>

<h3><span class="method delete">DELETE</span> /v1/secrets/:name</h3>
<p>Delete a secret permanently.</p>

<hr>
<h2>Payments</h2>

<h3><span class="method post">POST</span> /v1/payments/authorize</h3>
<p>Authorize a payment against a session's budget.</p>
<pre>curl -X POST https://haldir.xyz/v1/payments/authorize \\
  -H "Authorization: Bearer hld_xxx" \\
  -H "Content-Type: application/json" \\
  -d '{"session_id": "ses_xxx", "amount": 29.99, "description": "API subscription"}'</pre>

<hr>
<h2>Watch — Audit</h2>

<h3><span class="method post">POST</span> /v1/audit</h3>
<p>Log an agent action.</p>
<pre>curl -X POST https://haldir.xyz/v1/audit \\
  -H "Authorization: Bearer hld_xxx" \\
  -H "Content-Type: application/json" \\
  -d '{"session_id": "ses_xxx", "tool": "stripe", "action": "charge", "cost_usd": 29.99}'</pre>

<h3><span class="method get">GET</span> /v1/audit</h3>
<p>Query audit trail. Params: <code>session_id</code>, <code>agent_id</code>, <code>tool</code>, <code>flagged=true</code>, <code>limit</code>.</p>

<h3><span class="method get">GET</span> /v1/audit/spend</h3>
<p>Spend summary by tool. Params: <code>session_id</code>, <code>agent_id</code>.</p>

<hr>
<h2>Approvals — Human-in-the-loop</h2>

<h3><span class="method post">POST</span> /v1/approvals/rules</h3>
<p>Add an auto-approval rule. Types: <code>spend_over</code>, <code>tool_blocked</code>, <code>destructive</code>, <code>all</code>.</p>
<pre>curl -X POST https://haldir.xyz/v1/approvals/rules \\
  -H "Authorization: Bearer hld_xxx" \\
  -H "Content-Type: application/json" \\
  -d '{"type": "spend_over", "threshold": 100}'</pre>

<h3><span class="method post">POST</span> /v1/approvals/request</h3>
<p>Request human approval for an action.</p>

<h3><span class="method get">GET</span> /v1/approvals/:id</h3>
<p>Check approval status (agent polls this).</p>

<h3><span class="method post">POST</span> /v1/approvals/:id/approve</h3>
<p>Approve a pending request.</p>

<h3><span class="method post">POST</span> /v1/approvals/:id/deny</h3>
<p>Deny a pending request.</p>

<h3><span class="method get">GET</span> /v1/approvals/pending</h3>
<p>List all pending approval requests.</p>

<hr>
<h2>Webhooks</h2>

<h3><span class="method post">POST</span> /v1/webhooks</h3>
<p>Register a webhook. Events: <code>all</code>, <code>anomaly</code>, <code>approval_requested</code>, <code>budget_exhausted</code>.</p>
<pre>curl -X POST https://haldir.xyz/v1/webhooks \\
  -H "Authorization: Bearer hld_xxx" \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://hooks.slack.com/xxx", "events": ["anomaly", "approval_requested"]}'</pre>

<h3><span class="method get">GET</span> /v1/webhooks</h3>
<p>List registered webhooks.</p>

<hr>
<h2>MCP</h2>

<h3><span class="method post">POST</span> /mcp</h3>
<p>MCP JSON-RPC endpoint for AI assistants. Supports <code>initialize</code>, <code>tools/list</code>, <code>tools/call</code>, <code>resources/list</code>, <code>prompts/list</code>.</p>

<h3><span class="method get">GET</span> /.well-known/mcp/server-card.json</h3>
<p>MCP server discovery metadata.</p>

<hr>
<p style="margin-top:2rem; font-size:0.75rem; color:rgba(224,221,213,0.3);">&copy; 2026 Haldir &middot; <a href="https://haldir.xyz">haldir.xyz</a></p>
</body>
</html>""", 200, {"Content-Type": "text/html"}


# ── MCP JSON-RPC (Model Context Protocol) ──

MCP_SERVER_INFO = {
    "name": "haldir",
    "version": "0.1.0",
    "displayName": "Haldir — AI Agent Security Gateway",
    "description": (
        "Haldir is a security and governance layer for AI agents. "
        "It provides session-scoped permissions (Gate), encrypted secret storage "
        "with access control (Vault), and tamper-evident audit logging with "
        "anomaly detection (Watch). Use Haldir to enforce least-privilege, "
        "track spend budgets, and maintain full accountability for every action "
        "an AI agent takes."
    ),
}

MCP_CAPABILITIES = {
    "tools": {"listChanged": False},
    "resources": {"listChanged": False},
    "prompts": {"listChanged": False},
}

MCP_TOOLS = [
    {
        "name": "create_session",
        "description": (
            "Create a new agent session with scoped permissions and an optional spend budget. "
            "Every AI agent must have an active session before it can access secrets, make payments, "
            "or perform auditable actions. You specify which scopes (e.g. read, write, admin) the "
            "agent is allowed, a TTL in seconds, and an optional USD spend limit."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Unique identifier for the AI agent requesting a session. Used to track all actions back to this agent."
                },
                "scopes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of permission scopes to grant (e.g. ['read', 'browse', 'write']). Defaults to ['read', 'browse'] if omitted."
                },
                "ttl": {
                    "type": "integer",
                    "description": "Session time-to-live in seconds. The session automatically expires after this duration. Defaults to 3600 (1 hour)."
                },
                "spend_limit": {
                    "type": "number",
                    "description": "Maximum USD amount this session is allowed to spend. Once reached, all payment authorizations are denied. Omit for unlimited."
                },
            },
            "required": ["agent_id"],
        },
        "annotations": {
            "title": "Create Agent Session",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "get_session",
        "description": (
            "Retrieve the current state of an agent session including its scopes, spend budget, "
            "remaining balance, and validity status. Use this to check whether a session is still "
            "active before performing privileged operations, or to inspect how much budget remains."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID returned by create_session. This is the unique identifier for the session to inspect."
                },
            },
            "required": ["session_id"],
        },
        "annotations": {
            "title": "Get Session Info",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "revoke_session",
        "description": (
            "Immediately revoke an agent session, permanently disabling all permissions and blocking "
            "further actions under that session. Use this when an agent misbehaves, exceeds its mandate, "
            "or when a task is complete and the session should be cleaned up for security hygiene."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID to revoke. Once revoked, this session cannot be reactivated."
                },
            },
            "required": ["session_id"],
        },
        "annotations": {
            "title": "Revoke Session",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "check_permission",
        "description": (
            "Check whether a specific session has a given permission scope. Returns a boolean indicating "
            "if the action is allowed. Use this before performing any sensitive operation to enforce "
            "least-privilege access control without risking a 403 error on the actual call."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID to check permissions for."
                },
                "scope": {
                    "type": "string",
                    "description": "The permission scope to check (e.g. 'read', 'write', 'admin', 'execute')."
                },
            },
            "required": ["session_id", "scope"],
        },
        "annotations": {
            "title": "Check Permission",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "store_secret",
        "description": (
            "Store an encrypted secret in the Haldir Vault with an optional scope requirement. "
            "Secrets are encrypted at rest using AES and can only be retrieved by sessions that hold "
            "the required scope. Use this to safely store API keys, tokens, credentials, or any "
            "sensitive data that agents need access to."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "A unique name for the secret (e.g. 'openai_api_key', 'stripe_token'). Used to retrieve it later."
                },
                "value": {
                    "type": "string",
                    "description": "The secret value to encrypt and store. This is never logged or exposed in audit trails."
                },
                "scope_required": {
                    "type": "string",
                    "description": "The minimum permission scope a session must hold to read this secret. Defaults to 'read'."
                },
            },
            "required": ["name", "value"],
        },
        "annotations": {
            "title": "Store Secret",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "get_secret",
        "description": (
            "Retrieve a decrypted secret from the Vault. If a session_id is provided, the session's "
            "scopes are checked against the secret's required scope before returning the value. "
            "This is the primary way agents access credentials — through policy-controlled, auditable retrieval."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "The name of the secret to retrieve, as specified when it was stored."
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional session ID for scope-based access control. If provided, the session must hold the secret's required scope."
                },
            },
            "required": ["name"],
        },
        "annotations": {
            "title": "Get Secret",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "authorize_payment",
        "description": (
            "Authorize a payment against an agent session's spend budget. The amount is deducted from "
            "the session's remaining budget if sufficient funds exist. If the payment would exceed the "
            "budget, it is denied. Every authorization is logged to the audit trail for full financial accountability."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID whose budget to charge. The session must have a spend_limit set."
                },
                "amount": {
                    "type": "number",
                    "description": "The amount in the specified currency to authorize (e.g. 0.50 for fifty cents)."
                },
                "currency": {
                    "type": "string",
                    "description": "ISO 4217 currency code. Defaults to 'USD'."
                },
                "description": {
                    "type": "string",
                    "description": "Human-readable description of what this payment is for (e.g. 'GPT-4 API call', 'search query')."
                },
            },
            "required": ["session_id", "amount"],
        },
        "annotations": {
            "title": "Authorize Payment",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "log_action",
        "description": (
            "Log an agent action to the tamper-evident audit trail with automatic anomaly detection. "
            "Every tool call, API request, or decision an agent makes should be logged here. The Watch "
            "module automatically flags suspicious patterns like rapid-fire actions, high-cost operations, "
            "or unusual tool usage. Returns whether the action was flagged."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID performing the action. Links this log entry to the agent and its permissions."
                },
                "tool": {
                    "type": "string",
                    "description": "Name of the tool or service being used (e.g. 'web_search', 'code_exec', 'email_send')."
                },
                "action": {
                    "type": "string",
                    "description": "Description of the action taken (e.g. 'searched for competitor pricing', 'sent email to client')."
                },
                "details": {
                    "type": "string",
                    "description": "Optional additional context or metadata about the action in free-form text."
                },
                "cost_usd": {
                    "type": "number",
                    "description": "Optional cost in USD associated with this action (e.g. API call cost). Defaults to 0."
                },
            },
            "required": ["session_id", "action"],
        },
        "annotations": {
            "title": "Log Action",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "get_audit_trail",
        "description": (
            "Query the audit trail to review all actions taken by agents. Filter by session ID, agent ID, "
            "tool name, or flagged-only entries. Returns a chronological list of logged actions with their "
            "costs, timestamps, and anomaly flags. Essential for compliance reviews and debugging agent behavior."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Filter audit entries to a specific session. Omit to see all sessions."
                },
                "agent_id": {
                    "type": "string",
                    "description": "Filter audit entries to a specific agent. Omit to see all agents."
                },
                "tool": {
                    "type": "string",
                    "description": "Filter to entries from a specific tool (e.g. 'web_search'). Omit to see all tools."
                },
                "flagged_only": {
                    "type": "boolean",
                    "description": "If true, only return entries that were flagged as anomalous. Defaults to false."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of entries to return. Defaults to 100."
                },
            },
        },
        "annotations": {
            "title": "Get Audit Trail",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "get_spend",
        "description": (
            "Get a summary of total spend across agent sessions, broken down by session or agent. "
            "Returns total USD spent, number of transactions, and budget utilization. Use this to monitor "
            "cost control and detect runaway spending before budgets are exhausted."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Get spend for a specific session. Omit to see aggregate spend."
                },
                "agent_id": {
                    "type": "string",
                    "description": "Get spend for a specific agent across all their sessions. Omit to see all agents."
                },
            },
        },
        "annotations": {
            "title": "Get Spend Summary",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
]

MCP_PROMPTS = [
    {
        "name": "security-audit",
        "description": (
            "Audit an AI agent's recent actions for security concerns. Reviews the audit trail "
            "for anomalous patterns, excessive spending, scope violations, and suspicious behavior."
        ),
        "arguments": [
            {
                "name": "session_id",
                "description": "The session ID to audit. If omitted, audits all recent sessions.",
                "required": False,
            },
        ],
    },
    {
        "name": "budget-check",
        "description": (
            "Check the remaining budget for an agent session and warn if spending is approaching "
            "the limit. Provides a summary of spend rate and estimated time until budget exhaustion."
        ),
        "arguments": [
            {
                "name": "session_id",
                "description": "The session ID whose budget to check.",
                "required": True,
            },
        ],
    },
]

SYSTEM_INSTRUCTIONS = (
    "You are using Haldir, an AI agent security gateway. Haldir enforces least-privilege access, "
    "manages encrypted secrets, controls spend budgets, and logs every action to a tamper-evident "
    "audit trail.\n\n"
    "Workflow:\n"
    "1. Create a session with create_session (specify scopes and budget)\n"
    "2. Use check_permission before sensitive operations\n"
    "3. Retrieve secrets with get_secret (scope-checked)\n"
    "4. Authorize payments with authorize_payment (budget-checked)\n"
    "5. Log every action with log_action for accountability\n"
    "6. Review behavior with get_audit_trail and get_spend\n"
    "7. Revoke sessions when done with revoke_session\n\n"
    "Always follow the principle of least privilege: request only the scopes you need, "
    "set spend limits, and revoke sessions promptly."
)


def _mcp_response(id, result):
    """Build a JSON-RPC 2.0 success response."""
    return jsonify({"jsonrpc": "2.0", "id": id, "result": result})


def _mcp_error(id, code, message):
    """Build a JSON-RPC 2.0 error response."""
    return jsonify({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})


def _mcp_call_tool(name, arguments):
    """Dispatch an MCP tool call to the existing Gate/Vault/Watch logic."""

    # -- Gate --
    if name == "create_session":
        agent_id = arguments.get("agent_id")
        if not agent_id:
            return {"isError": True, "content": [{"type": "text", "text": "agent_id is required"}]}
        scopes = arguments.get("scopes", ["read", "browse"])
        ttl = arguments.get("ttl", 3600)
        spend_limit = arguments.get("spend_limit")
        gate.register_agent(agent_id, default_scopes=scopes)
        session = gate.create_session(agent_id, scopes=scopes, ttl=ttl, spend_limit=spend_limit)
        return {"content": [{"type": "text", "text": json.dumps({
            "session_id": session.session_id,
            "agent_id": session.agent_id,
            "scopes": session.scopes,
            "spend_limit": session.spend_limit,
            "expires_at": session.expires_at,
            "ttl": ttl,
        })}]}

    if name == "get_session":
        session = gate.get_session(arguments.get("session_id", ""))
        if not session:
            return {"isError": True, "content": [{"type": "text", "text": "Session not found or expired"}]}
        return {"content": [{"type": "text", "text": json.dumps({
            "session_id": session.session_id,
            "agent_id": session.agent_id,
            "scopes": session.scopes,
            "spend_limit": session.spend_limit,
            "spent": session.spent,
            "remaining_budget": session.remaining_budget,
            "is_valid": session.is_valid,
            "created_at": session.created_at,
            "expires_at": session.expires_at,
        })}]}

    if name == "revoke_session":
        sid = arguments.get("session_id", "")
        revoked = gate.revoke_session(sid)
        if not revoked:
            return {"isError": True, "content": [{"type": "text", "text": "Session not found"}]}
        return {"content": [{"type": "text", "text": json.dumps({"revoked": True, "session_id": sid})}]}

    if name == "check_permission":
        sid = arguments.get("session_id", "")
        scope = arguments.get("scope", "")
        if not scope:
            return {"isError": True, "content": [{"type": "text", "text": "scope is required"}]}
        allowed = gate.check_permission(sid, scope)
        return {"content": [{"type": "text", "text": json.dumps({"allowed": allowed, "session_id": sid, "scope": scope})}]}

    # -- Vault --
    if name == "store_secret":
        sname = arguments.get("name", "")
        value = arguments.get("value", "")
        if not sname or not value:
            return {"isError": True, "content": [{"type": "text", "text": "name and value are required"}]}
        scope_req = arguments.get("scope_required", "read")
        vault.store_secret(sname, value, scope_required=scope_req)
        return {"content": [{"type": "text", "text": json.dumps({"stored": True, "name": sname})}]}

    if name == "get_secret":
        sname = arguments.get("name", "")
        session_id = arguments.get("session_id")
        session = None
        if session_id:
            session = gate.get_session(session_id)
            if not session:
                return {"isError": True, "content": [{"type": "text", "text": "Invalid or expired session"}]}
        try:
            value = vault.get_secret(sname, session=session)
        except PermissionError as e:
            return {"isError": True, "content": [{"type": "text", "text": str(e)}]}
        if value is None:
            return {"isError": True, "content": [{"type": "text", "text": f"Secret '{sname}' not found"}]}
        return {"content": [{"type": "text", "text": json.dumps({"name": sname, "value": value})}]}

    if name == "authorize_payment":
        sid = arguments.get("session_id", "")
        amount = arguments.get("amount")
        if not sid or amount is None:
            return {"isError": True, "content": [{"type": "text", "text": "session_id and amount are required"}]}
        session = gate.get_session(sid)
        if not session:
            return {"isError": True, "content": [{"type": "text", "text": "Invalid or expired session"}]}
        result = vault.authorize_payment(
            session, float(amount),
            currency=arguments.get("currency", "USD"),
            description=arguments.get("description", ""),
        )
        return {"content": [{"type": "text", "text": json.dumps(result)}]}

    # -- Watch --
    if name == "log_action":
        sid = arguments.get("session_id", "")
        action = arguments.get("action", "")
        if not sid or not action:
            return {"isError": True, "content": [{"type": "text", "text": "session_id and action are required"}]}
        session = gate.get_session(sid)
        if not session:
            return {"isError": True, "content": [{"type": "text", "text": "Invalid or expired session"}]}
        entry = watch.log_action(
            session, tool=arguments.get("tool", ""), action=action,
            details=arguments.get("details"),
            cost_usd=float(arguments.get("cost_usd", 0)),
        )
        return {"content": [{"type": "text", "text": json.dumps({
            "logged": True, "entry_id": entry.entry_id,
            "flagged": entry.flagged, "flag_reason": entry.flag_reason,
        })}]}

    if name == "get_audit_trail":
        entries = watch.get_audit_trail(
            session_id=arguments.get("session_id"),
            agent_id=arguments.get("agent_id"),
            tool=arguments.get("tool"),
            flagged_only=arguments.get("flagged_only", False),
            limit=int(arguments.get("limit", 100)),
        )
        return {"content": [{"type": "text", "text": json.dumps({
            "count": len(entries),
            "entries": [
                {
                    "entry_id": e.entry_id, "session_id": e.session_id,
                    "agent_id": e.agent_id, "tool": e.tool, "action": e.action,
                    "cost_usd": e.cost_usd, "flagged": e.flagged,
                    "flag_reason": e.flag_reason, "timestamp": e.timestamp,
                    "details": e.details,
                }
                for e in entries
            ],
        })}]}

    if name == "get_spend":
        return {"content": [{"type": "text", "text": json.dumps(watch.get_spend(
            session_id=arguments.get("session_id"),
            agent_id=arguments.get("agent_id"),
        ))}]}

    return {"isError": True, "content": [{"type": "text", "text": f"Unknown tool: {name}"}]}


@app.route("/mcp", methods=["POST"])
def mcp_jsonrpc():
    """MCP JSON-RPC 2.0 endpoint for Smithery.ai and MCP clients."""
    body = request.get_json(silent=True)
    if not body:
        return _mcp_error(None, -32700, "Parse error"), 400

    method = body.get("method", "")
    req_id = body.get("id")
    params = body.get("params", {})

    # notifications (no id) — return 204
    if req_id is None and method.startswith("notifications/"):
        return "", 204

    if method == "initialize":
        return _mcp_response(req_id, {
            "protocolVersion": "2024-11-05",
            "serverInfo": MCP_SERVER_INFO,
            "capabilities": MCP_CAPABILITIES,
            "instructions": SYSTEM_INSTRUCTIONS,
        })

    if method == "tools/list":
        return _mcp_response(req_id, {"tools": MCP_TOOLS})

    if method == "resources/list":
        return _mcp_response(req_id, {"resources": []})

    if method == "prompts/list":
        return _mcp_response(req_id, {"prompts": MCP_PROMPTS})

    if method == "prompts/get":
        prompt_name = params.get("name", "")
        if prompt_name == "security-audit":
            sid = (params.get("arguments") or {}).get("session_id", "")
            msg = f"Review the Haldir audit trail"
            if sid:
                msg += f" for session {sid}"
            msg += (
                ". Look for: anomalous action patterns, flagged entries, excessive spending, "
                "scope violations, rapid-fire actions, and any suspicious behavior. "
                "Summarize findings and recommend whether to revoke or continue the session."
            )
            return _mcp_response(req_id, {
                "description": "Audit an agent's actions for security concerns",
                "messages": [{"role": "user", "content": {"type": "text", "text": msg}}],
            })
        if prompt_name == "budget-check":
            sid = (params.get("arguments") or {}).get("session_id", "")
            if not sid:
                return _mcp_error(req_id, -32602, "session_id argument is required for budget-check")
            msg = (
                f"Check the budget status for Haldir session {sid}. "
                "Get the session info and spend summary. Calculate the spend rate, "
                "estimate time until budget exhaustion, and warn if spending is above 75% of the limit."
            )
            return _mcp_response(req_id, {
                "description": "Check remaining budget for an agent session",
                "messages": [{"role": "user", "content": {"type": "text", "text": msg}}],
            })
        return _mcp_error(req_id, -32602, f"Unknown prompt: {prompt_name}")

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        result = _mcp_call_tool(tool_name, arguments)
        return _mcp_response(req_id, result)

    # Unknown method
    return _mcp_error(req_id, -32601, f"Method not found: {method}")


@app.route("/mcp", methods=["GET"])
def mcp_info():
    """GET /mcp — server info for discovery."""
    return jsonify({
        "protocolVersion": "2024-11-05",
        "serverInfo": MCP_SERVER_INFO,
        "capabilities": MCP_CAPABILITIES,
        "instructions": SYSTEM_INSTRUCTIONS,
    })


@app.route("/.well-known/mcp/server-card.json")
def mcp_server_card():
    """MCP server card for automated discovery and Smithery listing."""
    return jsonify({
        "name": "haldir",
        "displayName": "Haldir — AI Agent Security Gateway",
        "description": (
            "Security and governance layer for AI agents. Enforces session-scoped permissions, "
            "manages encrypted secrets with access control, controls spend budgets, and logs "
            "every action to a tamper-evident audit trail with anomaly detection."
        ),
        "version": "0.1.0",
        "url": "https://haldir.xyz",
        "mcpEndpoint": "https://haldir.xyz/mcp",
        "transport": "http",
        "capabilities": MCP_CAPABILITIES,
        "tools": [{"name": t["name"], "description": t["description"]} for t in MCP_TOOLS],
        "prompts": [{"name": p["name"], "description": p["description"]} for p in MCP_PROMPTS],
        "configSchema": {
            "type": "object",
            "properties": {
                "apiKey": {
                    "type": "string",
                    "description": "Haldir API key for authentication (starts with hld_). Create one via POST /v1/keys.",
                },
                "baseUrl": {
                    "type": "string",
                    "description": "Base URL of the Haldir API server. Defaults to https://haldir.xyz",
                    "default": "https://haldir.xyz",
                },
            },
            "required": ["apiKey"],
        },
        "author": {
            "name": "0xN0rD",
            "url": "https://haldir.xyz",
        },
        "license": "AGPL-3.0",
        "tags": [
            "security", "governance", "ai-agents", "permissions", "audit",
            "secrets", "budget", "compliance", "least-privilege", "mcp",
        ],
    })


# ── Health ──

@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "service": "haldir", "version": "0.1.0"})


@app.route("/v1")
def api_index():
    return jsonify({
        "service": "haldir",
        "version": "0.1.0",
        "docs": "https://haldir.xyz/docs",
        "endpoints": {
            "sessions": "/v1/sessions",
            "secrets": "/v1/secrets",
            "payments": "/v1/payments/authorize",
            "audit": "/v1/audit",
            "keys": "/v1/keys",
        },
    })


@app.route("/")
def landing():
    landing_path = os.path.join(os.path.dirname(__file__), "landing", "index.html")
    if os.path.exists(landing_path):
        with open(landing_path) as f:
            return f.read(), 200, {"Content-Type": "text/html"}
    return jsonify({"service": "haldir", "version": "0.1.0"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=True)
