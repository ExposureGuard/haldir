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

from flask import Flask, request, jsonify, abort, redirect
from flask_cors import CORS

from haldir_db import init_db, get_db
from haldir_gate.gate import Gate
from haldir_vault.vault import Vault
from haldir_watch.watch import Watch

# ── App setup ──

DB_PATH = os.environ.get("HALDIR_DB_PATH", "/data/haldir.db" if os.path.isdir("/data") else "haldir.db")
ENCRYPTION_KEY = os.environ.get("HALDIR_ENCRYPTION_KEY", "").encode() or None

app = Flask(__name__)
CORS(app, resources={r"/v1/*": {"origins": "*"}, r"/mcp": {"origins": "*"}})

# Init DB on startup
init_db(DB_PATH)

# Init components
gate = Gate(db_path=DB_PATH)
vault = Vault(encryption_key=ENCRYPTION_KEY, db_path=DB_PATH)
watch = Watch(db_path=DB_PATH)

# Require encryption key in production
if not ENCRYPTION_KEY:
    print("[!] WARNING: No HALDIR_ENCRYPTION_KEY set. A random key was generated.")
    print("[!] Secrets will be LOST on restart. Set HALDIR_ENCRYPTION_KEY env var.")

# ── Billing tier limits ──

TIER_LIMITS = {
    "free":       {"agents": 1,    "actions_per_month": 1_000},
    "pro":        {"agents": 10,   "actions_per_month": 50_000},
    "enterprise": {"agents": 999_999, "actions_per_month": 999_999_999},
}

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_PRO = os.environ.get("STRIPE_PRICE_PRO", "")
STRIPE_PRICE_ENTERPRISE = os.environ.get("STRIPE_PRICE_ENTERPRISE", "")


# ── API Key auth ──


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
        try:
            request.tenant_id = row["tenant_id"] or key_hash[:16]
        except (IndexError, KeyError):
            request.tenant_id = key_hash[:16]
        return f(*args, **kwargs)
    return decorated


def _get_tenant_tier(tenant_id):
    """Get the effective billing tier for a tenant from subscriptions table."""
    conn = get_db(DB_PATH)
    row = conn.execute(
        "SELECT tier, status FROM subscriptions WHERE tenant_id = ?",
        (tenant_id,)
    ).fetchone()
    conn.close()
    if row and row["status"] == "active":
        return row["tier"]
    return "free"


def _get_tenant_agent_count(tenant_id):
    """Count distinct agents with active sessions for a tenant."""
    conn = get_db(DB_PATH)
    count = conn.execute(
        "SELECT COUNT(DISTINCT agent_id) FROM sessions WHERE tenant_id = ? AND revoked = 0 AND (expires_at = 0 OR expires_at > ?)",
        (tenant_id, time.time())
    ).fetchone()[0]
    conn.close()
    return count


def _get_tenant_monthly_actions(tenant_id):
    """Get action count for current month."""
    month = time.strftime("%Y-%m")
    conn = get_db(DB_PATH)
    row = conn.execute(
        "SELECT action_count FROM usage WHERE tenant_id = ? AND month = ?",
        (tenant_id, month)
    ).fetchone()
    conn.close()
    return row["action_count"] if row else 0


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
    tier = "free"  # Always free on creation — only Stripe webhooks can upgrade

    full_key = f"hld_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(full_key)
    tenant_id = key_hash[:16]

    conn = get_db(DB_PATH)
    conn.execute(
        "INSERT INTO api_keys (key_hash, key_prefix, tenant_id, name, tier, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (key_hash, full_key[:12], tenant_id, name, tier, time.time())
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


@app.route("/v1/demo/key", methods=["POST"])
def create_demo_key():
    """Create a temporary demo API key for the landing page. No auth required."""
    try:
        full_key = f"hld_{secrets.token_urlsafe(32)}"
        key_hash = _hash_key(full_key)
        tenant_id = f"demo_{key_hash[:12]}"

        conn = get_db(DB_PATH)
        conn.execute(
            "INSERT INTO api_keys (key_hash, key_prefix, tenant_id, name, tier, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (key_hash, full_key[:12], tenant_id, "landing-demo", "free", time.time())
        )
        conn.commit()
        conn.close()

        return jsonify({
            "key": full_key,
            "prefix": full_key[:12],
            "name": "landing-demo",
            "tier": "free",
        }), 201
    except Exception as e:
        print(f"[!] Demo key creation failed: {e}")
        return jsonify({"error": "Demo temporarily unavailable. Try again in a moment."}), 503


# ── Gate: Sessions ──

@app.route("/v1/sessions", methods=["POST"])
@require_api_key
def create_session():
    data = request.json or {}
    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "agent_id is required"}), 400

    # Enforce agent limit per billing tier
    tenant = getattr(request, "tenant_id", "")
    tier = _get_tenant_tier(tenant)
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    current_agents = _get_tenant_agent_count(tenant)

    # Only count as new agent if this agent_id doesn't already have an active session
    conn = get_db(DB_PATH)
    existing = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE tenant_id = ? AND agent_id = ? AND revoked = 0 AND (expires_at = 0 OR expires_at > ?)",
        (tenant, agent_id, time.time())
    ).fetchone()[0]
    conn.close()
    if existing == 0 and current_agents >= limits["agents"]:
        return jsonify({
            "error": "Agent limit reached for your tier",
            "tier": tier,
            "limit": limits["agents"],
            "current": current_agents,
            "upgrade": "https://haldir.xyz/pricing",
        }), 403

    scopes = data.get("scopes", ["read", "browse"])
    try:
        ttl = int(data.get("ttl", 3600))
    except (TypeError, ValueError):
        return jsonify({"error": "ttl must be an integer"}), 400
    if ttl < 0 or ttl > 86400 * 30:
        return jsonify({"error": "ttl must be between 0 and 2592000 (30 days)"}), 400

    spend_limit = data.get("spend_limit")
    if spend_limit is not None:
        try:
            spend_limit = float(spend_limit)
        except (TypeError, ValueError):
            return jsonify({"error": "spend_limit must be a number"}), 400
        if spend_limit < 0:
            return jsonify({"error": "spend_limit must be non-negative"}), 400

    tenant = getattr(request, "tenant_id", "")
    gate.register_agent(agent_id, default_scopes=scopes, tenant_id=tenant)
    session = gate.create_session(agent_id, scopes=scopes, ttl=ttl, spend_limit=spend_limit, tenant_id=tenant)

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
    tenant = getattr(request, "tenant_id", "")
    session = gate.get_session(session_id, tenant_id=tenant)
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
    tenant = getattr(request, "tenant_id", "")
    revoked = gate.revoke_session(session_id, tenant_id=tenant)
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

    tenant = getattr(request, "tenant_id", "")
    allowed = gate.check_permission(session_id, scope, tenant_id=tenant)
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
    tenant = getattr(request, "tenant_id", "")
    vault.store_secret(name, value, scope_required=scope_required, tenant_id=tenant)

    return jsonify({"stored": True, "name": name}), 201


@app.route("/v1/secrets/<name>", methods=["GET"])
@require_api_key
def get_secret(name):
    tenant = getattr(request, "tenant_id", "")
    session_id = request.headers.get("X-Session-ID") or request.args.get("session_id")
    if not session_id:
        return jsonify({"error": "X-Session-ID header or session_id param required to access secrets"}), 400

    session = gate.get_session(session_id, tenant_id=tenant)
    if not session:
        return jsonify({"error": "Invalid or expired session"}), 401

    try:
        value = vault.get_secret(name, session=session, tenant_id=tenant)
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403

    if value is None:
        return jsonify({"error": f"Secret '{name}' not found"}), 404

    return jsonify({"name": name, "value": value})


@app.route("/v1/secrets/<name>", methods=["DELETE"])
@require_api_key
def delete_secret(name):
    tenant = getattr(request, "tenant_id", "")
    deleted = vault.delete_secret(name, tenant_id=tenant)
    if not deleted:
        return jsonify({"error": f"Secret '{name}' not found"}), 404
    return jsonify({"deleted": True, "name": name})


@app.route("/v1/secrets", methods=["GET"])
@require_api_key
def list_secrets():
    tenant = getattr(request, "tenant_id", "")
    names = vault.list_secrets(tenant_id=tenant)
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

    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return jsonify({"error": "amount must be a number"}), 400
    if amount <= 0:
        return jsonify({"error": "amount must be positive"}), 400
    if amount > 1_000_000:
        return jsonify({"error": "amount exceeds maximum ($1,000,000)"}), 400

    tenant = getattr(request, "tenant_id", "")
    session = gate.get_session(session_id, tenant_id=tenant)
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

    cost_usd = data.get("cost_usd", 0)
    try:
        cost_usd = float(cost_usd)
    except (TypeError, ValueError):
        return jsonify({"error": "cost_usd must be a number"}), 400
    if cost_usd < 0:
        return jsonify({"error": "cost_usd must be non-negative"}), 400

    tenant = getattr(request, "tenant_id", "")
    session = gate.get_session(session_id, tenant_id=tenant)
    if not session:
        return jsonify({"error": "Invalid or expired session"}), 401

    entry = watch.log_action(
        session, tool=tool, action=action,
        details=data.get("details"),
        cost_usd=cost_usd,
        tenant_id=tenant,
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
    tenant = getattr(request, "tenant_id", "")
    entries = watch.get_audit_trail(
        session_id=request.args.get("session_id"),
        agent_id=request.args.get("agent_id"),
        tool=request.args.get("tool"),
        flagged_only=request.args.get("flagged") == "true",
        limit=int(request.args.get("limit", 100)),
        tenant_id=tenant,
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
                "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash,
            }
            for e in entries
        ],
    })


@app.route("/v1/audit/spend", methods=["GET"])
@require_api_key
def get_spend():
    tenant = getattr(request, "tenant_id", "")
    return jsonify(watch.get_spend(
        session_id=request.args.get("session_id"),
        agent_id=request.args.get("agent_id"),
        tenant_id=tenant,
    ))


@app.route("/v1/audit/verify", methods=["GET"])
@require_api_key
def verify_audit_chain():
    """Verify the cryptographic integrity of the audit log hash chain."""
    tenant = getattr(request, "tenant_id", "")
    result = watch.verify_chain(tenant_id=tenant)
    return jsonify(result)


# ── Usage tracking (for billing) ──

@app.after_request
def track_usage(response):
    """Track API usage per tenant for billing."""
    if request.path.startswith("/v1/") and hasattr(request, "tenant_id"):
        tenant = request.tenant_id
        month = time.strftime("%Y-%m")
        try:
            conn = get_db(DB_PATH)
            conn.execute(
                "INSERT INTO usage (tenant_id, month, action_count) VALUES (?, ?, 1) "
                "ON CONFLICT(tenant_id, month) DO UPDATE SET action_count = action_count + 1",
                (tenant, month)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[!] Usage tracking failed for tenant {tenant}: {e}")
    return response


@app.route("/v1/usage", methods=["GET"])
@require_api_key
def get_usage():
    """Get usage stats for billing."""
    tenant = getattr(request, "tenant_id", "")
    month = request.args.get("month", time.strftime("%Y-%m"))
    conn = get_db(DB_PATH)
    row = conn.execute(
        "SELECT * FROM usage WHERE tenant_id = ? AND month = ?",
        (tenant, month)
    ).fetchone()
    conn.close()
    if row:
        return jsonify({
            "tenant_id": tenant,
            "month": month,
            "action_count": row["action_count"],
            "tier": getattr(request, "api_key_tier", "free"),
        })
    return jsonify({"tenant_id": tenant, "month": month, "action_count": 0})


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
    tenant = getattr(request, "tenant_id", "")
    session = gate.get_session(session_id, tenant_id=tenant)
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
    if request.path.startswith("/v1/") and request.path not in ("/v1/keys", "/v1/demo/key"):
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

        # Look up tier and tenant from DB (runs before @require_api_key)
        conn = get_db(DB_PATH)
        row = conn.execute("SELECT tenant_id, tier FROM api_keys WHERE key_hash = ? AND revoked = 0", (key_hash,)).fetchone()
        conn.close()
        if not row:
            return  # Let @require_api_key handle invalid keys

        tier = row["tier"]
        tenant = row["tenant_id"]

        # Check subscription tier (may override key tier)
        billing_tier = _get_tenant_tier(tenant)
        effective_tier = billing_tier if billing_tier != "free" else tier

        limit = RATE_LIMITS.get(effective_tier, 100)
        if entry["count"] > limit:
            return jsonify({
                "error": "Rate limit exceeded",
                "limit": limit,
                "tier": effective_tier,
                "retry_after": int(entry["start"] + window - now),
            }), 429

        if tenant:
            tier_limits = TIER_LIMITS.get(effective_tier, TIER_LIMITS["free"])
            monthly_actions = _get_tenant_monthly_actions(tenant)
            if monthly_actions >= tier_limits["actions_per_month"]:
                return jsonify({
                    "error": "Monthly action quota exceeded",
                    "tier": billing_tier,
                    "limit": tier_limits["actions_per_month"],
                    "used": monthly_actions,
                    "upgrade": "https://haldir.xyz/pricing",
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
        "name": "createSession",
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
        "name": "getSession",
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
        "name": "revokeSession",
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
        "name": "checkPermission",
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
        "name": "storeSecret",
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
        "name": "getSecret",
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
        "name": "authorizePayment",
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
        "name": "logAction",
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
        "name": "getAuditTrail",
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
        "name": "getSpend",
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
    tenant = getattr(request, "tenant_id", "")

    # -- Gate --
    if name == "createSession":
        agent_id = arguments.get("agent_id")
        if not agent_id:
            return {"isError": True, "content": [{"type": "text", "text": "agent_id is required"}]}
        scopes = arguments.get("scopes", ["read", "browse"])
        ttl = arguments.get("ttl", 3600)
        spend_limit = arguments.get("spend_limit")
        gate.register_agent(agent_id, default_scopes=scopes, tenant_id=tenant)
        session = gate.create_session(agent_id, scopes=scopes, ttl=ttl, spend_limit=spend_limit, tenant_id=tenant)
        return {"content": [{"type": "text", "text": json.dumps({
            "session_id": session.session_id,
            "agent_id": session.agent_id,
            "scopes": session.scopes,
            "spend_limit": session.spend_limit,
            "expires_at": session.expires_at,
            "ttl": ttl,
        })}]}

    if name == "getSession":
        session = gate.get_session(arguments.get("session_id", ""), tenant_id=tenant)
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

    if name == "revokeSession":
        sid = arguments.get("session_id", "")
        revoked = gate.revoke_session(sid, tenant_id=tenant)
        if not revoked:
            return {"isError": True, "content": [{"type": "text", "text": "Session not found"}]}
        return {"content": [{"type": "text", "text": json.dumps({"revoked": True, "session_id": sid})}]}

    if name == "checkPermission":
        sid = arguments.get("session_id", "")
        scope = arguments.get("scope", "")
        if not scope:
            return {"isError": True, "content": [{"type": "text", "text": "scope is required"}]}
        allowed = gate.check_permission(sid, scope, tenant_id=tenant)
        return {"content": [{"type": "text", "text": json.dumps({"allowed": allowed, "session_id": sid, "scope": scope})}]}

    # -- Vault --
    if name == "storeSecret":
        sname = arguments.get("name", "")
        value = arguments.get("value", "")
        if not sname or not value:
            return {"isError": True, "content": [{"type": "text", "text": "name and value are required"}]}
        scope_req = arguments.get("scope_required", "read")
        vault.store_secret(sname, value, scope_required=scope_req, tenant_id=tenant)
        return {"content": [{"type": "text", "text": json.dumps({"stored": True, "name": sname})}]}

    if name == "getSecret":
        sname = arguments.get("name", "")
        session_id = arguments.get("session_id")
        if not session_id:
            return {"isError": True, "content": [{"type": "text", "text": "session_id is required to access secrets"}]}
        session = gate.get_session(session_id, tenant_id=tenant)
        if not session:
            return {"isError": True, "content": [{"type": "text", "text": "Invalid or expired session"}]}
        try:
            value = vault.get_secret(sname, session=session, tenant_id=tenant)
        except PermissionError as e:
            return {"isError": True, "content": [{"type": "text", "text": str(e)}]}
        if value is None:
            return {"isError": True, "content": [{"type": "text", "text": f"Secret '{sname}' not found"}]}
        return {"content": [{"type": "text", "text": json.dumps({"name": sname, "value": value})}]}

    if name == "authorizePayment":
        sid = arguments.get("session_id", "")
        amount = arguments.get("amount")
        if not sid or amount is None:
            return {"isError": True, "content": [{"type": "text", "text": "session_id and amount are required"}]}
        session = gate.get_session(sid, tenant_id=tenant)
        if not session:
            return {"isError": True, "content": [{"type": "text", "text": "Invalid or expired session"}]}
        result = vault.authorize_payment(
            session, float(amount),
            currency=arguments.get("currency", "USD"),
            description=arguments.get("description", ""),
        )
        return {"content": [{"type": "text", "text": json.dumps(result)}]}

    # -- Watch --
    if name == "logAction":
        sid = arguments.get("session_id", "")
        action = arguments.get("action", "")
        if not sid or not action:
            return {"isError": True, "content": [{"type": "text", "text": "session_id and action are required"}]}
        session = gate.get_session(sid, tenant_id=tenant)
        if not session:
            return {"isError": True, "content": [{"type": "text", "text": "Invalid or expired session"}]}
        entry = watch.log_action(
            session, tool=arguments.get("tool", ""), action=action,
            details=arguments.get("details"),
            cost_usd=float(arguments.get("cost_usd", 0)),
            tenant_id=tenant,
        )
        return {"content": [{"type": "text", "text": json.dumps({
            "logged": True, "entry_id": entry.entry_id,
            "flagged": entry.flagged, "flag_reason": entry.flag_reason,
        })}]}

    if name == "getAuditTrail":
        entries = watch.get_audit_trail(
            session_id=arguments.get("session_id"),
            agent_id=arguments.get("agent_id"),
            tool=arguments.get("tool"),
            flagged_only=arguments.get("flagged_only", False),
            limit=int(arguments.get("limit", 100)),
            tenant_id=tenant,
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

    if name == "getSpend":
        return {"content": [{"type": "text", "text": json.dumps(watch.get_spend(
            session_id=arguments.get("session_id"),
            agent_id=arguments.get("agent_id"),
            tenant_id=tenant,
        ))}]}

    return {"isError": True, "content": [{"type": "text", "text": f"Unknown tool: {name}"}]}


@app.route("/mcp", methods=["POST"])
@require_api_key
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


@app.route("/.well-known/mcp/mcp.json")
def mcp_discovery():
    """Lightweight MCP discovery metadata."""
    mcp_dir = os.path.join(os.path.dirname(__file__), ".well-known", "mcp")
    path = os.path.join(mcp_dir, "mcp.json")
    if os.path.exists(path):
        with open(path) as f:
            return jsonify(json.load(f))
    return jsonify({"error": "not found"}), 404


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
        "license": "MIT",
        "tags": [
            "security", "governance", "ai-agents", "permissions", "audit",
            "secrets", "budget", "compliance", "least-privilege", "mcp",
        ],
    })


# ── Proxy Mode ──

from haldir_gate.proxy import HaldirProxy

proxy = HaldirProxy(
    gate=gate, vault=vault, watch=watch,
    approval_engine=approval_engine,
    webhook_mgr=webhook_mgr,
    db_path=DB_PATH,
)


@app.route("/v1/proxy/upstreams", methods=["POST"])
@require_api_key
def register_upstream():
    """Register an upstream MCP server to proxy through Haldir."""
    data = request.json or {}
    name = data.get("name")
    url = data.get("url")
    if not name or not url:
        return jsonify({"error": "name and url are required"}), 400
    server = proxy.register_upstream(name, url)
    resp = {
        "registered": True,
        "name": name,
        "url": url,
        "healthy": server.healthy,
        "tools_discovered": len(server.tools),
        "tool_names": [t["name"] for t in server.tools],
    }
    if hasattr(server, '_last_error'):
        resp["error"] = server._last_error
    if hasattr(server, '_raw_status'):
        resp["upstream_status"] = server._raw_status
    if hasattr(server, '_raw_body'):
        resp["upstream_body"] = server._raw_body[:300]
    return jsonify(resp), 201


@app.route("/v1/proxy/upstreams", methods=["GET"])
@require_api_key
def list_upstreams():
    """List all registered upstream servers and their status."""
    return jsonify(proxy.get_stats())


@app.route("/v1/proxy/tools", methods=["GET"])
@require_api_key
def proxy_tools():
    """List all tools available through the proxy (from all upstreams)."""
    tools = proxy.get_tools()
    return jsonify({
        "count": len(tools),
        "tools": [{"name": t["name"], "description": t.get("description", ""),
                    "upstream": t.get("_haldir", {}).get("upstream", "")}
                   for t in tools],
    })


@app.route("/v1/proxy/call", methods=["POST"])
@require_api_key
def proxy_call():
    """
    Call a tool through the Haldir proxy.

    Every call is intercepted: session validated, permissions checked,
    policies enforced, approval verified, then forwarded to the upstream
    MCP server. The call is logged to the audit trail.
    """
    data = request.json or {}
    tool_name = data.get("tool")
    arguments = data.get("arguments", {})
    session_id = data.get("session_id")

    if not tool_name:
        return jsonify({"error": "tool is required"}), 400
    if not session_id:
        return jsonify({"error": "session_id is required"}), 400

    tenant = getattr(request, "tenant_id", "")
    session = gate.get_session(session_id, tenant_id=tenant)
    if not session:
        return jsonify({"error": "Invalid or expired session"}), 401

    result = proxy.call_tool(tool_name, arguments, session=session)
    status = 403 if result.get("isError") else 200
    return jsonify(result), status


@app.route("/v1/proxy/policies", methods=["POST"])
@require_api_key
def add_proxy_policy():
    """
    Add a governance policy to the proxy.

    Types:
    - block_tool: {"type": "block_tool", "tool": "dangerous_tool"}
    - allow_list: {"type": "allow_list", "tools": ["safe_tool_1", "safe_tool_2"]}
    - deny_list: {"type": "deny_list", "tools": ["blocked_1", "blocked_2"]}
    - spend_limit: {"type": "spend_limit", "max": 100.0}
    - rate_limit: {"type": "rate_limit", "max_per_minute": 30}
    - time_window: {"type": "time_window", "start_hour": 9, "end_hour": 17}
    """
    data = request.json or {}
    ptype = data.get("type")
    if not ptype:
        return jsonify({"error": "type is required"}), 400
    proxy.add_policy(**data)
    return jsonify({"added": True, "type": ptype}), 201


@app.route("/v1/proxy/policies", methods=["GET"])
@require_api_key
def list_proxy_policies():
    return jsonify({"policies": proxy._policies, "count": len(proxy._policies)})


# ── Metrics (founder view) ──

@app.route("/v1/metrics")
@require_api_key
def metrics():
    """Full platform metrics — users, sessions, actions, spend, secrets, upstreams."""
    conn = get_db(DB_PATH)
    m = {}

    # API keys (users)
    m["total_api_keys"] = conn.execute("SELECT COUNT(*) FROM api_keys WHERE revoked = 0").fetchone()[0]

    # Sessions
    m["total_sessions"] = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    m["active_sessions"] = conn.execute("SELECT COUNT(*) FROM sessions WHERE revoked = 0 AND (expires_at = 0 OR expires_at > ?)", (time.time(),)).fetchone()[0]

    # Unique agents
    m["unique_agents"] = conn.execute("SELECT COUNT(DISTINCT agent_id) FROM sessions").fetchone()[0]

    # Audit
    m["total_actions"] = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    m["flagged_actions"] = conn.execute("SELECT COUNT(*) FROM audit_log WHERE flagged = 1").fetchone()[0]
    m["actions_today"] = conn.execute("SELECT COUNT(*) FROM audit_log WHERE timestamp > ?", (time.time() - 86400,)).fetchone()[0]

    # Spend
    row = conn.execute("SELECT COALESCE(SUM(cost_usd), 0) as total FROM audit_log").fetchone()
    m["total_spend_usd"] = round(row["total"], 2)

    # Secrets
    m["total_secrets"] = conn.execute("SELECT COUNT(*) FROM secrets").fetchone()[0]

    # Payments
    m["total_payments"] = conn.execute("SELECT COUNT(*) FROM payments").fetchone()[0]
    row = conn.execute("SELECT COALESCE(SUM(amount), 0) as total FROM payments").fetchone()
    m["total_payment_volume_usd"] = round(row["total"], 2)

    # Approvals
    try:
        m["pending_approvals"] = conn.execute("SELECT COUNT(*) FROM approval_requests WHERE status = 'pending'").fetchone()[0]
        m["total_approvals"] = conn.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0]
    except Exception:
        m["pending_approvals"] = 0
        m["total_approvals"] = 0

    # Top tools
    rows = conn.execute("SELECT tool, COUNT(*) as cnt FROM audit_log GROUP BY tool ORDER BY cnt DESC LIMIT 10").fetchall()
    m["top_tools"] = {r["tool"]: r["cnt"] for r in rows}

    # Top agents
    rows = conn.execute("SELECT agent_id, COUNT(*) as cnt FROM audit_log GROUP BY agent_id ORDER BY cnt DESC LIMIT 10").fetchall()
    m["top_agents"] = {r["agent_id"]: r["cnt"] for r in rows}

    # Usage this month
    month = time.strftime("%Y-%m")
    rows = conn.execute("SELECT tenant_id, action_count FROM usage WHERE month = ? ORDER BY action_count DESC LIMIT 10", (month,)).fetchall()
    m["usage_this_month"] = {r["tenant_id"][:8]: r["action_count"] for r in rows}

    conn.close()
    return jsonify(m)


# ── Quickstart ──

@app.route("/quickstart")
def quickstart_page():
    qs_path = os.path.join(os.path.dirname(__file__), "quickstart.html")
    if os.path.exists(qs_path):
        with open(qs_path) as f:
            return f.read(), 200, {"Content-Type": "text/html"}
    return redirect("/docs")


# ── Billing (Stripe) ──

@app.route("/pricing")
def pricing_page():
    """Pricing page — temporarily hidden while iterating on tiers."""
    return redirect("/", code=302)


def _pricing_page_html():
    """Archived pricing page HTML. Re-enable by returning this from pricing_page()."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pricing — Haldir</title>
<meta name="description" content="Simple usage-based pricing for AI agent security. Free tier included.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500&family=Inter:wght@200;300;400;600&display=swap" rel="stylesheet">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
:root {
    --gold: #b8973a;
    --gold-soft: rgba(184,151,58,0.5);
    --gold-glow: rgba(184,151,58,0.08);
    --w: #e0ddd5;
    --w80: rgba(224,221,213,0.8);
    --w50: rgba(224,221,213,0.5);
    --w20: rgba(224,221,213,0.2);
    --w08: rgba(224,221,213,0.08);
    --w04: rgba(224,221,213,0.04);
    --bg: #050505;
    --mono: 'IBM Plex Mono', monospace;
    --sans: 'Inter', -apple-system, sans-serif;
}
html { scroll-behavior: smooth; }
body { background: var(--bg); color: var(--w); font-family: var(--sans); overflow-x: hidden; }

/* Nav */
nav {
    display: flex; justify-content: space-between; align-items: center;
    padding: 1.5rem 3rem; border-bottom: 1px solid var(--w08);
}
.logo {
    font-family: var(--mono); font-size: 0.8rem; font-weight: 400;
    letter-spacing: 4px; text-transform: uppercase;
    color: var(--w); text-decoration: none;
}
.nav-r { display: flex; gap: 2.5rem; align-items: center; }
.nav-r a {
    font-family: var(--mono); font-size: 0.65rem; font-weight: 300;
    letter-spacing: 2px; text-transform: uppercase;
    color: var(--w50); text-decoration: none; transition: color 0.3s;
}
.nav-r a:hover { color: var(--w); }

/* Hero */
.pricing-hero {
    text-align: center; padding: 6rem 2rem 3rem;
    position: relative;
}
.pricing-hero::before {
    content: ''; position: absolute; top: 30%; left: 50%;
    width: 500px; height: 500px; transform: translate(-50%, -50%);
    background: radial-gradient(circle, var(--gold-glow) 0%, transparent 70%);
    pointer-events: none;
}
.pricing-hero h1 {
    font-weight: 200; font-size: clamp(2rem, 4vw, 3rem);
    letter-spacing: -1px; margin-bottom: 1rem;
}
.pricing-hero h1 em { font-style: normal; color: var(--gold); }
.pricing-hero p {
    font-size: 0.9rem; font-weight: 300; color: var(--w50);
    max-width: 450px; margin: 0 auto; line-height: 1.8;
}

/* Pricing grid */
.pricing-grid {
    display: grid; grid-template-columns: repeat(3, 1fr);
    gap: 1px; max-width: 960px; margin: 0 auto 4rem;
    padding: 0 2rem;
    background: var(--w08); border: 1px solid var(--w08);
}
.tier-card {
    background: var(--bg); padding: 3rem 2.5rem;
    display: flex; flex-direction: column; position: relative;
}
.tier-card.featured {
    background: rgba(184,151,58,0.03);
    border-top: 2px solid var(--gold);
}
.tier-badge {
    position: absolute; top: 1rem; right: 1.5rem;
    font-family: var(--mono); font-size: 0.55rem; font-weight: 400;
    letter-spacing: 2px; text-transform: uppercase;
    color: var(--gold); background: rgba(184,151,58,0.1);
    padding: 0.25rem 0.6rem; border-radius: 3px;
}
.current-badge {
    position: absolute; top: 1rem; right: 1.5rem;
    font-family: var(--mono); font-size: 0.55rem; font-weight: 400;
    letter-spacing: 2px; text-transform: uppercase;
    color: #6bbd6b; background: rgba(107,189,107,0.1);
    padding: 0.25rem 0.6rem; border-radius: 3px;
}
.tier-name {
    font-family: var(--mono); font-size: 0.65rem; font-weight: 400;
    letter-spacing: 3px; text-transform: uppercase;
    color: var(--w50); margin-bottom: 1.5rem;
}
.tier-price {
    font-weight: 200; font-size: 2.5rem; letter-spacing: -1px;
    margin-bottom: 0.25rem;
}
.tier-price span { font-size: 0.9rem; font-weight: 300; color: var(--w50); }
.tier-desc {
    font-size: 0.8rem; color: var(--w50); line-height: 1.7;
    margin-bottom: 2rem; min-height: 2.5rem;
}
.tier-features {
    list-style: none; margin-bottom: 2.5rem; flex: 1;
}
.tier-features li {
    font-family: var(--mono); font-size: 0.75rem; color: var(--w50);
    padding: 0.5rem 0; border-bottom: 1px solid var(--w08);
    display: flex; align-items: center; gap: 0.6rem;
}
.tier-features li::before {
    content: ''; display: inline-block; width: 4px; height: 4px;
    background: var(--gold); border-radius: 50%; flex-shrink: 0;
}
.tier-btn {
    display: block; text-align: center;
    font-family: var(--mono); font-size: 0.65rem; font-weight: 400;
    letter-spacing: 2px; text-transform: uppercase;
    padding: 0.85rem 2rem; text-decoration: none;
    transition: all 0.3s; cursor: pointer; border: none; width: 100%;
}
.tier-btn-outline {
    background: transparent; color: var(--w50);
    border: 1px solid var(--w20);
}
.tier-btn-outline:hover { color: var(--w); border-color: var(--w50); }
.tier-btn-gold {
    background: var(--gold); color: var(--bg);
}
.tier-btn-gold:hover { background: #cca842; }
.tier-btn-white {
    background: var(--w); color: var(--bg);
}
.tier-btn-white:hover { background: var(--w80); }

/* FAQ */
.faq {
    max-width: 640px; margin: 0 auto 6rem; padding: 0 2rem;
}
.faq h2 {
    font-weight: 200; font-size: 1.5rem; margin-bottom: 2rem;
    text-align: center;
}
.faq-item {
    border-bottom: 1px solid var(--w08); padding: 1.25rem 0;
}
.faq-q {
    font-size: 0.85rem; font-weight: 400; margin-bottom: 0.5rem;
}
.faq-a {
    font-size: 0.8rem; font-weight: 300; color: var(--w50); line-height: 1.7;
}

/* Footer */
footer {
    border-top: 1px solid var(--w08);
    padding: 2rem 3rem; text-align: center;
    font-family: var(--mono); font-size: 0.65rem;
    color: var(--w20); letter-spacing: 1px;
}
footer a { color: var(--gold); text-decoration: none; }

/* Responsive */
@media (max-width: 768px) {
    nav { padding: 1rem 1.5rem; }
    .pricing-grid { grid-template-columns: 1fr; padding: 0 1rem; }
    .pricing-hero { padding: 4rem 1.5rem 2rem; }
}
</style>
</head>
<body>

<nav>
    <a href="/" class="logo">Haldir</a>
    <div class="nav-r">
        <a href="/quickstart">Quickstart</a>
        <a href="/docs">Docs</a>
        <a href="/blog">Blog</a>
        <a href="/dashboard">Dashboard</a>
    </div>
</nav>

<div class="pricing-hero">
    <h1>Simple, <em>usage-based</em> pricing</h1>
    <p>Start free. Scale when your agents do. No surprises.</p>
</div>

<div class="pricing-grid">
    <!-- Free -->
    <div class="tier-card">
        <span class="current-badge">Current: Free</span>
        <div class="tier-name">Free</div>
        <div class="tier-price">$0 <span>/ forever</span></div>
        <div class="tier-desc">Get started. One agent, full security.</div>
        <ul class="tier-features">
            <li>1 agent</li>
            <li>1,000 actions / month</li>
            <li>Session-scoped permissions</li>
            <li>Encrypted secret storage</li>
            <li>Audit trail</li>
            <li>MCP support</li>
            <li>Community support</li>
        </ul>
        <a href="/docs" class="tier-btn tier-btn-outline">Get Started</a>
    </div>

    <!-- Pro -->
    <div class="tier-card featured">
        <span class="tier-badge">Most Popular</span>
        <div class="tier-name">Pro</div>
        <div class="tier-price">$49 <span>/ month</span></div>
        <div class="tier-desc">For teams running multiple agents in production.</div>
        <ul class="tier-features">
            <li>10 agents</li>
            <li>50,000 actions / month</li>
            <li>Everything in Free</li>
            <li>Anomaly detection</li>
            <li>Webhooks (Slack, Discord)</li>
            <li>Human-in-the-loop approvals</li>
            <li>Proxy mode + governance policies</li>
            <li>Priority support</li>
        </ul>
        <button onclick="checkout('pro')" class="tier-btn tier-btn-gold">Upgrade to Pro</button>
    </div>

    <!-- Enterprise -->
    <div class="tier-card">
        <div class="tier-name">Enterprise</div>
        <div class="tier-price">$499 <span>/ month</span></div>
        <div class="tier-desc">Unlimited scale. Full control. Dedicated support.</div>
        <ul class="tier-features">
            <li>Unlimited agents</li>
            <li>Unlimited actions</li>
            <li>Everything in Pro</li>
            <li>SSO / SAML (coming soon)</li>
            <li>Custom policy engine</li>
            <li>Dedicated infrastructure</li>
            <li>SLA guarantee</li>
            <li>Dedicated Slack channel</li>
        </ul>
        <button onclick="checkout('enterprise')" class="tier-btn tier-btn-white">Upgrade to Enterprise</button>
    </div>
</div>

<div class="faq">
    <h2>Questions</h2>
    <div class="faq-item">
        <div class="faq-q">What counts as an action?</div>
        <div class="faq-a">Every API call to /v1/* counts as one action. Creating sessions, checking permissions, storing secrets, logging audit entries — each is one action.</div>
    </div>
    <div class="faq-item">
        <div class="faq-q">What happens if I exceed my limit?</div>
        <div class="faq-a">API calls return a 429 with a clear message and a link to upgrade. No data is lost, no sessions are terminated. You just can't make new calls until the next month or you upgrade.</div>
    </div>
    <div class="faq-item">
        <div class="faq-q">Can I change plans anytime?</div>
        <div class="faq-a">Yes. Upgrade instantly, downgrade at end of billing period. Managed through the Stripe customer portal — no emails, no sales calls.</div>
    </div>
    <div class="faq-item">
        <div class="faq-q">Do you offer annual billing?</div>
        <div class="faq-a">Not yet, but it's coming. Contact us if you want to lock in a discount today.</div>
    </div>
    <div class="faq-item">
        <div class="faq-q">Is there a self-hosted option?</div>
        <div class="faq-a">Haldir is MIT licensed. You can self-host for free. The paid tiers are for the managed cloud service at haldir.xyz.</div>
    </div>
</div>

<footer>&copy; 2026 Haldir &middot; <a href="https://haldir.xyz">haldir.xyz</a></footer>

<script>
function checkout(tier) {
    const apiKey = prompt('Enter your Haldir API key (hld_...) to upgrade.\\n\\nDon\\'t have one yet? Get one free at haldir.xyz/quickstart');
    if (!apiKey) return;
    fetch('/v1/billing/checkout', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + apiKey,
        },
        body: JSON.stringify({ tier: tier }),
    })
    .then(r => r.json())
    .then(data => {
        if (data.url) {
            window.location.href = data.url;
        } else {
            alert(data.error || 'Something went wrong');
        }
    })
    .catch(() => alert('Network error — check your API key and try again'));
}
</script>
</body>
</html>""", 200, {"Content-Type": "text/html"}


@app.route("/v1/billing/checkout", methods=["POST"])
@require_api_key
def billing_checkout():
    """Create a Stripe Checkout session for Pro or Enterprise."""
    if not STRIPE_SECRET_KEY:
        return jsonify({"error": "Billing not configured — STRIPE_SECRET_KEY not set"}), 503

    import stripe
    stripe.api_key = STRIPE_SECRET_KEY

    data = request.json or {}
    tier = data.get("tier", "pro")
    tenant = getattr(request, "tenant_id", "")

    price_id = STRIPE_PRICE_PRO if tier == "pro" else STRIPE_PRICE_ENTERPRISE
    if not price_id:
        return jsonify({"error": f"No Stripe price configured for tier '{tier}'"}), 400

    # Reuse existing Stripe customer if one exists
    conn = get_db(DB_PATH)
    row = conn.execute("SELECT stripe_customer_id FROM subscriptions WHERE tenant_id = ?", (tenant,)).fetchone()
    conn.close()
    customer_id = row["stripe_customer_id"] if row and row["stripe_customer_id"] else None

    try:
        checkout_params = {
            "mode": "subscription",
            "line_items": [{"price": price_id, "quantity": 1}],
            "success_url": "https://haldir.xyz/pricing?session_id={CHECKOUT_SESSION_ID}&status=success",
            "cancel_url": "https://haldir.xyz/pricing?status=cancelled",
            "metadata": {"tenant_id": tenant, "tier": tier},
        }
        if customer_id:
            checkout_params["customer"] = customer_id
        # Subscription mode auto-creates customer; no customer_creation param needed

        session = stripe.checkout.Session.create(**checkout_params)
        return jsonify({"url": session.url, "session_id": session.id})
    except stripe.StripeError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/v1/billing/webhook", methods=["POST"])
def billing_webhook():
    """Handle Stripe webhook events for subscription lifecycle."""
    if not STRIPE_SECRET_KEY or not STRIPE_WEBHOOK_SECRET:
        return jsonify({"error": "Billing webhooks not configured"}), 503

    import stripe
    stripe.api_key = STRIPE_SECRET_KEY

    payload = request.get_data(as_text=True)
    sig = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.SignatureVerificationError):
        return jsonify({"error": "Invalid webhook signature"}), 400

    etype = event["type"]
    obj = event["data"]["object"]

    if etype == "checkout.session.completed":
        tenant_id = obj.get("metadata", {}).get("tenant_id", "")
        tier = obj.get("metadata", {}).get("tier", "pro")
        customer_id = obj.get("customer", "")
        subscription_id = obj.get("subscription", "")

        if tenant_id:
            now = time.time()
            conn = get_db(DB_PATH)
            # Upsert subscription record
            conn.execute(
                "INSERT INTO subscriptions (tenant_id, stripe_customer_id, stripe_subscription_id, tier, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'active', ?, ?) "
                "ON CONFLICT(tenant_id) DO UPDATE SET "
                "stripe_customer_id = ?, stripe_subscription_id = ?, tier = ?, status = 'active', updated_at = ?",
                (tenant_id, customer_id, subscription_id, tier, now, now,
                 customer_id, subscription_id, tier, now)
            )
            # Also update the api_keys tier
            conn.execute(
                "UPDATE api_keys SET tier = ? WHERE tenant_id = ?",
                (tier, tenant_id)
            )
            conn.commit()
            conn.close()

    elif etype == "invoice.payment_succeeded":
        subscription_id = obj.get("subscription", "")
        period_end = obj.get("lines", {}).get("data", [{}])[0].get("period", {}).get("end", 0)
        if subscription_id:
            conn = get_db(DB_PATH)
            conn.execute(
                "UPDATE subscriptions SET status = 'active', current_period_end = ?, updated_at = ? "
                "WHERE stripe_subscription_id = ?",
                (period_end, time.time(), subscription_id)
            )
            conn.commit()
            conn.close()

    elif etype == "customer.subscription.deleted":
        subscription_id = obj.get("id", "")
        if subscription_id:
            conn = get_db(DB_PATH)
            # Downgrade to free
            conn.execute(
                "UPDATE subscriptions SET tier = 'free', status = 'cancelled', updated_at = ? "
                "WHERE stripe_subscription_id = ?",
                (time.time(), subscription_id)
            )
            # Also downgrade the api_keys tier
            row = conn.execute(
                "SELECT tenant_id FROM subscriptions WHERE stripe_subscription_id = ?",
                (subscription_id,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE api_keys SET tier = 'free' WHERE tenant_id = ?",
                    (row["tenant_id"],)
                )
            conn.commit()
            conn.close()

    return jsonify({"received": True}), 200


@app.route("/v1/billing/portal", methods=["GET"])
@require_api_key
def billing_portal():
    """Return a Stripe Customer Portal URL for managing subscription."""
    if not STRIPE_SECRET_KEY:
        return jsonify({"error": "Billing not configured — STRIPE_SECRET_KEY not set"}), 503

    import stripe
    stripe.api_key = STRIPE_SECRET_KEY

    tenant = getattr(request, "tenant_id", "")
    conn = get_db(DB_PATH)
    row = conn.execute("SELECT stripe_customer_id FROM subscriptions WHERE tenant_id = ?", (tenant,)).fetchone()
    conn.close()

    if not row or not row["stripe_customer_id"]:
        return jsonify({"error": "No billing account found. Subscribe first at /pricing"}), 404

    try:
        portal = stripe.billing_portal.Session.create(
            customer=row["stripe_customer_id"],
            return_url="https://haldir.xyz/pricing",
        )
        return jsonify({"url": portal.url})
    except stripe.StripeError as e:
        return jsonify({"error": str(e)}), 400


# ── Dashboard ──

@app.route("/dashboard")
def dashboard():
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    with open(dashboard_path) as f:
        return f.read(), 200, {"Content-Type": "text/html"}


# ── Blog ──

@app.route("/blog")
@app.route("/blog/")
def blog_index():
    blog_dir = os.path.join(os.path.dirname(__file__), "blog")
    if not os.path.isdir(blog_dir):
        return "Coming soon", 200
    posts = []
    for f in sorted(os.listdir(blog_dir)):
        if f.endswith(".md") and f != "index.md":
            path = os.path.join(blog_dir, f)
            with open(path) as fh:
                first_line = fh.readline().strip().lstrip("# ")
            slug = f.replace(".md", "")
            posts.append({"title": first_line, "slug": slug})
    html = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Haldir Blog</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500&family=Inter:wght@200;300;400;600&display=swap" rel="stylesheet">
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#050505;color:#e0ddd5;font-family:'Inter',sans-serif;padding:3rem;max-width:700px;margin:0 auto}
h1{font-weight:200;font-size:2rem;margin-bottom:2rem}a{color:#b8973a;text-decoration:none}a:hover{text-decoration:underline}
.post{padding:1rem 0;border-bottom:1px solid rgba(224,221,213,0.08)}.post a{font-size:1.1rem;font-weight:400}</style></head><body>
<h1><a href="/" style="color:#e0ddd5">Haldir</a> / Blog</h1>"""
    for p in posts:
        html += f'<div class="post"><a href="/blog/{p["slug"]}">{p["title"]}</a></div>'
    html += "</body></html>"
    return html, 200, {"Content-Type": "text/html"}


@app.route("/blog/<slug>")
def blog_post(slug):
    import re as _re
    if not _re.match(r'^[a-zA-Z0-9_-]+$', slug):
        return "Not found", 404
    blog_dir = os.path.join(os.path.dirname(__file__), "blog")
    path = os.path.join(blog_dir, f"{slug}.md")
    if not os.path.exists(path):
        return "Not found", 404
    with open(path) as f:
        content = f.read()
    # Simple markdown to HTML (headers, code blocks, paragraphs)
    import re
    lines = content.split("\n")
    html_lines = []
    in_code = False
    for line in lines:
        if line.startswith("```"):
            if in_code:
                html_lines.append("</pre>")
                in_code = False
            else:
                lang = line[3:].strip()
                html_lines.append(f'<pre style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:6px;padding:1.25rem;overflow-x:auto;font-size:0.8rem;line-height:1.8;color:rgba(224,221,213,0.6);margin:1rem 0">')
                in_code = True
            continue
        if in_code:
            html_lines.append(line)
            continue
        if line.startswith("# "):
            html_lines.append(f'<h1 style="font-weight:200;font-size:2rem;margin:1rem 0">{line[2:]}</h1>')
        elif line.startswith("## "):
            html_lines.append(f'<h2 style="font-weight:400;font-size:1.2rem;margin:2rem 0 0.5rem;color:#b8973a">{line[3:]}</h2>')
        elif line.startswith("### "):
            html_lines.append(f'<h3 style="font-weight:400;font-size:1rem;margin:1.5rem 0 0.5rem">{line[4:]}</h3>')
        elif line.startswith("- "):
            html_lines.append(f'<li style="margin:0.3rem 0 0.3rem 1.5rem;color:rgba(224,221,213,0.6);font-size:0.9rem;line-height:1.7">{line[2:]}</li>')
        elif line.strip():
            # Inline code
            line = re.sub(r'`([^`]+)`', r'<code style="background:rgba(255,255,255,0.05);padding:0.1rem 0.3rem;border-radius:3px;font-family:IBM Plex Mono,monospace;font-size:0.85em">\1</code>', line)
            # Bold
            line = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', line)
            # Links
            line = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', line)
            html_lines.append(f'<p style="margin:0.75rem 0;color:rgba(224,221,213,0.6);font-size:0.9rem;line-height:1.8">{line}</p>')
    body = "\n".join(html_lines)
    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{slug.replace('-',' ').title()} — Haldir</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500&family=Inter:wght@200;300;400;600&display=swap" rel="stylesheet">
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{background:#050505;color:#e0ddd5;font-family:'Inter',sans-serif;padding:3rem;max-width:700px;margin:0 auto}}
a{{color:#b8973a;text-decoration:none}}a:hover{{text-decoration:underline}}</style></head><body>
<p style="margin-bottom:2rem;font-size:0.8rem"><a href="/">Haldir</a> / <a href="/blog">Blog</a></p>
{body}
<p style="margin-top:3rem;padding-top:1rem;border-top:1px solid rgba(255,255,255,0.08);font-size:0.8rem;color:rgba(224,221,213,0.3)">&copy; 2026 Haldir &middot; <a href="https://haldir.xyz">haldir.xyz</a></p>
</body></html>"""
    return page, 200, {"Content-Type": "text/html"}


# ── Agent discovery files ──

@app.route("/llms.txt")
def llms_txt():
    p = os.path.join(os.path.dirname(__file__), "llms.txt")
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/robots.txt")
def robots_txt():
    p = os.path.join(os.path.dirname(__file__), "robots.txt")
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/.well-known/security.txt")
def security_txt():
    p = os.path.join(os.path.dirname(__file__), ".well-known", "security.txt")
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/.well-known/ai-plugin.json")
def ai_plugin():
    p = os.path.join(os.path.dirname(__file__), "ai-plugin.json")
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "application/json"}


@app.route("/openapi.json")
def openapi_spec():
    p = os.path.join(os.path.dirname(__file__), "openapi.json")
    if os.path.exists(p):
        with open(p) as f:
            return f.read(), 200, {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}
    return jsonify({"error": "OpenAPI spec not yet generated"}), 404


@app.route("/icon.svg")
def icon_svg():
    return '''<svg viewBox="0 0 80 92" fill="none" xmlns="http://www.w3.org/2000/svg">
<defs><linearGradient id="sg" x1="40" y1="4" x2="40" y2="88" gradientUnits="userSpaceOnUse">
<stop offset="0%" stop-color="#e8c84a"/><stop offset="100%" stop-color="#8a6d1b"/></linearGradient></defs>
<path d="M40 4 L72 18 V46 C72 68 58 80 40 88 C22 80 8 68 8 46 V18 Z" fill="url(#sg)" opacity="0.15" stroke="url(#sg)" stroke-width="2"/>
<path d="M32 44 L38 50 L52 36" stroke="#c9a33e" stroke-width="4" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
</svg>''', 200, {"Content-Type": "image/svg+xml"}


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
