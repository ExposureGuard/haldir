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
