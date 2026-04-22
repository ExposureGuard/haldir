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
import uuid
import secrets
import hashlib
from functools import wraps

from flask import Flask, request, jsonify, abort, redirect, g, send_from_directory
from flask_cors import CORS

from haldir_db import init_db, get_db
from haldir_gate.gate import Gate
from haldir_vault.vault import Vault
from haldir_watch.watch import Watch
import haldir_idempotency
from haldir_logging import configure_logging, get_logger
from haldir_metrics import registry as prom_metrics
from haldir_validation import validate_body
from haldir_openapi import generate_openapi
from haldir_status import build_status
from haldir_scopes import require_scope

configure_logging()
log = get_logger("haldir.api")

# Platform metrics — declared once at module load, incremented in the
# before/after request hooks.
_M_REQUESTS = prom_metrics.counter(
    "haldir_http_requests_total",
    "Total HTTP requests the API has handled.",
    label_names=("method", "path", "status"),
)
_M_DURATION = prom_metrics.histogram(
    "haldir_http_request_duration_seconds",
    "HTTP request duration (seconds) per route.",
    label_names=("method", "path"),
)
_M_RL_HITS = prom_metrics.counter(
    "haldir_rate_limit_exceeded_total",
    "Requests rejected with 429 by the rate limiter.",
    label_names=("tier",),
)
_M_IDEM_HITS = prom_metrics.counter(
    "haldir_idempotency_hits_total",
    "POSTs short-circuited by a prior Idempotency-Key match.",
    label_names=("endpoint",),
)
_M_IDEM_MISMATCH = prom_metrics.counter(
    "haldir_idempotency_mismatches_total",
    "Idempotency-Key reused against a different body (422).",
    label_names=("endpoint",),
)

# ── App setup ──

DB_PATH = os.environ.get("HALDIR_DB_PATH", "/data/haldir.db" if os.path.isdir("/data") else "haldir.db")
ENCRYPTION_KEY = os.environ.get("HALDIR_ENCRYPTION_KEY", "").encode() or None

app = Flask(__name__)
# Reject bodies larger than 1 MiB. Every Haldir POST body is a small
# JSON document — sessions, secrets, policy rules — so there's no
# legitimate reason to accept more. Oversize bodies are cheap DoS fodder
# (memory-amplification, slow JSON parse). Flask returns 413 automatically
# when this is exceeded; our error handler converts it to JSON.
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
CORS(app, resources={r"/v1/*": {"origins": "*"}, r"/mcp": {"origins": "*"}})

# Init DB on startup. init_db() creates tables via the legacy
# CREATE TABLE IF NOT EXISTS path, which is safe to keep as a belt-
# and-suspenders — the migrations runner becomes canonical going
# forward, but init_db() remains a no-op safety net for any table
# that doesn't yet have a migration covering it.
init_db(DB_PATH)

# Schema migrations. Under HALDIR_AUTO_MIGRATE=1 we apply every
# pending migration at import time so each gunicorn cold start
# converges to the declared schema. Under the default (off) the
# operator runs `python -m haldir_migrate up` explicitly — useful
# when deploys want migrations in a dedicated job before traffic
# reaches the workers.
if os.environ.get("HALDIR_AUTO_MIGRATE") == "1":
    import haldir_migrate
    _mig_summary = haldir_migrate.apply_pending(DB_PATH)
    if _mig_summary["applied"] or _mig_summary["bootstrapped"]:
        log.info("schema migrations run at boot", extra={
            "applied":      _mig_summary["applied"],
            "bootstrapped": _mig_summary["bootstrapped"],
        })
    if _mig_summary["drift"]:
        log.warning("schema migration drift detected", extra={
            "drifted_versions": _mig_summary["drift"],
        })

# Idempotency schema — retry-safe POST handling for /v1/audit and
# /v1/payments/authorize. See haldir_idempotency.py.
_idem_conn = get_db(DB_PATH)
try:
    haldir_idempotency.init_schema(_idem_conn)
    _idem_conn.commit()
finally:
    _idem_conn.close()

# Init components
gate = Gate(db_path=DB_PATH)
vault = Vault(encryption_key=ENCRYPTION_KEY, db_path=DB_PATH)
watch = Watch(db_path=DB_PATH)

# Require encryption key in production
if not ENCRYPTION_KEY:
    log.warning(
        "no HALDIR_ENCRYPTION_KEY set — generated ephemeral key; secrets will be lost on restart",
    )


# ── Idempotency helpers ────────────────────────────────────────────────
#
# Every mutating POST endpoint accepts an optional `Idempotency-Key`
# header. When present, the two helpers below gate handler execution so
# a second POST with the same (tenant, key, endpoint, body) returns the
# original response rather than re-processing. See haldir_idempotency.py.
#
# Usage inside an endpoint:
#
#     @app.route("/v1/sessions", methods=["POST"])
#     def create_session():
#         data = request.json or {}
#         tenant = getattr(request, "tenant_id", "")
#         cached = _idempotency_lookup("/v1/sessions", data, tenant)
#         if cached is not None:
#             return cached
#         ...do the work...
#         _idempotency_store("/v1/sessions", data, tenant, response, status)
#         return jsonify(response), status

def _idempotency_lookup(endpoint: str, body: dict, tenant: str):
    """Return (jsonify_response, status) to short-circuit the handler, or
    None to proceed. Returns a 422 response if the caller reused a key
    with a different body."""
    idem_key = request.headers.get("Idempotency-Key")
    if not idem_key:
        return None
    conn = get_db(DB_PATH)
    try:
        try:
            hit = haldir_idempotency.lookup(
                conn, tenant, idem_key, endpoint, body,
            )
            if hit is not None:
                _M_IDEM_HITS.inc(endpoint=endpoint)
                return jsonify(hit.body), hit.status
        except haldir_idempotency.IdempotencyMismatch as e:
            _M_IDEM_MISMATCH.inc(endpoint=endpoint)
            return jsonify({"error": str(e)}), 422
    finally:
        conn.close()
    return None


def _idempotency_store(endpoint: str, body: dict, tenant: str,
                      response: dict, status: int) -> None:
    """Cache a response for future retries with the same Idempotency-Key.
    No-op when the header is absent."""
    idem_key = request.headers.get("Idempotency-Key")
    if not idem_key:
        return
    conn = get_db(DB_PATH)
    try:
        haldir_idempotency.store(
            conn, tenant, idem_key, endpoint, body, response, status,
        )
        conn.commit()
    finally:
        conn.close()


# ── Platform middleware ────────────────────────────────────────────────
#
# Three cross-cutting concerns applied to every HTTP request:
#
#   1. Request-ID propagation — every request gets a UUID (or echoes the
#      caller's X-Request-ID header). Returned on every response so users
#      can correlate client logs to server logs, and embedded in JSON
#      error bodies so bug reports always carry a traceable identifier.
#
#   2. Security headers — HSTS, X-Content-Type-Options, Referrer-Policy,
#      X-Frame-Options. Cheap, standards-based defenses that browsers
#      enforce on the client side. Applied to all responses.
#
#   3. Rate-limit headers — Stripe/GitHub-style X-RateLimit-Limit,
#      X-RateLimit-Remaining, X-RateLimit-Reset so clients can budget
#      their traffic before hitting a 429.
#
# JSON error handlers below replace Flask's default HTML error pages so
# API clients always receive a parseable body.

SECURITY_HEADERS = {
    # HSTS: force HTTPS for a year + subdomains. Tell browsers never to
    # downgrade to plaintext for haldir.xyz.
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    # Stop MIME-type sniffing; browsers must honor our Content-Type.
    "X-Content-Type-Options": "nosniff",
    # Deny framing — nothing on Haldir should be embedded in an iframe.
    "X-Frame-Options": "DENY",
    # Don't leak the full URL (which may carry session IDs) to off-site
    # resources. Stripe uses the same policy.
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # Disable unused browser features for API responses (defense in depth).
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


@app.before_request
def _platform_before() -> None:
    """Attach per-request state: request_id + start timestamp."""
    # Honor an inbound X-Request-ID from load balancers / gateways so a
    # single ID flows across the whole stack. Cap length defensively to
    # avoid header-injection tricks.
    incoming = (request.headers.get("X-Request-ID") or "").strip()[:64]
    g.request_id = incoming or uuid.uuid4().hex
    g.request_start = time.time()


@app.after_request
def _platform_after(response):  # type: ignore[no-untyped-def]
    """Emit request-ID, security, and rate-limit headers, then access log."""
    response.headers["X-Request-ID"] = getattr(g, "request_id", "")
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)

    # Rate-limit headers. Two bucket dimensions, each with its own full
    # surface so a client hitting the 429 can tell which limit fired and
    # when to retry:
    #
    #   X-RateLimit-*                  — the short (hourly) window
    #   X-RateLimit-Monthly-*          — the subscription-tier quota
    #   X-RateLimit-Resource           — which bucket this response
    #                                    pertains to ("hourly" | "monthly")
    #   Retry-After                    — RFC 7231 seconds-until-retry,
    #                                    set only on 429 responses
    #
    # Populated by the rate_limit before_request hook below when the
    # request was authenticated. Missing on unauthenticated requests
    # (health checks, bootstrap) — clients don't need them there.
    rl = getattr(g, "rate_limit", None)
    if rl:
        response.headers["X-RateLimit-Limit"]       = str(rl["limit"])
        response.headers["X-RateLimit-Remaining"]   = str(max(0, rl["remaining"]))
        response.headers["X-RateLimit-Used"]        = str(rl["used"])
        response.headers["X-RateLimit-Reset"]       = str(rl["reset"])
        response.headers["X-RateLimit-Reset-After"] = str(max(0, rl["reset_after"]))
        response.headers["X-RateLimit-Resource"]    = rl.get("resource", "hourly")

    rlm = getattr(g, "rate_limit_monthly", None)
    if rlm:
        response.headers["X-RateLimit-Monthly-Limit"]       = str(rlm["limit"])
        response.headers["X-RateLimit-Monthly-Remaining"]   = str(max(0, rlm["remaining"]))
        response.headers["X-RateLimit-Monthly-Used"]        = str(rlm["used"])
        response.headers["X-RateLimit-Monthly-Reset"]       = str(rlm["reset"])
        response.headers["X-RateLimit-Monthly-Reset-After"] = str(max(0, rlm["reset_after"]))

    retry_after = getattr(g, "retry_after", None)
    if retry_after is not None and response.status_code == 429:
        response.headers["Retry-After"] = str(max(1, int(retry_after)))

    # Metrics + structured access log.
    start = getattr(g, "request_start", None)
    duration_s = (time.time() - start) if start else None
    # Use the matched URL rule (e.g. `/v1/sessions/<id>/check`) rather
    # than the raw path so metric cardinality stays bounded — otherwise
    # every UUID in a URL produces a new time series.
    rule = getattr(request.url_rule, "rule", None)
    metric_path = rule or "unmatched"
    _M_REQUESTS.inc(
        method=request.method,
        path=metric_path,
        status=str(response.status_code),
    )
    if duration_s is not None:
        _M_DURATION.observe(duration_s, method=request.method, path=metric_path)

    # Skip /healthz access logs by default (noisy, uninteresting) —
    # flip HALDIR_LOG_HEALTHZ=1 to include them.
    if request.path != "/healthz" or os.environ.get("HALDIR_LOG_HEALTHZ") == "1":
        log.info(
            "request",
            extra={
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "duration_ms": int(duration_s * 1000) if duration_s is not None else None,
                "remote_addr": request.remote_addr,
                "user_agent": request.headers.get("User-Agent", "")[:120],
            },
        )
    return response


def _json_error(code: str, message: str, status: int, **extra):  # type: ignore[no-untyped-def]
    """Uniform error envelope: machine-readable `code` + human `error` +
    request_id so support requests are always traceable."""
    payload = {
        "error": message,
        "code": code,
        "request_id": getattr(g, "request_id", ""),
    }
    payload.update(extra)
    return jsonify(payload), status


@app.errorhandler(404)
def _err_404(_e):  # type: ignore[no-untyped-def]
    return _json_error("not_found", "Endpoint not found", 404)


@app.errorhandler(405)
def _err_405(_e):  # type: ignore[no-untyped-def]
    return _json_error("method_not_allowed", "Method not allowed for this endpoint", 405)


@app.errorhandler(413)
def _err_413(_e):  # type: ignore[no-untyped-def]
    return _json_error(
        "payload_too_large",
        "Request body exceeds 1 MiB limit",
        413,
        max_bytes=app.config["MAX_CONTENT_LENGTH"],
    )


@app.errorhandler(500)
def _err_500(e):  # type: ignore[no-untyped-def]
    # Log the stack server-side with full context; never leak it to clients.
    log.exception(
        "unhandled exception",
        extra={"method": request.method, "path": request.path},
    )
    return _json_error("internal_error", "Internal server error", 500)


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

        # Scopes — defaults to wildcard for legacy rows that pre-date
        # migration 003. The decorator @require_scope reads this list
        # off `request.api_key_scopes` when gating individual endpoints.
        import haldir_scopes
        try:
            request.api_key_scopes = haldir_scopes.parse(row["scopes"])
        except (IndexError, KeyError):
            request.api_key_scopes = [haldir_scopes.WILDCARD]

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

    # First key is free; subsequent keys need auth. When authed,
    # the new key inherits the caller's tenant_id so a tenant admin
    # can mint sub-keys (read-only SIEM key, CI deploy key, etc.)
    # under their existing tenant — that's the multi-key, single-
    # tenant pattern every Stripe-shaped API ships.
    inherited_tenant: str | None = None
    if key_count > 0:
        key = request.headers.get("Authorization", "").replace("Bearer ", "") or request.headers.get("X-API-Key", "")
        bootstrap = os.environ.get("HALDIR_BOOTSTRAP_TOKEN", "")
        if key:
            key_hash = _hash_key(key)
            conn = get_db(DB_PATH)
            row = conn.execute("SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0", (key_hash,)).fetchone()
            conn.close()
            if not row:
                return jsonify({"error": "Invalid API key"}), 401
            inherited_tenant = row["tenant_id"] or None
        elif bootstrap and request.json and request.json.get("bootstrap_token") == bootstrap:
            pass
        else:
            return jsonify({"error": "Authentication required to create additional keys"}), 401

    data = request.json or {}
    # Pre-auth endpoint (bootstrap) so there's no tenant yet — cache under
    # the empty tenant string; Idempotency-Keys are UUIDv4 so collision
    # risk across callers is negligible.
    cached = _idempotency_lookup("/v1/keys", data, "")
    if cached is not None:
        return cached

    name = data.get("name", "default")
    tier = "free"  # Always free on creation — only Stripe webhooks can upgrade

    # Per-key scopes. Default to wildcard for back-compat with every
    # existing client that doesn't pass `scopes`. Validate aggressively
    # so a typo like "aduit:read" fails fast with a 400 rather than
    # silently locking the holder out.
    import haldir_scopes
    try:
        requested_scopes = haldir_scopes.parse(data.get("scopes"))
        validated_scopes = haldir_scopes.validate(requested_scopes)
    except haldir_scopes.ScopeValidationError as e:
        return jsonify({"error": str(e), "code": "invalid_scope"}), 400

    full_key = f"hld_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(full_key)
    # Inherit caller's tenant so sub-keys live under the same tenant;
    # only the very first / bootstrap key starts a fresh one.
    tenant_id = inherited_tenant or key_hash[:16]

    conn = get_db(DB_PATH)
    conn.execute(
        "INSERT INTO api_keys (key_hash, key_prefix, tenant_id, name, tier, "
        "scopes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (key_hash, full_key[:12], tenant_id, name, tier,
         haldir_scopes.serialize(validated_scopes), time.time()),
    )
    conn.commit()
    conn.close()

    response = {
        "key": full_key,
        "prefix": full_key[:12],
        "name": name,
        "tier": tier,
        "scopes": validated_scopes,
        "message": "Save this key — it won't be shown again.",
    }
    _idempotency_store("/v1/keys", data, "", response, 201)
    return jsonify(response), 201


# ── Key admin lifecycle (list + revoke) ─────────────────────────────

@app.route("/v1/keys", methods=["GET"])
@require_api_key
@require_scope("admin:read")
def list_api_keys():
    """List every API key registered against the authed tenant.

    Returns prefix (the first 12 chars — safe to display, can't be
    used to authenticate), name, tier, scopes, created_at, last_used,
    revoked. The full key is never returned — once minted, it lives
    only on the holder's machine.

    This is the operational surface every security review asks for:
    'who can hit our API right now?' answered without a DB shell."""
    tenant = getattr(request, "tenant_id", "")
    conn = get_db(DB_PATH)
    rows = conn.execute(
        "SELECT key_prefix, name, tier, scopes, created_at, "
        "last_used, revoked FROM api_keys WHERE tenant_id = ? "
        "ORDER BY created_at DESC",
        (tenant,),
    ).fetchall()
    conn.close()
    keys = []
    for r in rows:
        try:
            scopes = json.loads(r["scopes"]) if "scopes" in r.keys() else ["*"]
        except (TypeError, json.JSONDecodeError):
            scopes = ["*"]
        keys.append({
            "prefix":     r["key_prefix"],
            "name":       r["name"],
            "tier":       r["tier"],
            "scopes":     scopes,
            "created_at": r["created_at"],
            "last_used":  r["last_used"],
            "revoked":    bool(r["revoked"]),
        })
    return jsonify({"keys": keys, "count": len(keys)})


@app.route("/v1/keys/<prefix>", methods=["DELETE"])
@require_api_key
@require_scope("admin:write")
def revoke_api_key(prefix: str):
    """Revoke a key by its 12-char prefix.

    Tenant-scoped: a tenant can only revoke their own keys. Returns
    404 if the prefix doesn't exist within the authed tenant.

    The currently-authed key can revoke itself — useful for the "I
    just found this in a public commit, kill it now" flow without
    needing to mint another key first.
    """
    if not prefix or len(prefix) > 64:
        return _json_error("invalid_prefix",
                           "prefix must be 1-64 chars", 400)
    tenant = getattr(request, "tenant_id", "")
    conn = get_db(DB_PATH)
    row = conn.execute(
        "SELECT key_hash FROM api_keys WHERE key_prefix = ? "
        "AND tenant_id = ? AND revoked = 0",
        (prefix, tenant),
    ).fetchone()
    if not row:
        conn.close()
        return _json_error("not_found",
                           "no active key with that prefix in this tenant",
                           404)
    conn.execute(
        "UPDATE api_keys SET revoked = 1 WHERE key_hash = ?",
        (row["key_hash"],),
    )
    conn.commit()
    conn.close()
    return jsonify({"revoked": True, "prefix": prefix}), 200


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
    except Exception:
        log.exception("demo key creation failed")
        return jsonify({"error": "Demo temporarily unavailable. Try again in a moment."}), 503


# ── Gate: Sessions ──

@app.route("/v1/sessions", methods=["POST"])
@require_api_key
@validate_body({
    "agent_id":    {"type": str,   "required": True, "maxlen": 128},
    "scopes":      {"type": list,  "default": ["read", "browse"]},
    "ttl":         {"type": int,   "default": 3600, "min": 0, "max": 86400 * 30},
    "spend_limit": {"type": float, "default": None, "min": 0},
})
def create_session():
    data = request.validated
    agent_id = data["agent_id"]
    scopes = data["scopes"]
    ttl = data["ttl"]
    spend_limit = data["spend_limit"]

    tenant = getattr(request, "tenant_id", "")
    cached = _idempotency_lookup("/v1/sessions", data, tenant)
    if cached is not None:
        return cached

    # Enforce agent limit per billing tier
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

    gate.register_agent(agent_id, default_scopes=scopes, tenant_id=tenant)
    session = gate.create_session(agent_id, scopes=scopes, ttl=ttl, spend_limit=spend_limit, tenant_id=tenant)

    response = {
        "session_id": session.session_id,
        "agent_id": session.agent_id,
        "scopes": session.scopes,
        "spend_limit": session.spend_limit,
        "expires_at": session.expires_at,
        "ttl": ttl,
    }
    _idempotency_store("/v1/sessions", data, tenant, response, 201)
    return jsonify(response), 201


@app.route("/v1/sessions/<session_id>", methods=["GET"])
@require_api_key
@require_scope("sessions:read")
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
@require_scope("sessions:write")
def revoke_session(session_id):
    tenant = getattr(request, "tenant_id", "")
    revoked = gate.revoke_session(session_id, tenant_id=tenant)
    if not revoked:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({"revoked": True, "session_id": session_id})


@app.route("/v1/sessions/<session_id>/check", methods=["POST"])
@require_api_key
@require_scope("sessions:read")
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
@require_scope("vault:write")
def store_secret():
    data = request.json or {}
    name = data.get("name")
    value = data.get("value")
    if not name or not value:
        return jsonify({"error": "name and value are required"}), 400

    tenant = getattr(request, "tenant_id", "")
    cached = _idempotency_lookup("/v1/secrets", data, tenant)
    if cached is not None:
        return cached

    scope_required = data.get("scope_required", "read")
    vault.store_secret(name, value, scope_required=scope_required, tenant_id=tenant)

    response = {"stored": True, "name": name}
    _idempotency_store("/v1/secrets", data, tenant, response, 201)
    return jsonify(response), 201


@app.route("/v1/secrets/<name>", methods=["GET"])
@require_api_key
@require_scope("vault:read")
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
@require_scope("vault:write")
def delete_secret(name):
    tenant = getattr(request, "tenant_id", "")
    deleted = vault.delete_secret(name, tenant_id=tenant)
    if not deleted:
        return jsonify({"error": f"Secret '{name}' not found"}), 404
    return jsonify({"deleted": True, "name": name})


@app.route("/v1/secrets", methods=["GET"])
@require_api_key
@require_scope("vault:read")
def list_secrets():
    tenant = getattr(request, "tenant_id", "")
    names = vault.list_secrets(tenant_id=tenant)
    return jsonify({"secrets": names, "count": len(names)})


# ── Vault: Payments ──

@app.route("/v1/payments/authorize", methods=["POST"])
@require_api_key
@validate_body({
    "session_id":  {"type": str,   "required": True, "maxlen": 128},
    # Minimum 1 cent, maximum $1M per single authorization — guards
    # against fat-finger disasters and still leaves headroom for
    # enterprise purchases.
    "amount":      {"type": float, "required": True, "min": 0.01, "max": 1_000_000},
    "currency":    {"type": str,   "default": "USD", "maxlen": 8},
    "description": {"type": str,   "default": "",    "maxlen": 500},
})
def authorize_payment():
    data = request.validated
    session_id = data["session_id"]
    amount = data["amount"]

    tenant = getattr(request, "tenant_id", "")
    cached = _idempotency_lookup("/v1/payments/authorize", data, tenant)
    if cached is not None:
        return cached

    session = gate.get_session(session_id, tenant_id=tenant)
    if not session:
        return jsonify({"error": "Invalid or expired session"}), 401

    result = vault.authorize_payment(
        session, amount,
        currency=data["currency"],
        description=data["description"],
    )

    status = 200 if result["authorized"] else 403
    _idempotency_store("/v1/payments/authorize", data, tenant, result, status)
    return jsonify(result), status


# ── Watch: Audit ──

@app.route("/v1/audit", methods=["POST"])
@require_api_key
@require_scope("audit:write")
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

    cached = _idempotency_lookup("/v1/audit", data, tenant)
    if cached is not None:
        return cached

    session = gate.get_session(session_id, tenant_id=tenant)
    if not session:
        return jsonify({"error": "Invalid or expired session"}), 401

    entry = watch.log_action(
        session, tool=tool, action=action,
        details=data.get("details"),
        cost_usd=cost_usd,
        tenant_id=tenant,
    )

    response = {
        "logged": True,
        "entry_id": entry.entry_id,
        "flagged": entry.flagged,
        "flag_reason": entry.flag_reason,
    }
    _idempotency_store("/v1/audit", data, tenant, response, 201)
    return jsonify(response), 201


@app.route("/v1/audit", methods=["GET"])
@require_api_key
@require_scope("audit:read")
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
@require_scope("audit:read")
def get_spend():
    tenant = getattr(request, "tenant_id", "")
    return jsonify(watch.get_spend(
        session_id=request.args.get("session_id"),
        agent_id=request.args.get("agent_id"),
        tenant_id=tenant,
    ))


@app.route("/v1/audit/verify", methods=["GET"])
@require_api_key
@require_scope("audit:read")
def verify_audit_chain():
    """Verify the cryptographic integrity of the audit log hash chain."""
    tenant = getattr(request, "tenant_id", "")
    result = watch.verify_chain(tenant_id=tenant)
    return jsonify(result)


# ── Audit export (compliance / SIEM / archival) ─────────────────────────
#
# Two endpoints. The first streams the trail in CSV or JSONL; the second
# returns the same integrity manifest without the body, for consumers
# who verify out-of-band. Both share an ExportFilters object so the
# OpenAPI contract stays in lock-step.

def _parse_export_filters() -> "haldir_export.ExportFilters":
    from haldir_export import ExportFilters

    def _f(k: str) -> float | None:
        v = request.args.get(k)
        if not v:
            return None
        try:
            # Accept both unix seconds and ISO 8601.
            return float(v)
        except ValueError:
            try:
                from datetime import datetime
                return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
            except ValueError:
                return None

    return ExportFilters(
        session_id=request.args.get("session_id"),
        agent_id=request.args.get("agent_id"),
        tool=request.args.get("tool"),
        since=_f("since"),
        until=_f("until"),
        flagged_only=request.args.get("flagged") == "true",
    )


@app.route("/v1/audit/export", methods=["GET"])
@require_api_key
@require_scope("audit:read")
def export_audit_trail():
    """Stream the caller's audit trail for ingest into a SIEM, data
    warehouse, or compliance archive. Supports CSV and JSONL; every
    export is chronological (timestamp ASC) and carries an integrity
    manifest either as the final JSONL record or via the companion
    /v1/audit/export/manifest endpoint."""
    import haldir_export

    fmt = request.args.get("format", "jsonl").lower()
    if fmt not in ("csv", "jsonl"):
        return _json_error(
            "invalid_format",
            "format must be 'csv' or 'jsonl'",
            400,
            got=fmt,
        )

    tenant = getattr(request, "tenant_id", "")
    filters = _parse_export_filters()
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    ext = "csv" if fmt == "csv" else "jsonl"
    mimetype = "text/csv" if fmt == "csv" else "application/x-ndjson"
    filename = f"haldir-audit-{tenant or 'export'}-{stamp}.{ext}"

    from flask import Response
    return Response(
        haldir_export.export_stream(DB_PATH, tenant, filters, fmt),
        mimetype=f"{mimetype}; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            # X-Accel-Buffering=no lets reverse proxies (nginx) stream
            # to the client as chunks arrive, instead of buffering the
            # whole response and defeating the point.
            "X-Accel-Buffering": "no",
            # Tell consumers the manifest is embedded in the stream
            # (JSONL) or available out-of-band (CSV).
            "X-Haldir-Export-Manifest": (
                "embedded-final-line" if fmt == "jsonl" else "out-of-band"
            ),
            "X-Haldir-Export-Format-Version": "1",
        },
    )


@app.route("/v1/audit/export/manifest", methods=["GET"])
@require_api_key
@require_scope("audit:read")
def export_audit_manifest():
    """Return the chain-verification manifest for the same filter set
    an export would use, without shipping the body. Lets auditors
    verify an archived export by re-running this call and comparing
    the sha256 + last_chain_hash."""
    import haldir_export
    tenant = getattr(request, "tenant_id", "")
    filters = _parse_export_filters()
    manifest = haldir_export.compute_manifest(DB_PATH, tenant, filters)
    return jsonify(manifest)


# ── Tamper-evident audit tree (RFC 6962 Merkle) ─────────────────────────
#
# Haldir's audit log is SHA-256 hash-chained end-to-end, which proves
# that no entry has been mutated in isolation. The Merkle surface below
# adds the second half of the tamper-evidence story: an auditor (or any
# third party holding an entry) can verify *inclusion* in a specific
# Signed Tree Head without replaying the whole log, and can verify that
# a later STH is a strict append-only extension of an earlier one
# (consistency proof — the same primitive Certificate Transparency uses
# to detect tree forks).
#
# All three endpoints are pure reads scoped by tenant_id; no DB writes.

@app.route("/v1/audit/tree-head", methods=["GET"])
@require_api_key
@require_scope("audit:read")
def get_audit_tree_head():
    """Current Signed Tree Head (STH) for the caller's audit log.

    The STH is an HMAC-SHA256 signature over (tree_size, root_hash,
    signed_at). Any later tree-head for the same tenant can be proved
    to extend this one via /v1/audit/consistency-proof."""
    import haldir_audit_tree
    tenant = getattr(request, "tenant_id", "")
    return jsonify(haldir_audit_tree.get_tree_head(DB_PATH, tenant))


@app.route("/v1/audit/inclusion-proof/<entry_id>", methods=["GET"])
@require_api_key
@require_scope("audit:read")
def get_audit_inclusion_proof(entry_id: str):
    """RFC 6962 inclusion proof for a single audit entry.

    Returns the leaf_hash, leaf_index, tree_size, root_hash, and the
    audit_path needed to re-hash up to the root. Bundled with the
    current STH so the proof can be verified offline against a signed
    commitment, not a raw root."""
    import haldir_audit_tree
    tenant = getattr(request, "tenant_id", "")
    proof = haldir_audit_tree.get_inclusion_proof(DB_PATH, tenant, entry_id)
    if proof is None:
        return _json_error(
            "not_found",
            "audit entry not found in this tenant's log",
            404,
            entry_id=entry_id,
        )
    return jsonify(proof)


@app.route("/v1/audit/sth-log", methods=["GET"])
@require_api_key
@require_scope("audit:read")
def get_audit_sth_log():
    """Self-published log of every Signed Tree Head Haldir has issued
    for this tenant.

    Query params:
      since (int)   — exclusive lower bound on tree_size (default 0)
      limit (int)   — max rows to return (default 1000, max 10000)

    Returns:
      {
        "tenant_id":  ...,
        "count":      <int total recorded>,
        "earliest":   <oldest row or null>,
        "latest":     <newest row or null>,
        "sths":       [<rows>...]
      }

    The combination of this endpoint and /v1/audit/sth-log/verify
    closes Haldir's tamper-evidence loop: an auditor can pin any
    STH today, demand the full log next quarter, and prove with
    certainty that no historical STH has been rewritten."""
    import haldir_sth_log
    tenant = getattr(request, "tenant_id", "")
    try:
        since = int(request.args.get("since", "0"))
        limit = min(int(request.args.get("limit", "1000")), 10000)
    except ValueError:
        return _json_error(
            "invalid_argument",
            "since and limit must be integers",
            400,
        )
    return jsonify({
        "tenant_id": tenant,
        "count":     haldir_sth_log.count(DB_PATH, tenant),
        "earliest":  haldir_sth_log.earliest(DB_PATH, tenant),
        "latest":    haldir_sth_log.latest(DB_PATH, tenant),
        "sths":      haldir_sth_log.list(DB_PATH, tenant, since, limit),
    })


@app.route("/v1/audit/sth-log/mirror/receipts", methods=["GET"])
@require_api_key
@require_scope("audit:read")
def get_sth_mirror_receipts():
    """Every external-transparency-log receipt Haldir recorded for
    this tenant.

    Haldir mirrors each STH to an external, append-only log — Sigstore
    Rekor, a file the operator archives, a webhook to a customer's
    own immutable store — and records the RECEIPT each backend returns
    here. An auditor cross-references Haldir's internal sth_log with
    the receipts + the external log itself to detect coordinated
    rewrites of Haldir's DB (see THREAT_MODEL.md §10.3).

    Query params:
      tree_size (int, optional) — narrow to receipts for one specific
                                   STH (e.g. diagnosing a divergence
                                   at that tree height)
      limit (int, default 100, max 1000)

    Returns:
      {tenant_id, count, receipts: [
         {tree_size, backend, receipt_id, log_index, mirrored_at,
          success, receipt_json, error_message},
         ...
      ]}
    """
    import haldir_transparency_mirror
    tenant = getattr(request, "tenant_id", "")
    tree_size_arg = request.args.get("tree_size")
    tree_size: int | None = None
    if tree_size_arg is not None:
        try:
            tree_size = int(tree_size_arg)
        except ValueError:
            return _json_error(
                "invalid_argument",
                "tree_size must be an integer",
                400,
            )
    try:
        limit = min(int(request.args.get("limit", "100")), 1000)
    except ValueError:
        return _json_error(
            "invalid_argument", "limit must be an integer", 400,
        )
    receipts = haldir_transparency_mirror.list_receipts(
        DB_PATH, tenant, tree_size=tree_size, limit=limit,
    )
    return jsonify({
        "tenant_id": tenant,
        "count":     len(receipts),
        "receipts":  receipts,
    })


@app.route("/v1/audit/sth-log/mirror/receipts/<receipt_id>/verify", methods=["GET"])
@require_api_key
@require_scope("audit:read")
def verify_sth_mirror_receipt(receipt_id: str):
    """Cryptographically verify a single Rekor receipt against
    Rekor's own publicly-published signing key.

    An auditor uses this to independently confirm that the UUID the
    mirror stored is actually in Rekor's real log — closing the
    "lying mirror" residual (THREAT_MODEL §10.3b). Two cryptographic
    proofs run here:

      1. RFC 6962 inclusion proof: leaf_hash → sibling hashes →
         claimed root. We delegate to haldir_merkle.verify_inclusion
         so the SAME verifier that validates Haldir's own tree
         validates Rekor's.
      2. SignedEntryTimestamp: Rekor's ECDSA-P-256 signature over
         the canonical {body, integratedTime, logID, logIndex}
         envelope, verified against Rekor's public key fetched
         live from the configured Rekor URL.

    Both checks must pass for verified=true. Individual subcheck
    results are returned so an operator dashboard can surface which
    step failed.
    """
    import haldir_rekor_verify
    import haldir_transparency_mirror
    tenant = getattr(request, "tenant_id", "")
    # Find the receipt. receipt_id is the Rekor UUID.
    all_receipts = haldir_transparency_mirror.list_receipts(
        DB_PATH, tenant, limit=10000,
    )
    receipt = next(
        (r for r in all_receipts if r.get("receipt_id") == receipt_id),
        None,
    )
    if receipt is None:
        return _json_error(
            "not_found",
            "no Rekor receipt with that id for this tenant",
            404,
            receipt_id=receipt_id,
        )
    return jsonify(haldir_rekor_verify.verify_receipt(receipt))


@app.route("/v1/audit/sth-log/verify", methods=["GET"])
@require_api_key
@require_scope("audit:read")
def verify_audit_sth_log():
    """Anti-equivocation verifier: an auditor pins (tree_size, root_hash)
    at one point in time and asks Haldir to prove the recorded STH at
    that tree_size still matches.

    Three outcomes:
      verified=true                 → pinned root matches the recorded
                                       row at that tree_size
      verified=false reason=equivocation
                                    → DIFFERENT root recorded at the
                                       pinned tree_size (cryptographic
                                       proof of misbehaviour)
      verified=false reason=not_in_log
                                    → no row at that tree_size; either
                                       predates retention or pinned STH
                                       is forged

    Query params:
      pinned_size (int, required)
      pinned_root (hex, required)
    """
    import haldir_sth_log
    tenant = getattr(request, "tenant_id", "")
    pinned_size_s = request.args.get("pinned_size", "")
    pinned_root   = request.args.get("pinned_root", "").strip().lower()
    if not pinned_size_s or not pinned_root:
        return _json_error(
            "invalid_argument",
            "pinned_size and pinned_root are required query params",
            400,
        )
    try:
        pinned_size = int(pinned_size_s)
    except ValueError:
        return _json_error(
            "invalid_argument", "pinned_size must be an integer", 400,
        )
    return jsonify(haldir_sth_log.verify_against_pinned(
        DB_PATH, tenant, pinned_size, pinned_root,
    ))


@app.route("/v1/audit/consistency-proof", methods=["GET"])
@require_api_key
@require_scope("audit:read")
def get_audit_consistency_proof():
    """RFC 6962 consistency proof between two tree sizes.

    Query params:
      first  — size of the earlier tree (required, >= 1)
      second — size of the later tree   (required, >= first)

    Both sizes must be <= the current log size. Returns the path of
    internal-node hashes an auditor can combine to reconstruct both
    the first_root and the second_root; if they match what that
    auditor already holds, the later tree is proved to be an
    append-only extension of the earlier one."""
    import haldir_audit_tree
    tenant = getattr(request, "tenant_id", "")
    try:
        first_size = int(request.args.get("first", ""))
        second_size = int(request.args.get("second", ""))
    except ValueError:
        return _json_error(
            "invalid_argument",
            "first and second must be integers",
            400,
        )
    proof = haldir_audit_tree.get_consistency_proof(
        DB_PATH, tenant, first_size, second_size,
    )
    if proof is None:
        return _json_error(
            "invalid_range",
            "invalid first/second sizes for this tenant's tree",
            400,
            first=first_size,
            second=second_size,
        )
    return jsonify(proof)


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
        except Exception:
            log.exception("usage tracking failed", extra={"tenant_id": tenant})
    return response


@app.route("/v1/usage", methods=["GET"])
@require_api_key
@require_scope("admin:read")
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
@require_scope("approvals:write")
def add_approval_rule():
    data = request.json or {}
    rule_type = data.get("type")
    if not rule_type:
        return jsonify({"error": "type is required (spend_over, tool_blocked, destructive, all)"}), 400
    tenant = getattr(request, "tenant_id", "")
    cached = _idempotency_lookup("/v1/approvals/rules", data, tenant)
    if cached is not None:
        return cached
    approval_engine.add_rule(
        rule_type=rule_type,
        threshold=float(data.get("threshold", 0)),
        tools=data.get("tools"),
    )
    response = {"added": True, "type": rule_type}
    _idempotency_store("/v1/approvals/rules", data, tenant, response, 201)
    return jsonify(response), 201


@app.route("/v1/approvals/request", methods=["POST"])
@require_api_key
@require_scope("approvals:write")
def request_approval():
    data = request.json or {}
    session_id = data.get("session_id")
    if not session_id:
        return jsonify({"error": "session_id is required"}), 400
    tenant = getattr(request, "tenant_id", "")
    cached = _idempotency_lookup("/v1/approvals/request", data, tenant)
    if cached is not None:
        return cached
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
    response = {
        "request_id": req.request_id,
        "status": req.status.value,
        "expires_at": req.expires_at,
    }
    _idempotency_store("/v1/approvals/request", data, tenant, response, 201)
    return jsonify(response), 201


@app.route("/v1/approvals/<request_id>", methods=["GET"])
@require_api_key
@require_scope("approvals:read")
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
@require_scope("approvals:write")
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
@require_scope("approvals:write")
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
@require_scope("approvals:read")
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

# ── Compliance scheduler ──────────────────────────────────────────────
#
# Daemon thread that wakes every hour, scans compliance_schedules for
# due rows, generates an evidence pack covering the prior cadence
# period, and fires it through webhook_mgr (signed + retried like any
# other event).
#
# Off by default to keep test runs deterministic — ops sets
# HALDIR_COMPLIANCE_SCHEDULER=1 in production.

if os.environ.get("HALDIR_COMPLIANCE_SCHEDULER") == "1":
    import haldir_compliance_scheduler as _comp_sched
    _comp_sched.start_background(DB_PATH, webhook_mgr=webhook_mgr)
    log.info("compliance scheduler started")

@app.route("/v1/webhooks", methods=["POST"])
@require_api_key
@require_scope("webhooks:write")
def register_webhook():
    data = request.json or {}
    url = data.get("url")
    if not url:
        return jsonify({"error": "url is required"}), 400
    tenant = getattr(request, "tenant_id", "")
    cached = _idempotency_lookup("/v1/webhooks", data, tenant)
    if cached is not None:
        return cached
    wh = webhook_mgr.register(
        url=url,
        name=data.get("name", ""),
        events=data.get("events"),
        tenant_id=tenant,
    )
    response = {
        "registered": True,
        "webhook_id": wh.webhook_id,
        "url": wh.url,
        "events": wh.events,
        "secret": wh.secret,  # one-time display, like POST /v1/keys
        "message": "Save the secret — it won't be shown again.",
    }
    _idempotency_store("/v1/webhooks", data, tenant, response, 201)
    return jsonify(response), 201


@app.route("/v1/webhooks", methods=["GET"])
@require_api_key
@require_scope("webhooks:read")
def list_webhooks():
    return jsonify({"webhooks": webhook_mgr.list_webhooks()})


@app.route("/v1/webhooks/<int:webhook_id>/rotate-secret", methods=["POST"])
@require_api_key
@require_scope("webhooks:write")
def rotate_webhook_secret(webhook_id: int):
    """Mint a new HMAC secret for the webhook + demote the current
    secret to `secret_prev` with a 24-hour grace window. Stripe-style
    zero-downtime rotation: configure both secrets at the receiver,
    rotate at Haldir, expire the old one at the receiver after the
    overlap window passes.

    Returns both secrets so the receiver can wire them up before the
    next event fires. The previous secret is included one final time
    here (it was already on file) so callers don't have to look it
    up out-of-band."""
    tenant = getattr(request, "tenant_id", "")
    grace = int(request.args.get("grace_seconds", 24 * 3600))
    grace = max(60, min(grace, 7 * 24 * 3600))  # 1 min - 7 days
    out = webhook_mgr.rotate_secret(
        webhook_id, tenant_id=tenant, grace_seconds=grace,
    )
    if out is None:
        return _json_error(
            "not_found",
            "no webhook with that id in this tenant",
            404,
        )
    return jsonify(out), 200


# ── Tenant admin overview (one-call dashboard) ──────────────────────────

@app.route("/v1/admin/overview", methods=["GET"])
@require_api_key
@require_scope("admin:read")
def admin_overview():
    """Single-call dashboard: tier + usage + sessions + vault + audit
    + webhooks + approvals + health for the authed tenant. Drives any
    operator UI without N HTTP fan-outs.

    Pure aggregate queries — bounded cost regardless of how many audit
    rows or sessions a tenant has accumulated."""
    import haldir_admin
    from haldir_status import build_status

    tenant = getattr(request, "tenant_id", "")
    overview = haldir_admin.build_overview(
        DB_PATH,
        tenant,
        watch=watch,
        tier_limits=TIER_LIMITS,
        health_snapshot=build_status(DB_PATH, prom_metrics),
    )
    return jsonify(overview)


# ── Compliance evidence pack (auditor-ready document) ──────────────────

def _parse_iso_or_unix(v: str | None) -> float | None:
    if not v:
        return None
    try:
        return float(v)
    except ValueError:
        try:
            from datetime import datetime
            return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None


@app.route("/v1/compliance/evidence", methods=["GET"])
@require_api_key
@require_scope("admin:read")
def compliance_evidence():
    """Auditor-ready proof-of-control pack: identity, access control,
    encryption, audit trail, spend governance, approvals, webhooks,
    plus a SHA-256 self-signature.

    Query:
      since   ISO 8601 or unix seconds (default: 90 days ago)
      until   ISO 8601 or unix seconds (default: now)
      format  json | markdown | md (default: json)
    """
    import haldir_compliance
    tenant = getattr(request, "tenant_id", "")
    since = _parse_iso_or_unix(request.args.get("since"))
    until = _parse_iso_or_unix(request.args.get("until"))
    fmt = (request.args.get("format") or "json").lower()
    if fmt not in ("json", "markdown", "md"):
        return _json_error(
            "invalid_format",
            "format must be 'json' or 'markdown'",
            400, got=fmt,
        )
    pack = haldir_compliance.build_evidence_pack(
        DB_PATH, tenant, since=since, until=until,
    )
    if fmt in ("markdown", "md"):
        body = haldir_compliance.render_markdown(pack)
        return body, 200, {
            "Content-Type":        "text/markdown; charset=utf-8",
            "Content-Disposition":
                f'attachment; filename="haldir-evidence-{tenant or "pack"}.md"',
            "X-Haldir-Evidence-Digest": pack["signatures"]["digest"],
        }
    return jsonify(pack)


@app.route("/v1/compliance/schedules", methods=["POST"])
@require_api_key
@require_scope("admin:write")
@validate_body({
    "name":     {"type": str, "required": True, "maxlen": 128},
    "cadence":  {"type": str, "required": True,
                 "choices": ["daily", "weekly", "monthly", "quarterly"]},
    "delivery": {"type": str, "required": True, "maxlen": 256},
})
def create_compliance_schedule():
    """Register a recurring evidence-pack delivery. Cadence + delivery
    target are validated; duplicate names are allowed (auditors may
    want both 'monthly-internal' and 'monthly-external' targets)."""
    import haldir_compliance_scheduler as sched
    data = request.validated
    tenant = getattr(request, "tenant_id", "")
    try:
        out = sched.create_schedule(
            DB_PATH, tenant,
            name=data["name"], cadence=data["cadence"],
            delivery=data["delivery"],
        )
    except sched.ScheduleValidationError as e:
        return _json_error("invalid_schedule", str(e), 400)
    return jsonify(out), 201


@app.route("/v1/compliance/schedules", methods=["GET"])
@require_api_key
@require_scope("admin:read")
def list_compliance_schedules():
    """Return every schedule registered for the authed tenant —
    name, cadence, delivery, last-run state, next-due timestamp."""
    import haldir_compliance_scheduler as sched
    tenant = getattr(request, "tenant_id", "")
    return jsonify({"schedules": sched.list_schedules(DB_PATH, tenant)})


@app.route("/v1/compliance/schedules/<schedule_id>", methods=["DELETE"])
@require_api_key
@require_scope("admin:write")
def delete_compliance_schedule(schedule_id: str):
    import haldir_compliance_scheduler as sched
    tenant = getattr(request, "tenant_id", "")
    if not sched.delete_schedule(DB_PATH, tenant, schedule_id):
        return _json_error("not_found", "schedule not found", 404)
    return ("", 204)


@app.route("/v1/compliance/score", methods=["GET"])
@require_api_key
@require_scope("admin:read")
def compliance_score():
    """Live 0-100 readiness score + per-control pass/warn/fail detail.

    Each SOC2 criterion Haldir covers is evaluated against the tenant's
    current state; the top-line number is `passing / total * 100` with
    warnings counted as half a pass. Returns both the score AND the
    per-criterion `remediation` hint so downstream UIs can render
    "here's what to fix to close the gap"."""
    import haldir_compliance_score
    tenant = getattr(request, "tenant_id", "")
    return jsonify(haldir_compliance_score.compute_score(DB_PATH, tenant))


@app.route("/v1/compliance/evidence/manifest", methods=["GET"])
@require_api_key
@require_scope("admin:read")
def compliance_evidence_manifest():
    """Just the signature block — used by an auditor verifying an
    archived pack without re-downloading the whole document."""
    import haldir_compliance
    tenant = getattr(request, "tenant_id", "")
    since = _parse_iso_or_unix(request.args.get("since"))
    until = _parse_iso_or_unix(request.args.get("until"))
    pack = haldir_compliance.build_evidence_pack(
        DB_PATH, tenant, since=since, until=until,
    )
    return jsonify({
        "signatures":   pack["signatures"],
        "period_start": pack["period_start"],
        "period_end":   pack["period_end"],
        "tenant_id":    pack["tenant_id"],
    })


# ── Compliance dashboard (HTML — the URL CISOs bookmark) ─────────────

@app.route("/compliance", methods=["GET"])
def compliance_html():
    """Live, browser-rendered evidence pack — the URL a CISO would
    bookmark and check before every audit cycle. Same data path as
    /v1/compliance/evidence; HTML is just the presentation layer.

    Auth precedence + sandbox flow mirrors /admin/overview so the two
    surfaces feel like one product:

      ?key=<hld_...>            sign in via querystring
      Authorization: Bearer ... sign in via header
      ?demo=1                   mint a sandbox key + redirect
      (no key)                  render a sign-in form, status 200
    """
    import haldir_compliance

    if request.args.get("demo") == "1":
        full_key = f"hld_{secrets.token_urlsafe(32)}"
        key_hash = _hash_key(full_key)
        tenant_id = f"demo_{key_hash[:12]}"
        conn = get_db(DB_PATH)
        conn.execute(
            "INSERT INTO api_keys (key_hash, key_prefix, tenant_id, name, "
            "tier, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (key_hash, full_key[:12], tenant_id, "compliance-demo",
             "free", '["*"]', time.time()),
        )
        conn.commit()
        conn.close()
        return redirect(f"/compliance?key={full_key}")

    key = request.args.get("key", "")
    if not key:
        key = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not key:
        # Reuse the admin login form — same look, same demo button,
        # same UX so visitors don't get a different sign-in surface.
        return _render_admin_login(), 200, {
            "Content-Type": "text/html; charset=utf-8",
        }

    key_hash = _hash_key(key)
    conn = get_db(DB_PATH)
    row = conn.execute(
        "SELECT tenant_id FROM api_keys WHERE key_hash = ? AND revoked = 0",
        (key_hash,),
    ).fetchone()
    conn.close()
    if not row:
        return _render_admin_login(error="Invalid or revoked key."), 401, {
            "Content-Type": "text/html; charset=utf-8",
        }

    tenant_id = row["tenant_id"]
    since = _parse_iso_or_unix(request.args.get("since"))
    until = _parse_iso_or_unix(request.args.get("until"))
    pack = haldir_compliance.build_evidence_pack(
        DB_PATH, tenant_id, since=since, until=until,
    )
    import haldir_compliance_score
    score = haldir_compliance_score.compute_score(DB_PATH, tenant_id)
    return haldir_compliance.render_html(pack, key=key, score=score), 200, {
        "Content-Type": "text/html; charset=utf-8",
    }


# ── Web admin dashboard (HTML mirror of the CLI's `haldir overview`) ──

@app.route("/admin", methods=["GET"])
def admin_redirect():
    return redirect("/admin/overview")


@app.route("/admin/overview", methods=["GET"])
def admin_overview_html():
    """Server-rendered tenant dashboard. Same payload as the JSON
    endpoint; HTML is just the presentation layer.

    Auth precedence: ?key=<hld_...> querystring → Authorization header.
    If no key is provided, render a minimal "paste a key" form. If the
    visitor clicks the demo button (?demo=1), auto-mint a sandbox key
    and redirect with it — same flow the CLI's `haldir login` walks
    a developer through.
    """
    import haldir_admin
    from haldir_status import build_status

    # ── Demo flow: mint a fresh sandbox key + redirect ───────────────
    if request.args.get("demo") == "1":
        full_key = f"hld_{secrets.token_urlsafe(32)}"
        key_hash = _hash_key(full_key)
        tenant_id = f"demo_{key_hash[:12]}"
        conn = get_db(DB_PATH)
        conn.execute(
            "INSERT INTO api_keys (key_hash, key_prefix, tenant_id, name, tier, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (key_hash, full_key[:12], tenant_id, "admin-demo", "free", time.time()),
        )
        conn.commit()
        conn.close()
        return redirect(f"/admin/overview?key={full_key}")

    # ── Resolve key + tenant ────────────────────────────────────────
    key = request.args.get("key", "")
    if not key:
        key = request.headers.get(
            "Authorization", "").replace("Bearer ", "")
    if not key:
        return _render_admin_login(), 200, {
            "Content-Type": "text/html; charset=utf-8",
        }

    key_hash = _hash_key(key)
    conn = get_db(DB_PATH)
    row = conn.execute(
        "SELECT tenant_id FROM api_keys WHERE key_hash = ? AND revoked = 0",
        (key_hash,),
    ).fetchone()
    conn.close()
    if not row:
        return _render_admin_login(error="Invalid or revoked key."), 401, {
            "Content-Type": "text/html; charset=utf-8",
        }
    tenant_id = row["tenant_id"]

    overview = haldir_admin.build_overview(
        DB_PATH, tenant_id,
        watch=watch, tier_limits=TIER_LIMITS,
        health_snapshot=build_status(DB_PATH, prom_metrics),
    )
    return _render_admin_overview(overview, key), 200, {
        "Content-Type": "text/html; charset=utf-8",
    }


def _render_admin_login(error: str = "") -> str:
    """Tiny key-paste form when the visitor hits /admin/overview with
    no auth. Includes a one-click demo button that mints a sandbox
    key — same path /demo uses, so visitors can preview the dashboard
    without signing up."""
    err_block = (
        f'<p class="err">{error}</p>' if error else ''
    )
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Haldir Admin · sign in</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500&family=Inter:wght@200;300;400;600&display=swap" rel="stylesheet">
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#050505;color:#e0ddd5;font-family:'Inter',sans-serif;
       min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem}
  .card{max-width:440px;width:100%;border:1px solid rgba(224,221,213,0.08);
        border-radius:8px;padding:2.5rem 2rem;background:rgba(255,255,255,0.015)}
  h1{font-weight:300;font-size:1.5rem;letter-spacing:-0.5px;margin-bottom:0.5rem}
  .lede{font-size:0.85rem;color:rgba(224,221,213,0.5);margin-bottom:2rem;line-height:1.6}
  label{display:block;font-family:'IBM Plex Mono',monospace;font-size:0.6rem;
        letter-spacing:2px;text-transform:uppercase;color:rgba(224,221,213,0.5);margin-bottom:0.5rem}
  input{width:100%;background:#0a0a0a;border:1px solid rgba(224,221,213,0.2);
        border-radius:4px;padding:0.75rem 1rem;color:#e0ddd5;font-family:'IBM Plex Mono',monospace;
        font-size:0.85rem}
  input:focus{outline:none;border-color:#b8973a}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;margin-top:1.5rem}
  button,a.btn{display:block;width:100%;padding:0.85rem;border:none;border-radius:4px;
        font-family:'IBM Plex Mono',monospace;font-size:0.65rem;letter-spacing:2px;
        text-transform:uppercase;cursor:pointer;text-align:center;text-decoration:none}
  .btn-w{background:#e0ddd5;color:#050505}
  .btn-g{background:transparent;color:rgba(224,221,213,0.5);
         border:1px solid rgba(224,221,213,0.2)}
  .btn-w:hover{background:rgba(224,221,213,0.8)}
  .btn-g:hover{color:#e0ddd5;border-color:rgba(224,221,213,0.5)}
  .err{color:#d05a5a;font-size:0.8rem;margin-bottom:1rem}
  .footer{text-align:center;font-size:0.7rem;color:rgba(224,221,213,0.3);
          margin-top:1.5rem;font-family:'IBM Plex Mono',monospace}
  .footer a{color:rgba(224,221,213,0.5);text-decoration:none}
</style>
</head>
<body>
<div class="card">
  <h1>Haldir admin</h1>
  <p class="lede">Sign in with your API key to see your tenant's live dashboard,
     or click below for a sandbox preview.</p>
  """ + err_block + """
  <form method="get" action="/admin/overview">
    <label for="key">API key</label>
    <input type="text" id="key" name="key" placeholder="hld_..." autofocus>
    <div class="row">
      <button type="submit" class="btn-w">Sign in</button>
      <a class="btn btn-g" href="/admin/overview?demo=1">Live demo</a>
    </div>
  </form>
  <p class="footer">
    No key yet? <a href="/quickstart">Get one</a> · <a href="/">haldir.xyz</a>
  </p>
</div>
</body>
</html>"""


def _render_admin_overview(o: dict, key: str) -> str:
    """The dashboard. Same layout as the CLI's `haldir overview` —
    pills, progress bar, seven-row summary — translated to HTML."""
    import html as _h

    state = o.get("health", {}).get("status", "ok")
    state_color = {
        "ok":       "#0b8043",
        "degraded": "#b58900",
        "down":     "#b00020",
    }.get(state, "#5a5a5a")
    state_label = {
        "ok":       "All systems operational",
        "degraded": "Partial degradation",
        "down":     "Service disruption",
    }.get(state, state)

    u = o.get("usage", {})
    pct = float(u.get("actions_pct_used", 0.0))
    bar_pct = min(100.0, max(0.0, pct * 100))
    bar_color = (
        "#0b8043" if pct < 0.7 else
        "#b58900" if pct < 0.9 else
        "#b00020"
    )

    s = o.get("sessions", {})
    v = o.get("vault", {})
    a = o.get("audit", {})
    w = o.get("webhooks", {})
    ap = o.get("approvals", {})

    chain_ok = a.get("chain_verified", True)
    chain_mark = "✓" if chain_ok else "✗"
    chain_color = "#0b8043" if chain_ok else "#b00020"

    rate = float(w.get("delivery_success_rate_24h", 1.0))
    rate_color = (
        "#0b8043" if rate >= 0.99 else
        "#b58900" if rate >= 0.95 else
        "#b00020"
    )

    pending = ap.get("pending_count", 0)
    pending_color = "#b58900" if pending else "#5a5a5a"

    c = o.get("compliance", {})
    compliance_sub = (
        f"next pack {c['next_due_at']}" if c.get("next_due_at")
        else "no recurring schedules"
    )

    # Truncate the key shown in the corner so we don't leak it into
    # OG cards if someone screenshots the page.
    key_short = (_h.escape(key[:8]) + "..." + _h.escape(key[-4:])
                 ) if key and len(key) > 12 else _h.escape(key or "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Haldir admin · {_h.escape(o.get('tenant_id', ''))}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<meta http-equiv="refresh" content="30">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500&family=Inter:wght@200;300;400;600&display=swap" rel="stylesheet">
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{background:#050505;color:#e0ddd5;font-family:'Inter',sans-serif;
        min-height:100vh;padding:3rem 1.5rem}}
  .wrap{{max-width:880px;margin:0 auto}}
  header{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:2rem}}
  h1{{font-weight:300;font-size:1.4rem;letter-spacing:-0.5px}}
  .meta{{font-family:'IBM Plex Mono',monospace;font-size:0.7rem;
         color:rgba(224,221,213,0.4);margin-top:0.25rem}}
  .right{{text-align:right;font-family:'IBM Plex Mono',monospace;font-size:0.65rem}}
  .right a{{color:rgba(224,221,213,0.5);text-decoration:none;margin-left:1rem}}
  .right a:hover{{color:#e0ddd5}}

  .banner{{background:{state_color};color:#fff;padding:1rem 1.5rem;
          border-radius:6px;font-size:0.95rem;font-weight:500;margin-bottom:1.5rem}}

  .grid{{display:grid;gap:1px;background:rgba(224,221,213,0.08);
         border:1px solid rgba(224,221,213,0.08);border-radius:6px;overflow:hidden}}
  .row{{background:#050505;display:grid;grid-template-columns:140px 1fr auto;
        align-items:center;padding:1.1rem 1.5rem;gap:1.25rem}}
  .label{{font-family:'IBM Plex Mono',monospace;font-size:0.6rem;
          letter-spacing:2px;text-transform:uppercase;
          color:rgba(224,221,213,0.4)}}
  .value{{font-size:1.1rem;font-weight:500;color:#e0ddd5}}
  .sub{{font-family:'IBM Plex Mono',monospace;font-size:0.7rem;
        color:rgba(224,221,213,0.5);text-align:right}}

  .pill{{display:inline-flex;align-items:center;gap:0.5rem;
         font-family:'IBM Plex Mono',monospace;font-size:0.7rem;
         text-transform:lowercase}}
  .dot{{width:8px;height:8px;border-radius:50%}}

  .bar{{display:inline-block;width:160px;height:8px;background:rgba(224,221,213,0.08);
        border-radius:4px;overflow:hidden;vertical-align:middle;margin-left:0.5rem}}
  .bar-fill{{display:block;height:100%;background:{bar_color};width:{bar_pct:.1f}%}}

  footer{{font-family:'IBM Plex Mono',monospace;font-size:0.65rem;
          color:rgba(224,221,213,0.3);text-align:center;margin-top:2rem}}
  footer a{{color:rgba(224,221,213,0.5);text-decoration:none;margin:0 0.75rem}}
</style>
</head>
<body>
<div class="wrap">

  <header>
    <div>
      <h1>Haldir admin</h1>
      <div class="meta">
        {_h.escape(o.get('tenant_id', ''))} · tier
        <span style="color:#b8973a">{_h.escape(o.get('tier', ''))}</span> ·
        {_h.escape(o.get('generated_at', ''))}
      </div>
    </div>
    <div class="right">
      <span style="color:rgba(224,221,213,0.3)">{key_short}</span>
      <a href="/admin/overview?key={_h.escape(key)}">refresh</a>
      <a href="/admin/overview">sign out</a>
    </div>
  </header>

  <div class="banner">{state_label}</div>

  <div class="grid">

    <div class="row">
      <div class="label">Actions</div>
      <div class="value">{u.get('actions_this_month', 0):,}<span style="color:rgba(224,221,213,0.4);font-weight:300"> / {u.get('actions_limit', 0):,}</span><span class="bar"><span class="bar-fill"></span></span></div>
      <div class="sub">{pct * 100:.1f}% of monthly quota</div>
    </div>

    <div class="row">
      <div class="label">Spend</div>
      <div class="value">${u.get('spend_usd_this_month', 0.0):.2f}</div>
      <div class="sub">this month</div>
    </div>

    <div class="row">
      <div class="label">Sessions</div>
      <div class="value">{s.get('active_count', 0):,}</div>
      <div class="sub">{s.get('agents_active', 0)} / {s.get('agents_limit', 0)} agents</div>
    </div>

    <div class="row">
      <div class="label">Vault</div>
      <div class="value">{v.get('secrets_count', 0):,} <span style="font-weight:300;color:rgba(224,221,213,0.5);font-size:0.85rem">secrets</span></div>
      <div class="sub">{v.get('secret_access_count', 0)} accesses this month</div>
    </div>

    <div class="row">
      <div class="label">Audit</div>
      <div class="value">{a.get('total_entries', 0):,} <span style="font-weight:300;color:rgba(224,221,213,0.5);font-size:0.85rem">entries</span></div>
      <div class="sub">{a.get('flagged_7d', 0)} flagged · chain <span style="color:{chain_color}">{chain_mark}</span></div>
    </div>

    <div class="row">
      <div class="label">Webhooks</div>
      <div class="value">{w.get('registered_count', 0):,} <span style="font-weight:300;color:rgba(224,221,213,0.5);font-size:0.85rem">registered · {w.get('deliveries_24h', 0):,} deliveries (24h)</span></div>
      <div class="sub"><span style="color:{rate_color}">{rate * 100:.2f}%</span> success</div>
    </div>

    <div class="row">
      <div class="label">Approvals</div>
      <div class="value" style="color:{pending_color}">{pending:,} <span style="font-weight:300;color:rgba(224,221,213,0.5);font-size:0.85rem">pending</span></div>
      <div class="sub"></div>
    </div>

    <div class="row">
      <div class="label">Compliance</div>
      <div class="value">{c.get('active_count', 0)} <span style="font-weight:300;color:rgba(224,221,213,0.5);font-size:0.85rem">recurring schedules</span></div>
      <div class="sub">{compliance_sub}</div>
    </div>

  </div>

  <footer>
    <a href="/">haldir.xyz</a> ·
    <a href="/swagger">API</a> ·
    <a href="/status">status</a> ·
    <a href="/v1/admin/overview?key={_h.escape(key)}">JSON</a> ·
    <span style="color:rgba(224,221,213,0.3)">refreshes every 30s</span>
  </footer>

</div>
</body>
</html>"""


@app.route("/v1/webhooks/deliveries", methods=["GET"])
@require_api_key
@require_scope("webhooks:read")
def list_webhook_deliveries():
    """Return the most recent delivery attempts for the authed tenant.
    Query params:
        limit     max rows (default 50, cap 500)
        event_id  narrow to a single event
    """
    tenant = getattr(request, "tenant_id", "")
    limit = min(int(request.args.get("limit", 50)), 500)
    event_id = request.args.get("event_id")
    return jsonify({
        "deliveries": webhook_mgr.list_deliveries(
            tenant_id=tenant, limit=limit, event_id=event_id,
        ),
    })


# ── Rate Limiting ──

_rate_limits = {}  # key_hash -> {window_start, count}
RATE_LIMITS = {"free": 100, "pro": 5000, "enterprise": 50000}

# Per-process, in-memory counters. Good enough for single-node Haldir
# deployments (which is where most installs live today). When we fan
# out across multiple gunicorn hosts the counter shifts to a shared
# store (Redis / Postgres advisory locks) so limits are globally
# accurate — tracked as follow-up, not a correctness hazard yet
# because production runs a single container.

def _seconds_until_end_of_month(now_ts: float) -> int:
    """Unix-epoch seconds between now and the first second of the
    next calendar month. Used for the monthly-quota Retry-After so
    clients know when the subscription window rolls over, not just
    'some unknown quantity of seconds in the future'."""
    from datetime import datetime, timezone
    now = datetime.fromtimestamp(now_ts, tz=timezone.utc)
    if now.month == 12:
        nxt = now.replace(year=now.year + 1, month=1, day=1,
                          hour=0, minute=0, second=0, microsecond=0)
    else:
        nxt = now.replace(month=now.month + 1, day=1,
                          hour=0, minute=0, second=0, microsecond=0)
    return max(1, int(nxt.timestamp() - now_ts))


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
        reset = int(entry["start"] + window)
        reset_after = max(0, reset - int(now))
        remaining = limit - entry["count"]
        # Stash for _platform_after to emit Stripe/GitHub-style headers.
        g.rate_limit = {
            "limit":       limit,
            "used":        entry["count"],
            "remaining":   remaining,
            "reset":       reset,
            "reset_after": reset_after,
            "resource":    "hourly",
        }
        if entry["count"] > limit:
            _M_RL_HITS.inc(tier=effective_tier)
            g.retry_after = reset_after
            return _json_error(
                "rate_limit_exceeded",
                "Rate limit exceeded",
                429,
                limit=limit,
                tier=effective_tier,
                retry_after=reset_after,
                resource="hourly",
            )

        if tenant:
            tier_limits = TIER_LIMITS.get(effective_tier, TIER_LIMITS["free"])
            monthly_limit = tier_limits["actions_per_month"]
            monthly_actions = _get_tenant_monthly_actions(tenant)
            monthly_reset_after = _seconds_until_end_of_month(now)
            g.rate_limit_monthly = {
                "limit":       monthly_limit,
                "used":        monthly_actions,
                "remaining":   max(0, monthly_limit - monthly_actions),
                "reset":       int(now + monthly_reset_after),
                "reset_after": monthly_reset_after,
            }
            if monthly_actions >= monthly_limit:
                # Mark the overall resource dimension as monthly so the
                # X-RateLimit-Resource header tells callers which bucket
                # they hit (hourly vs monthly quota).
                g.rate_limit["resource"] = "monthly"
                g.retry_after = monthly_reset_after
                return _json_error(
                    "monthly_quota_exceeded",
                    "Monthly action quota exceeded",
                    429,
                    tier=billing_tier,
                    limit=monthly_limit,
                    used=monthly_actions,
                    retry_after=monthly_reset_after,
                    resource="monthly",
                    upgrade="https://haldir.xyz/pricing",
                )


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
    """MCP server card for automated discovery and Smithery listing.

    Two layers merged:
      1. Static richness from `.well-known/mcp/server-card.json` on
         disk — curated description, categories, tags, use-cases,
         trust signals, full link map.
      2. Live tools + prompts + capabilities from the in-process
         MCP_TOOLS / MCP_PROMPTS / MCP_CAPABILITIES dicts so the
         card never drifts from what the server actually advertises.
    """
    card_path = os.path.join(
        os.path.dirname(__file__), ".well-known", "mcp", "server-card.json",
    )
    base: dict = {}
    if os.path.exists(card_path):
        with open(card_path) as f:
            base = json.load(f)
    # Overlay live server state.
    base["capabilities"] = MCP_CAPABILITIES
    base["tools"] = [
        {"name": t["name"], "description": t["description"]} for t in MCP_TOOLS
    ]
    base["prompts"] = [
        {"name": p["name"], "description": p["description"]} for p in MCP_PROMPTS
    ]
    base.setdefault("configSchema", {
        "type": "object",
        "properties": {
            "apiKey": {
                "type": "string",
                "description": "Haldir API key (starts with hld_). Mint via POST /v1/keys.",
            },
            "baseUrl": {
                "type": "string",
                "description": "Base URL of the Haldir API server.",
                "default": "https://haldir.xyz",
            },
        },
        "required": ["apiKey"],
    })
    return jsonify(base)


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
@require_scope("proxy:write")
def register_upstream():
    """Register an upstream MCP server to proxy through Haldir."""
    data = request.json or {}
    name = data.get("name")
    url = data.get("url")
    if not name or not url:
        return jsonify({"error": "name and url are required"}), 400
    tenant = getattr(request, "tenant_id", "")
    cached = _idempotency_lookup("/v1/proxy/upstreams", data, tenant)
    if cached is not None:
        return cached
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
    _idempotency_store("/v1/proxy/upstreams", data, tenant, resp, 201)
    return jsonify(resp), 201


@app.route("/v1/proxy/upstreams", methods=["GET"])
@require_api_key
@require_scope("proxy:read")
def list_upstreams():
    """List all registered upstream servers and their status."""
    return jsonify(proxy.get_stats())


@app.route("/v1/proxy/tools", methods=["GET"])
@require_api_key
@require_scope("proxy:read")
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
@require_scope("proxy:write")
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
    cached = _idempotency_lookup("/v1/proxy/call", data, tenant)
    if cached is not None:
        return cached
    session = gate.get_session(session_id, tenant_id=tenant)
    if not session:
        return jsonify({"error": "Invalid or expired session"}), 401

    result = proxy.call_tool(tool_name, arguments, session=session)
    status = 403 if result.get("isError") else 200
    _idempotency_store("/v1/proxy/call", data, tenant, result, status)
    return jsonify(result), status


@app.route("/v1/proxy/policies", methods=["POST"])
@require_api_key
@require_scope("proxy:write")
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
    tenant = getattr(request, "tenant_id", "")
    cached = _idempotency_lookup("/v1/proxy/policies", data, tenant)
    if cached is not None:
        return cached
    proxy.add_policy(**data)
    response = {"added": True, "type": ptype}
    _idempotency_store("/v1/proxy/policies", data, tenant, response, 201)
    return jsonify(response), 201


@app.route("/v1/proxy/policies", methods=["GET"])
@require_api_key
@require_scope("proxy:read")
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


@app.route("/demo")
def demo_page():
    """Public, in-browser playground. Walks a visitor through the four
    primitives (mint key, create session, check permission, log audit)
    against the live API — same routes the SDKs hit. Real API calls,
    sandbox tenant per visitor."""
    demo_path = os.path.join(os.path.dirname(__file__), "landing", "demo.html")
    if os.path.exists(demo_path):
        with open(demo_path) as f:
            return f.read(), 200, {"Content-Type": "text/html"}
    return redirect("/docs")


@app.route("/demo/<path:filename>")
def demo_assets(filename):
    """Serve the animated SVG (and any future demo-page assets) from
    the `demo/` directory. Locked to one directory and the path is
    sanitized by Flask's send_from_directory."""
    demo_dir = os.path.join(os.path.dirname(__file__), "demo")
    return send_from_directory(demo_dir, filename, max_age=3600)


# ── x402 pay-per-request surface (agentic.market compatible) ─────────
#
# Three Haldir primitives exposed as x402-v2 paid resources. Gated
# behind HALDIR_X402_ENABLED so the default deploy doesn't force USDC
# on free-tier visitors. When enabled, the decorator handles the full
# 402 flow: header validation → facilitator verify → facilitator
# settle → Merkle-logged payment → underlying handler response with
# PAYMENT-RESPONSE carrying the tx hash.

import haldir_x402

X402_PRICE_TREE_HEAD      = 1000    # $0.001 USDC
X402_PRICE_INCLUSION      = 10000   # $0.01  USDC
X402_PRICE_EVIDENCE_PACK  = 100000  # $0.10  USDC


@app.route("/v1/x402/tree-head", methods=["GET"])
@haldir_x402.require_x402_payment(
    amount_atomic=X402_PRICE_TREE_HEAD,
    description="Current RFC 6962 Signed Tree Head for the demo tenant's audit log — Ed25519-signed, verifiable against /.well-known/jwks.json.",
    resource_name="tree-head",
    bazaar={
        "info": {
            "input": {
                "type":   "http",
                "method": "GET",
            },
            "output": {
                "type":   "object",
                "format": "application/json",
                "example": {
                    "tree_size":  5,
                    "root_hash":  "6dfb5091757a6cf6103c6c5875515d7ddce2a2aba5b4733dc73e18432213c608",
                    "signed_at":  1776641283,
                    "signature":  "1554589611ad7dda…",
                    "algorithm":  "Ed25519-over-canonical-sth",
                    "key_id":     "8d409dbbd0525852",
                    "tenant_id":  "demo-tamper-public",
                },
            },
        },
        "schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type":    "object",
            "required": ["tree_size", "root_hash", "signature", "algorithm"],
            "properties": {
                "tree_size":  {"type": "integer", "minimum": 0},
                "root_hash":  {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "signature":  {"type": "string"},
                "signed_at":  {"type": "integer"},
                "algorithm":  {"type": "string"},
                "key_id":     {"type": "string"},
                "public_key": {"type": "string"},
                "tenant_id":  {"type": "string"},
            },
        },
    },
)
def x402_tree_head():
    import haldir_audit_tree
    tenant = getattr(request, "tenant_id", "") or "demo-tamper-public"
    return jsonify(haldir_audit_tree.get_tree_head(DB_PATH, tenant))


@app.route("/v1/x402/inclusion-proof/<entry_id>", methods=["GET"])
@haldir_x402.require_x402_payment(
    amount_atomic=X402_PRICE_INCLUSION,
    description="RFC 6962 inclusion proof for a single audit entry — bundled with the current STH, verifiable offline with the Haldir SDK or any RFC 6962 verifier.",
    resource_name="inclusion-proof",
    bazaar={
        "info": {
            "input": {
                "type":   "http",
                "method": "GET",
                "pathParams": {
                    "entry_id": {
                        "type":        "string",
                        "description": "UUID of the audit entry to prove inclusion for",
                    },
                },
            },
            "output": {
                "type":   "object",
                "format": "application/json",
                "example": {
                    "algorithm":  "RFC6962-SHA256",
                    "entry_id":   "demo-entry-003",
                    "leaf_index": 2,
                    "leaf_hash":  "56ef498fc1fbac7e1fbccc3749b3a820cd605526d4069bd230b24c6665e3f884",
                    "tree_size":  5,
                    "root_hash":  "6dfb5091757a6cf6103c6c5875515d7ddce2a2aba5b4733dc73e18432213c608",
                    "audit_path": ["dab03c52…", "2671fb43…", "960b4b04…"],
                    "sth": {"tree_size": 5, "root_hash": "6dfb5091…",
                             "algorithm": "Ed25519-over-canonical-sth"},
                },
            },
        },
        "schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type":    "object",
            "required": ["algorithm", "leaf_hash", "leaf_index",
                          "tree_size", "root_hash", "audit_path", "sth"],
            "properties": {
                "algorithm":  {"const": "RFC6962-SHA256"},
                "entry_id":   {"type": "string"},
                "leaf_index": {"type": "integer", "minimum": 0},
                "leaf_hash":  {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "tree_size":  {"type": "integer", "minimum": 1},
                "root_hash":  {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "audit_path": {"type": "array", "items": {"type": "string"}},
                "sth":        {"type": "object"},
            },
        },
    },
)
def x402_inclusion_proof(entry_id: str):
    import haldir_audit_tree
    tenant = getattr(request, "tenant_id", "") or "demo-tamper-public"
    proof = haldir_audit_tree.get_inclusion_proof(DB_PATH, tenant, entry_id)
    if proof is None:
        return jsonify({"error": "entry not found in this tenant's log",
                        "entry_id": entry_id}), 404
    return jsonify(proof)


@app.route("/v1/x402/evidence-pack", methods=["GET"])
@haldir_x402.require_x402_payment(
    amount_atomic=X402_PRICE_EVIDENCE_PACK,
    description="Signed audit-prep evidence pack relevant to SOC2 CC5.2, CC6.1, CC6.7, CC7.2, CC7.3, CC8.1. JSON with eight sections + SHA-256 self-signature + embedded STH.",
    resource_name="evidence-pack",
    bazaar={
        "info": {
            "input": {
                "type":   "http",
                "method": "GET",
                "queryParams": {
                    "since": {
                        "type":        "string",
                        "description": "Period start (ISO 8601 or unix seconds). Defaults to 90 days ago.",
                    },
                    "until": {
                        "type":        "string",
                        "description": "Period end (ISO 8601 or unix seconds). Defaults to now.",
                    },
                },
            },
            "output": {
                "type":   "object",
                "format": "application/json",
                "example": {
                    "format_version": "haldir-evidence-1",
                    "tenant_id":      "demo-tamper-public",
                    "period_start":   "2026-01-01T00:00:00+00:00",
                    "period_end":     "2026-04-01T00:00:00+00:00",
                    "controls":       {"...": "8 SOC2 control sections"},
                    "tamper_evidence": {"algorithm": "RFC6962-SHA256",
                                          "tree_size": 5, "root_hash": "..."},
                    "signatures":     {"algorithm": "SHA-256",
                                          "digest": "..."},
                },
            },
        },
        "schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type":    "object",
            "required": ["tenant_id", "period_start", "period_end",
                          "controls", "signatures"],
            "properties": {
                "tenant_id":       {"type": "string"},
                "period_start":    {"type": "string"},
                "period_end":      {"type": "string"},
                "controls":        {"type": "object"},
                "tamper_evidence": {"type": "object"},
                "signatures":      {"type": "object"},
            },
        },
    },
)
def x402_evidence_pack():
    import haldir_compliance
    tenant = getattr(request, "tenant_id", "") or "demo-tamper-public"
    since = _parse_iso_or_unix(request.args.get("since"))
    until = _parse_iso_or_unix(request.args.get("until"))
    return jsonify(haldir_compliance.build_evidence_pack(
        DB_PATH, tenant, since=since, until=until,
    ))


@app.route("/v1/x402/manifest", methods=["GET"])
def x402_manifest():
    """Discovery endpoint — lists every x402 resource this server
    exposes with price + network + payTo. Public; no auth. Agentic
    crawlers (agentic.market, x402.org/ecosystem) pull this to list
    us in their directories."""
    return jsonify(haldir_x402.build_manifest(app))


@app.route("/.well-known/x402.json", methods=["GET"])
def x402_well_known():
    """Same content as /v1/x402/manifest at the well-known path. Some
    directory crawlers look here, some at /v1/x402/manifest — we
    advertise both so neither misses us."""
    return jsonify(haldir_x402.build_manifest(app))


# ── /demo/tamper — adversarial tamper-evidence demo ──────────────────
#
# Public, no-auth page. A visitor sees a live audit log for a seeded
# demo tenant, the current Signed Tree Head, and an inclusion proof
# for one entry; clicking "Tamper" mutates a row in the DB and the
# page re-renders showing the cryptographic fork-detection. Built on
# exactly the same haldir_merkle / haldir_audit_tree primitives the
# production /v1/audit/* endpoints use — nothing is mocked.

@app.route("/demo/tamper", methods=["GET"])
def demo_tamper_page():
    import haldir_demo_tamper
    return haldir_demo_tamper.render(), 200, {
        "Content-Type":   "text/html; charset=utf-8",
        "Cache-Control":  "no-store",
    }


@app.route("/demo/tamper/mutate", methods=["POST"])
def demo_tamper_mutate():
    import haldir_demo_tamper
    haldir_demo_tamper.tamper_target()
    return redirect("/demo/tamper", code=303)


@app.route("/demo/tamper/reset", methods=["POST"])
def demo_tamper_reset():
    import haldir_demo_tamper
    haldir_demo_tamper.reset()
    return redirect("/demo/tamper", code=303)


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

    cached = _idempotency_lookup("/v1/billing/checkout", data, tenant)
    if cached is not None:
        return cached

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
        response = {"url": session.url, "session_id": session.id}
        _idempotency_store("/v1/billing/checkout", data, tenant, response, 200)
        return jsonify(response)
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


@app.route("/llms-full.txt")
def llms_full_txt():
    p = os.path.join(os.path.dirname(__file__), "llms-full.txt")
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/robots.txt")
def robots_txt():
    p = os.path.join(os.path.dirname(__file__), "robots.txt")
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/sitemap.xml")
def sitemap_xml():
    p = os.path.join(os.path.dirname(__file__), "sitemap.xml")
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "application/xml; charset=utf-8"}


@app.route("/.well-known/security.txt")
def security_txt():
    p = os.path.join(os.path.dirname(__file__), ".well-known", "security.txt")
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/.well-known/ai.txt")
def ai_txt():
    p = os.path.join(os.path.dirname(__file__), ".well-known", "ai.txt")
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/.well-known/ai-plugin.json")
def ai_plugin():
    p = os.path.join(os.path.dirname(__file__), "ai-plugin.json")
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "application/json"}


@app.route("/.well-known/agent.json")
def agent_json():
    """Single-entry-point manifest for agents doing capability
    discovery. Describes every way to talk to Haldir (REST / MCP stdio
    / MCP HTTP / x402), every integration package, every trust signal,
    and where we're already listed in the ecosystem. One file, one
    fetch, complete picture."""
    p = os.path.join(
        os.path.dirname(__file__), ".well-known", "agent.json",
    )
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "application/json"}


@app.route("/.well-known/jwks.json")
def jwks_json():
    """JSON Web Key Set — publishes the Ed25519 public key used to
    sign Signed Tree Heads.

    An auditor pins a `kid` from this endpoint at enrollment. Future
    STHs tagged with that `kid` can be verified offline without
    Haldir participating. If Haldir ever rotates the key, a new `kid`
    appears here; the auditor sees the rotation explicitly and
    decides whether to trust it. Same pattern OIDC / Sigstore /
    Fulcio use for their signing keys.

    Shape conforms to RFC 7517 JWK format with `crv: Ed25519`
    (draft-ietf-cose-webauthn-algorithms extension, also how Okta /
    Auth0 / Ory / Supabase publish their OKP keys)."""
    import haldir_merkle as merkle
    import base64

    priv, source = merkle.load_ed25519_signing_key_from_env()
    pub_raw = priv.public_key().public_bytes_raw()
    kid = merkle._key_id_for_pubkey(pub_raw)

    def b64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    return jsonify({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": kid,
                "x":   b64url(pub_raw),
                "x-haldir-source": source,
            }
        ]
    })


@app.route("/AGENTS.md")
def agents_md():
    """Emerging convention — AI coding agents (Cursor, Codex, Aider,
    Claude Code, Windsurf, Devin) look for AGENTS.md at repo and site
    root for project-specific conventions. Mirror the on-disk file so
    the live site and the git tree stay in sync."""
    p = os.path.join(os.path.dirname(__file__), "AGENTS.md")
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "text/markdown; charset=utf-8"}


@app.route("/THREAT_MODEL.md")
def threat_model_md():
    """Public threat-model document — STRIDE per component, named
    adversaries, honest residual-risk declarations, disclosure policy.
    Enterprise security buyers and technical investors read this
    first; serving it at the repo + site root means there's one
    canonical version no marketing team can dilute."""
    p = os.path.join(os.path.dirname(__file__), "THREAT_MODEL.md")
    with open(p) as f:
        return f.read(), 200, {"Content-Type": "text/markdown; charset=utf-8"}


@app.route("/icon.svg")
def icon_svg():
    return '''<svg viewBox="0 0 80 92" fill="none" xmlns="http://www.w3.org/2000/svg">
<defs><linearGradient id="sg" x1="40" y1="4" x2="40" y2="88" gradientUnits="userSpaceOnUse">
<stop offset="0%" stop-color="#e8c84a"/><stop offset="100%" stop-color="#8a6d1b"/></linearGradient></defs>
<path d="M40 4 L72 18 V46 C72 68 58 80 40 88 C22 80 8 68 8 46 V18 Z" fill="url(#sg)" opacity="0.15" stroke="url(#sg)" stroke-width="2"/>
<path d="M32 44 L38 50 L52 36" stroke="#c9a33e" stroke-width="4" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
</svg>''', 200, {"Content-Type": "image/svg+xml"}


# ── Health & metrics ──

@app.route("/healthz")
def healthz():
    """Back-compat alias for /livez. New consumers should target the
    explicit liveness/readiness endpoints below — they map directly
    onto Kubernetes probe semantics and answer different questions."""
    import haldir_health
    return jsonify({**haldir_health.liveness(), "status": "ok",
                    "version": "0.1.0"})


@app.route("/livez")
def livez():
    """Liveness probe — process is responsive. Always 200 if Flask
    is serving requests. Does no I/O so a wedged DB never causes a
    container restart."""
    import haldir_health
    return jsonify(haldir_health.liveness())


@app.route("/readyz")
def readyz():
    """Readiness probe — should this pod receive traffic right now?
    Checks DB reachability, migration consistency, and encryption-key
    configuration. Returns 503 if any required check fails so the
    load balancer pulls this pod from rotation without restarting it.

    Pod restart on transient DB blip is the wrong behavior; the right
    behavior is 'wait for the dep to recover, then accept traffic
    again' — exactly the gap between liveness and readiness probes."""
    import haldir_health
    payload = haldir_health.readiness(DB_PATH)
    status = 200 if payload["ready"] else 503
    return jsonify(payload), status


@app.route("/metrics")
def prometheus_metrics():
    """Prometheus scrape endpoint.

    Gated behind HALDIR_METRICS_TOKEN: the scraper must pass it as
    `?token=...` OR via `Authorization: Bearer <token>`. If the env var
    is unset we refuse to expose metrics at all — safer than leaking
    internal telemetry to the public internet.

    Returns Prometheus text exposition format (v0.0.4)."""
    expected = os.environ.get("HALDIR_METRICS_TOKEN", "")
    if not expected:
        return _json_error(
            "metrics_disabled",
            "Metrics endpoint disabled — set HALDIR_METRICS_TOKEN to enable",
            503,
        )
    provided = (
        request.args.get("token", "")
        or request.headers.get("Authorization", "").replace("Bearer ", "")
    )
    if not secrets.compare_digest(provided, expected):
        return _json_error("unauthorized", "Valid metrics token required", 401)
    return prom_metrics.render(), 200, {
        "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
    }


# ── OpenAPI + Swagger UI ────────────────────────────────────────────────

@app.route("/openapi.json")
def openapi_spec():
    """OpenAPI 3.1 spec, generated directly from the live Flask route
    table + @validate_body schemas. Never out of sync with the code."""
    return jsonify(generate_openapi(app))


@app.route("/swagger")
def swagger_ui():
    """Interactive API explorer (Swagger UI served from jsdelivr CDN)."""
    return (
        """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Haldir API — Swagger UI</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
<style>html,body{margin:0;padding:0;background:#050505}</style>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
  window.onload = () => SwaggerUIBundle({
    url: '/openapi.json',
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis],
  });
</script>
</body>
</html>""",
        200,
        {"Content-Type": "text/html; charset=utf-8"},
    )


# ── Public status page ──────────────────────────────────────────────────

@app.route("/v1/status")
def status_json():
    """Machine-readable status snapshot. Cheap enough to be polled by
    uptime monitors (Pingdom, UptimeRobot, etc.) — one SQLite ping plus
    an in-memory read of the metrics registry."""
    return jsonify(build_status(DB_PATH, prom_metrics))


@app.route("/status")
def status_page():
    """Customer-facing status page — rendered server-side on every hit so
    the data is never stale. Uses the same build_status() snapshot as the
    JSON endpoint so the two can never disagree."""
    snap = build_status(DB_PATH, prom_metrics)

    banner_state = snap["status"]
    banner_color = {
        "ok":       "#0b8043",
        "degraded": "#b58900",
        "down":     "#b00020",
    }.get(banner_state, "#555")
    banner_text = {
        "ok":       "All systems operational",
        "degraded": "Partial degradation",
        "down":     "Service disruption",
    }.get(banner_state, banner_state)

    rows = []
    dot_color = {"ok": "#0b8043", "degraded": "#b58900", "down": "#b00020"}
    for c in snap["components"]:
        rows.append(
            f"""<tr>
  <td><span class="dot" style="background:{dot_color.get(c['state'], '#555')}"></span>{c['name']}</td>
  <td class="state">{c['state']}</td>
  <td class="msg">{c['message']}</td>
</tr>"""
        )
    rows_html = "\n".join(rows)

    sr = snap["metrics"]["success_rate"]
    success_pct = f"{sr['ratio'] * 100:.3f}%"
    success_sub = f"{sr['total'] - sr['errors']:,} / {sr['total']:,} requests"

    def _fmt_latency(seconds: float | None) -> str:
        if seconds is None:
            return "—"
        if seconds < 1:
            return f"{seconds * 1000:.0f} ms"
        return f"{seconds:.2f} s"

    lat = snap["metrics"]["latency_seconds"]

    import html as _html
    safe = _html.escape  # escape any future user-supplied strings

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Haldir Status</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Live operational status for the Haldir API.">
<style>
  :root {{
    --bg: #0a0a0a;
    --fg: #e8e8e8;
    --muted: #888;
    --card: #141414;
    --border: #222;
  }}
  * {{ box-sizing: border-box }}
  body {{
    margin: 0; padding: 2rem 1rem;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: var(--bg); color: var(--fg);
    line-height: 1.5;
  }}
  .wrap {{ max-width: 780px; margin: 0 auto }}
  header {{ margin-bottom: 2rem }}
  header a {{ color: var(--muted); text-decoration: none; font-size: 14px }}
  h1 {{ margin: 0 0 0.25rem; font-size: 28px; letter-spacing: -0.02em }}
  .checked {{ color: var(--muted); font-size: 13px }}
  .banner {{
    background: {banner_color}; color: #fff;
    padding: 1.25rem 1.5rem; border-radius: 8px;
    font-size: 20px; font-weight: 600;
    margin: 1.5rem 0;
  }}
  section {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem;
  }}
  h2 {{ margin: 0 0 1rem; font-size: 15px; text-transform: uppercase;
        letter-spacing: 0.08em; color: var(--muted); font-weight: 600 }}
  table {{ width: 100%; border-collapse: collapse }}
  td {{ padding: 0.6rem 0; border-bottom: 1px solid var(--border); font-size: 15px }}
  tr:last-child td {{ border-bottom: none }}
  td.state {{ text-transform: uppercase; font-size: 12px; letter-spacing: 0.05em;
              color: var(--muted); width: 110px }}
  td.msg {{ color: var(--muted); font-size: 14px; text-align: right }}
  .dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%;
          margin-right: 0.6rem; vertical-align: middle }}
  .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem }}
  .grid .cell {{ text-align: left }}
  .cell .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase;
                  letter-spacing: 0.05em }}
  .cell .value {{ font-size: 24px; font-weight: 600; margin-top: 0.25rem }}
  .cell .sub {{ color: var(--muted); font-size: 12px; margin-top: 0.15rem }}
  footer {{ color: var(--muted); font-size: 13px; margin-top: 2rem; text-align: center }}
  footer a {{ color: var(--muted) }}
  @media (max-width: 520px) {{
    .grid {{ grid-template-columns: repeat(2, 1fr) }}
    td.msg {{ display: none }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <a href="/">&larr; haldir.xyz</a>
    <h1>Haldir Status</h1>
    <div class="checked">Checked just now</div>
  </header>

  <div class="banner">{safe(banner_text)}</div>

  <section>
    <h2>Components</h2>
    <table>{rows_html}</table>
  </section>

  <section>
    <h2>Last {sr['total']:,} Requests</h2>
    <div class="grid">
      <div class="cell">
        <div class="label">Success rate</div>
        <div class="value">{success_pct}</div>
        <div class="sub">{success_sub}</div>
      </div>
      <div class="cell">
        <div class="label">p50 latency</div>
        <div class="value">{_fmt_latency(lat['p50'])}</div>
        <div class="sub">median</div>
      </div>
      <div class="cell">
        <div class="label">p95 latency</div>
        <div class="value">{_fmt_latency(lat['p95'])}</div>
        <div class="sub">95th pct</div>
      </div>
      <div class="cell">
        <div class="label">p99 latency</div>
        <div class="value">{_fmt_latency(lat['p99'])}</div>
        <div class="sub">99th pct</div>
      </div>
    </div>
  </section>

  <footer>
    <a href="/v1/status">JSON</a> &middot;
    <a href="/swagger">API docs</a> &middot;
    <a href="mailto:sterling@haldir.xyz">Report an issue</a>
  </footer>
</div>
</body>
</html>"""

    return html, 200, {"Content-Type": "text/html; charset=utf-8"}


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
