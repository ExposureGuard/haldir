-- Haldir baseline schema — migration 001.
--
-- This file is the authoritative source for Haldir's database schema
-- at the time the migrations system was introduced. It is written in
-- PostgreSQL syntax; the migration runner rewrites BYTEA → BLOB and
-- SERIAL PRIMARY KEY → INTEGER PRIMARY KEY AUTOINCREMENT when applied
-- against SQLite.
--
-- All statements use IF NOT EXISTS so re-application is a no-op. That
-- is how the migrations runner bootstraps existing deployments into
-- the versioning system without re-creating anything.
--
-- Future schema changes go into new 00N_*.sql files — do NOT edit this
-- one after it has been applied anywhere, or the checksum verifier
-- will flag drift on the next restart.

-- ── Identity & sessions ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    key_prefix TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    tier TEXT NOT NULL DEFAULT 'free',
    created_at REAL NOT NULL,
    last_used REAL NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_keys_tenant ON api_keys(tenant_id);

CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT '',
    default_scopes TEXT NOT NULL DEFAULT '["read","browse"]',
    max_spend REAL NOT NULL DEFAULT 0.0,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    PRIMARY KEY (agent_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    agent_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    spend_limit REAL NOT NULL DEFAULT 0.0,
    spent REAL NOT NULL DEFAULT 0.0,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL DEFAULT 0.0,
    revoked INTEGER NOT NULL DEFAULT 0,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);

-- ── Vault: encrypted secrets ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS secrets (
    name TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT '',
    encrypted_value BYTEA NOT NULL,
    scope_required TEXT NOT NULL DEFAULT 'read',
    created_at REAL NOT NULL,
    last_accessed REAL NOT NULL DEFAULT 0.0,
    access_count INTEGER NOT NULL DEFAULT 0,
    metadata TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (name, tenant_id)
);

-- ── Spend ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS payments (
    authorization_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    description TEXT NOT NULL DEFAULT '',
    remaining_budget REAL NOT NULL DEFAULT 0.0,
    timestamp DOUBLE PRECISION NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_payments_session ON payments(session_id);
CREATE INDEX IF NOT EXISTS idx_payments_tenant ON payments(tenant_id);

-- ── Audit trail (hash-chained) ─────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_log (
    entry_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    tool TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    cost_usd REAL NOT NULL DEFAULT 0.0,
    timestamp DOUBLE PRECISION NOT NULL,
    flagged INTEGER NOT NULL DEFAULT 0,
    flag_reason TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL DEFAULT '',
    entry_hash TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

CREATE TABLE IF NOT EXISTS anomaly_rules (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    rule_type TEXT NOT NULL,
    threshold REAL NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);

-- ── Approvals ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS approval_requests (
    request_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    tool TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    reason TEXT NOT NULL DEFAULT '',
    amount REAL NOT NULL DEFAULT 0.0,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL DEFAULT 0.0,
    decided_at REAL NOT NULL DEFAULT 0.0,
    decided_by TEXT NOT NULL DEFAULT '',
    decision_note TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approvals_tenant ON approval_requests(tenant_id);

-- ── Webhooks ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS webhooks (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    events TEXT NOT NULL DEFAULT '["all"]',
    active INTEGER NOT NULL DEFAULT 1,
    secret TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    last_fired REAL NOT NULL DEFAULT 0,
    fire_count INTEGER NOT NULL DEFAULT 0,
    fail_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhooks(tenant_id);

-- ── Billing ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS usage (
    tenant_id TEXT NOT NULL,
    month TEXT NOT NULL,
    action_count INTEGER NOT NULL DEFAULT 0,
    secret_access_count INTEGER NOT NULL DEFAULT 0,
    payment_count INTEGER NOT NULL DEFAULT 0,
    total_spend_usd REAL NOT NULL DEFAULT 0.0,
    PRIMARY KEY (tenant_id, month)
);

CREATE INDEX IF NOT EXISTS idx_usage_tenant ON usage(tenant_id);

CREATE TABLE IF NOT EXISTS subscriptions (
    tenant_id TEXT PRIMARY KEY,
    stripe_customer_id TEXT NOT NULL DEFAULT '',
    stripe_subscription_id TEXT NOT NULL DEFAULT '',
    tier TEXT NOT NULL DEFAULT 'free',
    status TEXT NOT NULL DEFAULT 'active',
    current_period_end REAL NOT NULL DEFAULT 0.0,
    created_at REAL NOT NULL DEFAULT 0.0,
    updated_at REAL NOT NULL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_subs_stripe_cust ON subscriptions(stripe_customer_id);

-- ── Idempotency (retry-safe POSTs) ─────────────────────────────────

CREATE TABLE IF NOT EXISTS idempotency_keys (
    tenant_id   TEXT    NOT NULL,
    key         TEXT    NOT NULL,
    endpoint    TEXT    NOT NULL,
    body_hash   TEXT    NOT NULL,
    response    TEXT    NOT NULL,
    status_code INTEGER NOT NULL,
    created_at  REAL    NOT NULL,
    PRIMARY KEY (tenant_id, key, endpoint)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_created ON idempotency_keys(created_at);
