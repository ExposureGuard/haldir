"""
Haldir Database — Multi-tenant persistence layer.

Supports SQLite (dev/small deployments) and PostgreSQL (production).
Every table has a tenant_id column for data isolation between API keys.

Set DATABASE_URL for Postgres: postgresql://user:pass@host/haldir
Otherwise falls back to SQLite at HALDIR_DB_PATH.
"""

import os
import time
import sqlite3

DATABASE_URL = os.environ.get("DATABASE_URL", "")
DEFAULT_DB_PATH = os.environ.get("HALDIR_DB_PATH", "/data/haldir.db" if os.path.isdir("/data") else "haldir.db")

_pg_pool = None


def _is_postgres() -> bool:
    return DATABASE_URL.startswith("postgres")


def get_db(db_path: str = DEFAULT_DB_PATH):
    """Get a database connection. Returns SQLite or Postgres depending on config."""
    if _is_postgres():
        return _get_pg()
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _get_pg():
    """Get a PostgreSQL connection from the pool."""
    global _pg_pool
    import psycopg2
    import psycopg2.extras

    if _pg_pool is None:
        from psycopg2 import pool
        _pg_pool = pool.ThreadedConnectionPool(1, 10, DATABASE_URL)

    conn = _pg_pool.getconn()
    conn.autocommit = False
    return PgConnectionWrapper(conn, _pg_pool)


class PgConnectionWrapper:
    """Wraps psycopg2 connection to match sqlite3 interface."""

    def __init__(self, conn, pool):
        self._conn = conn
        self._pool = pool
        self._cursor = None

    def execute(self, sql, params=None):
        # Convert ? placeholders to %s for postgres
        sql = sql.replace("?", "%s")
        # Convert INTEGER PRIMARY KEY AUTOINCREMENT to SERIAL
        sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        cursor = self._conn.cursor(cursor_factory=_DictCursor())
        cursor.execute(sql, params or ())
        self._cursor = cursor
        return cursor

    def executescript(self, sql):
        # Convert SQLite syntax to Postgres
        sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        sql = sql.replace("CREATE INDEX IF NOT EXISTS", "CREATE INDEX IF NOT EXISTS")
        cursor = self._conn.cursor()
        cursor.execute(sql)
        self._conn.commit()
        return cursor

    def commit(self):
        self._conn.commit()

    def close(self):
        self._pool.putconn(self._conn)

    def fetchone(self):
        if self._cursor:
            return self._cursor.fetchone()
        return None

    def fetchall(self):
        if self._cursor:
            return self._cursor.fetchall()
        return []


def _DictCursor():
    import psycopg2.extras
    return psycopg2.extras.RealDictCursor


def init_db(db_path: str = DEFAULT_DB_PATH):
    """Create all tables if they don't exist."""
    if _is_postgres():
        _init_pg()
    else:
        _init_sqlite(db_path)


def _init_sqlite(db_path: str):
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA_SQLITE)
    conn.commit()
    conn.close()


def _init_pg():
    import psycopg2
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()
    cursor.execute(_SCHEMA_POSTGRES)
    conn.commit()
    conn.close()


# ── Schema ──

_SCHEMA_SQLITE = """
    -- API keys
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

    -- Gate: agent policies
    CREATE TABLE IF NOT EXISTS agents (
        agent_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL DEFAULT '',
        default_scopes TEXT NOT NULL DEFAULT '["read","browse"]',
        max_spend REAL NOT NULL DEFAULT 0.0,
        metadata TEXT NOT NULL DEFAULT '{}',
        created_at REAL NOT NULL,
        PRIMARY KEY (agent_id, tenant_id)
    );

    -- Gate: sessions
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
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

    -- Vault: encrypted secrets
    CREATE TABLE IF NOT EXISTS secrets (
        name TEXT NOT NULL,
        tenant_id TEXT NOT NULL DEFAULT '',
        encrypted_value BLOB NOT NULL,
        scope_required TEXT NOT NULL DEFAULT 'read',
        created_at REAL NOT NULL,
        last_accessed REAL NOT NULL DEFAULT 0.0,
        access_count INTEGER NOT NULL DEFAULT 0,
        metadata TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY (name, tenant_id)
    );

    -- Vault: payment authorizations
    CREATE TABLE IF NOT EXISTS payments (
        authorization_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT '',
        session_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        amount REAL NOT NULL,
        currency TEXT NOT NULL DEFAULT 'USD',
        description TEXT NOT NULL DEFAULT '',
        remaining_budget REAL NOT NULL DEFAULT 0.0,
        timestamp REAL NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_payments_session ON payments(session_id);
    CREATE INDEX IF NOT EXISTS idx_payments_tenant ON payments(tenant_id);

    -- Watch: audit log
    CREATE TABLE IF NOT EXISTS audit_log (
        entry_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT '',
        session_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        action TEXT NOT NULL,
        tool TEXT NOT NULL DEFAULT '',
        details TEXT NOT NULL DEFAULT '{}',
        cost_usd REAL NOT NULL DEFAULT 0.0,
        timestamp REAL NOT NULL,
        flagged INTEGER NOT NULL DEFAULT 0,
        flag_reason TEXT NOT NULL DEFAULT ''
    );

    CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);
    CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
    CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_flagged ON audit_log(flagged);

    -- Watch: anomaly rules
    CREATE TABLE IF NOT EXISTS anomaly_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT '',
        rule_type TEXT NOT NULL,
        threshold REAL NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        created_at REAL NOT NULL
    );

    -- Approvals
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

    -- Webhooks
    CREATE TABLE IF NOT EXISTS webhooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT '',
        url TEXT NOT NULL,
        name TEXT NOT NULL DEFAULT '',
        events TEXT NOT NULL DEFAULT '["all"]',
        active INTEGER NOT NULL DEFAULT 1,
        created_at REAL NOT NULL,
        last_fired REAL NOT NULL DEFAULT 0,
        fire_count INTEGER NOT NULL DEFAULT 0,
        fail_count INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhooks(tenant_id);

    -- Usage tracking (for billing)
    CREATE TABLE IF NOT EXISTS usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        month TEXT NOT NULL,
        action_count INTEGER NOT NULL DEFAULT 0,
        secret_access_count INTEGER NOT NULL DEFAULT 0,
        payment_count INTEGER NOT NULL DEFAULT 0,
        total_spend_usd REAL NOT NULL DEFAULT 0.0,
        UNIQUE(tenant_id, month)
    );

    CREATE INDEX IF NOT EXISTS idx_usage_tenant ON usage(tenant_id);
"""

_SCHEMA_POSTGRES = _SCHEMA_SQLITE.replace(
    "INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY"
)
