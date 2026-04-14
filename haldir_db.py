"""
Haldir Database — Multi-tenant persistence layer.

Supports SQLite (dev/small deployments) and PostgreSQL (production).
Every table has a tenant_id column for data isolation between API keys.

Set DATABASE_URL for Postgres: postgresql://user:pass@host/haldir
Otherwise falls back to SQLite at HALDIR_DB_PATH.
"""

import os
import re
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
    import psycopg2.pool

    if _pg_pool is None:
        _pg_pool = psycopg2.pool.ThreadedConnectionPool(1, 20, DATABASE_URL)

    try:
        conn = _pg_pool.getconn()
        conn.autocommit = False
        return PgConnectionWrapper(conn, _pg_pool)
    except psycopg2.pool.PoolError:
        # Pool exhausted — reset it
        try:
            _pg_pool.closeall()
        except Exception:
            pass
        _pg_pool = psycopg2.pool.ThreadedConnectionPool(1, 20, DATABASE_URL)
        conn = _pg_pool.getconn()
        conn.autocommit = False
        return PgConnectionWrapper(conn, _pg_pool)


def _sqlite_to_pg(sql):
    """Convert SQLite SQL syntax to PostgreSQL."""
    sql = sql.replace("?", "%s")
    sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    # SQLite's INSERT OR REPLACE → Postgres ON CONFLICT DO UPDATE
    # Match known tables with composite PKs
    if "INSERT OR REPLACE INTO agents" in sql:
        sql = sql.replace("INSERT OR REPLACE INTO agents", "INSERT INTO agents")
        sql = sql.rstrip().rstrip(")") + ") ON CONFLICT (agent_id, tenant_id) DO UPDATE SET default_scopes=EXCLUDED.default_scopes, max_spend=EXCLUDED.max_spend, metadata=EXCLUDED.metadata, created_at=EXCLUDED.created_at"
    elif "INSERT OR REPLACE INTO secrets" in sql:
        sql = sql.replace("INSERT OR REPLACE INTO secrets", "INSERT INTO secrets")
        sql = sql.rstrip().rstrip(")") + ") ON CONFLICT (name, tenant_id) DO UPDATE SET encrypted_value=EXCLUDED.encrypted_value, scope_required=EXCLUDED.scope_required, created_at=EXCLUDED.created_at, metadata=EXCLUDED.metadata"
    else:
        sql = re.sub(
            r'INSERT OR REPLACE INTO (\w+)',
            r'INSERT INTO \1',
            sql
        )
    return sql


class PgConnectionWrapper:
    """Wraps psycopg2 connection to match sqlite3.Connection interface."""

    def __init__(self, conn, pool):
        self._conn = conn
        self._pool = pool
        self._last_cursor = None

    def execute(self, sql, params=None):
        import psycopg2.extras
        sql = _sqlite_to_pg(sql)
        cursor = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cursor.execute(sql, params or ())
        except Exception as e:
            self._conn.rollback()
            raise
        self._last_cursor = cursor
        return PgCursorWrapper(cursor)

    def executescript(self, sql):
        """Execute multiple SQL statements (for schema creation)."""
        sql = _sqlite_to_pg(sql)
        # Split on semicolons but skip empty statements
        statements = [s.strip() for s in sql.split(";") if s.strip()]
        cursor = self._conn.cursor()
        for stmt in statements:
            if stmt:
                try:
                    cursor.execute(stmt)
                except Exception as e:
                    # Skip errors for IF NOT EXISTS statements
                    if "already exists" in str(e):
                        self._conn.rollback()
                        continue
                    self._conn.rollback()
                    raise
        self._conn.commit()

    def commit(self):
        self._conn.commit()

    def close(self):
        try:
            self._pool.putconn(self._conn)
        except Exception:
            pass

    @property
    def total_changes(self):
        if self._last_cursor:
            return self._last_cursor.rowcount
        return 0


class PgCursorWrapper:
    """Wraps psycopg2 cursor to match sqlite3 cursor interface."""

    def __init__(self, cursor):
        self._cursor = cursor

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        # RealDictCursor returns dicts — wrap to support both dict and index access
        return PgRow(row)

    def fetchall(self):
        rows = self._cursor.fetchall()
        return [PgRow(r) for r in rows]

    def __iter__(self):
        return iter(self.fetchall())


class PgRow:
    """Wraps a psycopg2 RealDictRow to support both dict-style and index access like sqlite3.Row."""

    def __init__(self, data):
        self._data = dict(data)
        self._keys = list(self._data.keys())

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._data[self._keys[key]]
        return self._data[key]

    def get(self, key, default=None):
        return self._data.get(key, default)

    def keys(self):
        return self._keys

    def __contains__(self, key):
        return key in self._data

    def __repr__(self):
        return repr(self._data)


# ── Schema ──

_SCHEMA = """
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

    CREATE TABLE IF NOT EXISTS webhooks (
        id SERIAL PRIMARY KEY,
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
"""

# SQLite version uses BLOB instead of BYTEA and INTEGER PRIMARY KEY AUTOINCREMENT instead of SERIAL
_SCHEMA_SQLITE = _SCHEMA.replace("BYTEA", "BLOB").replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")


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
    # Execute each statement separately
    statements = [s.strip() for s in _SCHEMA.split(";") if s.strip()]
    for stmt in statements:
        try:
            cursor.execute(stmt)
            conn.commit()
        except Exception as e:
            conn.rollback()
            if "already exists" not in str(e):
                print(f"[!] DB init warning: {e}")
    conn.close()
