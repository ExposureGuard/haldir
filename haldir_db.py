"""
Haldir Database — Multi-tenant persistence layer.

Supports SQLite (dev/small deployments) and PostgreSQL (production).
Every table has a tenant_id column for data isolation between API keys.

Set DATABASE_URL for Postgres: postgresql://user:pass@host/haldir
Otherwise falls back to SQLite at HALDIR_DB_PATH.

Tuning surface (env vars):

  HALDIR_PG_POOL_MIN     Floor for the Postgres connection pool.
                         Defaults to 2 so the second request never
                         pays cold-connect latency.
  HALDIR_PG_POOL_MAX     Ceiling. Defaults to 20. Every gunicorn
                         worker shares this pool, so size it to
                         workers × typical concurrency per worker
                         (leave headroom for Postgres' max_connections).

SQLite pragma choices (applied on every connection open):

  journal_mode=WAL       Readers don't block writers. Required.
  synchronous=NORMAL     Safe with WAL. ~5-10x faster write commit
                         than FULL; at most loses the last few
                         committed txns on OS crash.
  temp_store=MEMORY      Sorts and temp tables stay in RAM. Meaningful
                         for the audit chain's ORDER BY hash lookups.
  mmap_size=256 MiB      Memory-map the DB file so page reads come
                         out of the OS page cache without a syscall.
                         The single biggest knob for concurrent-read
                         p99 latency under load.
  foreign_keys=ON        Enforce FK constraints (off by default).
  busy_timeout=5000      Wait 5 s for the writer lock before raising.
"""

import os
import re
import sqlite3

from haldir_logging import get_logger

logger = get_logger(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
DEFAULT_DB_PATH = os.environ.get("HALDIR_DB_PATH", "/data/haldir.db" if os.path.isdir("/data") else "haldir.db")

# Pool bounds. Callers that need to override per-process (tests) can
# also set _pg_pool_min / _pg_pool_max directly — they're read at
# pool-construction time.
_pg_pool_min = int(os.environ.get("HALDIR_PG_POOL_MIN", "2"))
_pg_pool_max = int(os.environ.get("HALDIR_PG_POOL_MAX", "20"))
_pg_pool = None

# SQLite pragmas applied on every connection open. Pulled out as a
# constant so tests can assert against the exact set.
_SQLITE_PRAGMAS: tuple[tuple[str, str], ...] = (
    ("journal_mode",  "WAL"),
    ("synchronous",   "NORMAL"),
    ("temp_store",    "MEMORY"),
    ("mmap_size",     "268435456"),  # 256 MiB
    ("foreign_keys",  "ON"),
    ("busy_timeout",  "5000"),
)


def _is_postgres() -> bool:
    return DATABASE_URL.startswith("postgres")


def get_db(db_path: str = DEFAULT_DB_PATH):
    """Get a database connection. Returns SQLite or Postgres depending on config."""
    if _is_postgres():
        return _get_pg()
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    for name, value in _SQLITE_PRAGMAS:
        conn.execute(f"PRAGMA {name}={value}")
    return conn


def _get_pg():
    """Get a PostgreSQL connection from the pool.

    Pool size is configurable via HALDIR_PG_POOL_MIN / MAX. On
    exhaustion we drain + rebuild, which drops in-flight connections
    but gets us back to a healthy state deterministically — preferable
    to blocking indefinitely while callers stack up."""
    global _pg_pool
    import psycopg2
    import psycopg2.extras
    import psycopg2.pool

    if _pg_pool is None:
        _pg_pool = psycopg2.pool.ThreadedConnectionPool(
            _pg_pool_min, _pg_pool_max, DATABASE_URL,
        )

    try:
        conn = _pg_pool.getconn()
        conn.autocommit = False
        return PgConnectionWrapper(conn, _pg_pool)
    except psycopg2.pool.PoolError:
        # Pool exhausted — reset it.
        try:
            _pg_pool.closeall()
        except Exception:
            pass
        _pg_pool = psycopg2.pool.ThreadedConnectionPool(
            _pg_pool_min, _pg_pool_max, DATABASE_URL,
        )
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
        """Execute multiple SQL statements (for schema creation).

        Comment handling: SQL line comments (`--`) are stripped BEFORE
        the `;` split, because comment text can legitimately contain
        semicolons (e.g. "one row per webhook;") and a naive split
        would carve a comment in half and try to execute the
        right-hand fragment as SQL. Tested against migration 002
        which has exactly this case in its leading comment block."""
        sql = _sqlite_to_pg(sql)
        # Strip SQL line comments first so semicolons inside comments
        # don't fragment the statement list.
        cleaned_lines = []
        for line in sql.split("\n"):
            stripped = line.lstrip()
            if stripped.startswith("--"):
                continue
            # Also handle inline trailing comments: `CREATE TABLE ... ; -- note`
            if "--" in line:
                idx = line.find("--")
                line = line[:idx]
            cleaned_lines.append(line)
        clean_sql = "\n".join(cleaned_lines)

        statements = [s.strip() for s in clean_sql.split(";") if s.strip()]
        cursor = self._conn.cursor()
        for stmt in statements:
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

    @property
    def rowcount(self):
        """sqlite3 cursors expose this; callers use it to tell whether a write
        changed anything.

        vault.delete_secret reads it to report whether a secret was removed,
        and haldir_sth_log.record uses it to decide whether a Signed Tree Head
        was newly recorded. Without it both raised AttributeError, and because
        record() swallows exceptions by design the STH log failed *silently* —
        the anti-equivocation layer recorded nothing on Postgres at all.
        """
        return self._cursor.rowcount

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
        scopes TEXT NOT NULL DEFAULT '["*"]',
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
        metadata TEXT NOT NULL DEFAULT '{}',
        parent_session_id TEXT NOT NULL DEFAULT ''
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);
    -- idx_sessions_parent is deliberately NOT created here. This script runs
    -- before the ADD COLUMN that gives legacy databases parent_session_id, and
    -- SQLite aborts the whole script on a reference to an unknown column.
    -- Both init paths create it after their ALTER TABLE instead.

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
        entry_hash TEXT NOT NULL DEFAULT '',
        seq INTEGER NOT NULL DEFAULT 0
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


def _migrate_audit_seq(conn):
    """Give every audit row a per-tenant sequence number, then make it unique.

    The chain's tail was selected with `ORDER BY timestamp DESC LIMIT 1` and
    no tiebreak, and nothing stopped two rows from naming the same
    predecessor. Under concurrency that forks the log: eight simultaneous
    appends produced eight entries, of which exactly one was reachable by
    walking from the head. The rest were on branches, and a log that is not a
    single chain proves nothing about its own history.

    A per-tenant sequence makes "the tail" a fact rather than a guess, and
    the unique index makes a fork impossible to commit — a racing writer
    collides and retries instead of silently branching.

    Runs on both backends: the correlated subquery and the partial-free
    unique index are portable, and `ADD COLUMN` is wrapped because neither
    engine offers `IF NOT EXISTS` for it.
    """
    try:
        conn.execute("ALTER TABLE audit_log ADD COLUMN seq INTEGER NOT NULL DEFAULT 0")
    except Exception:
        pass  # column already exists

    try:
        pending = conn.execute("SELECT 1 FROM audit_log WHERE seq = 0 LIMIT 1").fetchone()
    except Exception:
        return  # table missing; nothing to migrate

    # Backfill only when something needs it, so a large log is not renumbered
    # on every boot. The index below is created either way — skipping it on a
    # fresh database (where the table is empty, so *nothing* has seq = 0)
    # would leave every new deployment with an unguarded chain, which is
    # exactly the bug this function exists to close.
    if pending:
        # (timestamp, entry_id) is a total order: entry_id is the primary
        # key, so no two rows tie. Counting predecessors yields 1..N.
        conn.execute(
            "UPDATE audit_log SET seq = ("
            "  SELECT COUNT(*) FROM audit_log AS a2"
            "  WHERE a2.tenant_id = audit_log.tenant_id"
            "    AND (a2.timestamp < audit_log.timestamp"
            "         OR (a2.timestamp = audit_log.timestamp"
            "             AND a2.entry_id <= audit_log.entry_id))"
            ") WHERE seq = 0"
        )
    try:
        # Partial on seq > 0. Appends through Watch.log_action always number
        # their row (the tail's seq plus one), so the guard covers every
        # entry that joins the chain — while leaving rows written raw, with
        # seq left at its 0 default, free of a constraint they were never
        # part of. The tamper demo rewrites history on purpose, and test
        # fixtures plant rows with hand-picked hashes; neither should have
        # to fabricate a sequence number to do it.
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_seq "
            "ON audit_log(tenant_id, seq) WHERE seq > 0"
        )
    except Exception:
        pass  # pre-existing duplicates; appends still retry, index is a backstop


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
    # Idempotent column-add for legacy api_keys tables that pre-date
    # the scopes feature. Mirrors the same pattern haldir_watch/
    # webhooks.py uses for its `secret` column.
    try:
        conn.execute(
            "ALTER TABLE api_keys ADD COLUMN scopes TEXT NOT NULL DEFAULT '[\"*\"]'"
        )
    except Exception:
        pass  # column already exists; fine
    # Agent delegation hierarchy. `CREATE TABLE IF NOT EXISTS` above only
    # shapes fresh databases, so pre-existing installs need the column added
    # in place. SQLite has no `ADD COLUMN IF NOT EXISTS`, hence try/except.
    try:
        conn.execute(
            "ALTER TABLE sessions ADD COLUMN parent_session_id TEXT NOT NULL DEFAULT ''"
        )
    except Exception:
        pass  # column already exists; fine
    # Must follow the ALTER above — the column has to exist before it can be
    # indexed, and `CREATE INDEX IF NOT EXISTS` is not forgiving about that.
    try:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_parent ON sessions(parent_session_id)"
        )
    except Exception:
        pass  # index already exists; fine
    _migrate_audit_seq(conn)
    # Compliance scheduler table (migration 004). Belt-and-suspenders
    # for environments that don't run HALDIR_AUTO_MIGRATE.
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS compliance_schedules (
                schedule_id TEXT PRIMARY KEY,
                tenant_id   TEXT NOT NULL,
                name        TEXT NOT NULL DEFAULT '',
                cadence     TEXT NOT NULL,
                delivery    TEXT NOT NULL,
                active      INTEGER NOT NULL DEFAULT 1,
                created_at  REAL NOT NULL,
                last_run_at REAL NOT NULL DEFAULT 0,
                last_status TEXT NOT NULL DEFAULT '',
                last_error  TEXT NOT NULL DEFAULT '',
                run_count   INTEGER NOT NULL DEFAULT 0,
                fail_count  INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_schedules_tenant ON compliance_schedules(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_schedules_due    ON compliance_schedules(active, last_run_at);
        """)
    except Exception:
        pass
    # Audit retention + prune checkpoints (migration 008). Same
    # belt-and-suspenders reasoning as the table above.
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS audit_retention (
                tenant_id   TEXT PRIMARY KEY,
                retain_days INTEGER NOT NULL DEFAULT 0,
                updated_at  REAL NOT NULL,
                updated_by  TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS audit_checkpoints (
                checkpoint_id          TEXT PRIMARY KEY,
                tenant_id              TEXT NOT NULL,
                pruned_before          REAL NOT NULL,
                last_pruned_entry_hash TEXT NOT NULL DEFAULT '',
                entries_deleted        INTEGER NOT NULL DEFAULT 0,
                tree_size              INTEGER NOT NULL DEFAULT 0,
                root_hash              TEXT NOT NULL DEFAULT '',
                algorithm              TEXT NOT NULL DEFAULT '',
                signature              TEXT NOT NULL DEFAULT '',
                signed_at              REAL NOT NULL DEFAULT 0,
                key_id                 TEXT NOT NULL DEFAULT '',
                public_key             TEXT NOT NULL DEFAULT '',
                created_at             REAL NOT NULL,
                created_by             TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoints_tenant
                ON audit_checkpoints(tenant_id, created_at DESC);
        """)
    except Exception:
        pass
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
                logger.warning("DB init warning: %s", e)

    # Idempotent column-add for legacy api_keys tables that pre-date
    # the scopes feature. Postgres supports ADD COLUMN IF NOT EXISTS
    # since 9.6 — covers every Postgres version Haldir's SDK clients
    # would realistically point a tenant DB at.
    try:
        cursor.execute(
            "ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scopes "
            "TEXT NOT NULL DEFAULT '[\"*\"]'"
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.warning("api_keys.scopes ALTER skipped: %s", e)

    # Idempotent column-add for agent delegation hierarchy, mirroring the
    # api_keys.scopes block above. The CREATE TABLE in _SCHEMA only shapes
    # fresh databases, so existing deployments need the column added here.
    try:
        cursor.execute(
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS parent_session_id "
            "TEXT NOT NULL DEFAULT ''"
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.warning("sessions.parent_session_id ALTER skipped: %s", e)

    # Index for the hierarchy column. Postgres tolerates the out-of-order
    # CREATE INDEX in _SCHEMA (the statement just warns and is skipped), but
    # that would leave the index absent for the life of the process, so it is
    # created explicitly here, after the ALTER above.
    try:
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_parent ON sessions(parent_session_id)"
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.warning("idx_sessions_parent CREATE skipped: %s", e)

    # Chain sequencing for audit_log — see _migrate_audit_seq. Postgres
    # supports ADD COLUMN IF NOT EXISTS, but the helper's try/except covers
    # the non-IF-NOT-EXISTS path too, so the same code serves both backends.
    try:
        _migrate_audit_seq(conn)
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.warning("audit_log seq migration skipped: %s", e)

    # Migration 002 (webhook_deliveries table) is normally applied by
    # haldir_migrate at boot. Belt-and-suspenders: emit it here too so
    # an existing Postgres deployment that skips HALDIR_AUTO_MIGRATE
    # still ends up with the deliveries table.
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                delivery_id      TEXT    PRIMARY KEY,
                event_id         TEXT    NOT NULL,
                tenant_id        TEXT    NOT NULL DEFAULT '',
                webhook_url      TEXT    NOT NULL,
                event_type       TEXT    NOT NULL,
                attempt          INTEGER NOT NULL DEFAULT 1,
                status_code      INTEGER NOT NULL DEFAULT 0,
                response_excerpt TEXT    NOT NULL DEFAULT '',
                error            TEXT    NOT NULL DEFAULT '',
                duration_ms      INTEGER NOT NULL DEFAULT 0,
                created_at       DOUBLE PRECISION NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_tenant   ON webhook_deliveries(tenant_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_event    ON webhook_deliveries(event_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_created  ON webhook_deliveries(created_at)")
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.warning("webhook_deliveries init warning: %s", e)

    # Migration 004 (compliance_schedules) — same belt-and-suspenders
    # pattern. Lets the scheduler thread persist its state on Postgres
    # deployments that skip the migration runner.
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compliance_schedules (
                schedule_id TEXT PRIMARY KEY,
                tenant_id   TEXT NOT NULL,
                name        TEXT NOT NULL DEFAULT '',
                cadence     TEXT NOT NULL,
                delivery    TEXT NOT NULL,
                active      INTEGER NOT NULL DEFAULT 1,
                created_at  DOUBLE PRECISION NOT NULL,
                last_run_at DOUBLE PRECISION NOT NULL DEFAULT 0,
                last_status TEXT NOT NULL DEFAULT '',
                last_error  TEXT NOT NULL DEFAULT '',
                run_count   INTEGER NOT NULL DEFAULT 0,
                fail_count  INTEGER NOT NULL DEFAULT 0
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_schedules_tenant ON compliance_schedules(tenant_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_schedules_due    ON compliance_schedules(active, last_run_at)")
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.warning("compliance_schedules init warning: %s", e)

    conn.close()
