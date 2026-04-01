"""
Haldir Database — SQLite persistence layer for Gate, Vault, and Watch.

Single database file, WAL mode for concurrent reads.
"""

import sqlite3
import os
import time

DEFAULT_DB_PATH = os.environ.get("HALDIR_DB_PATH", "haldir.db")


def get_db(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH):
    """Create all tables if they don't exist."""
    conn = get_db(db_path)
    conn.executescript("""
        -- Gate: agent policies
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            default_scopes TEXT NOT NULL DEFAULT '["read","browse"]',
            max_spend REAL NOT NULL DEFAULT 0.0,
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL
        );

        -- Gate: sessions
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            scopes TEXT NOT NULL DEFAULT '[]',
            spend_limit REAL NOT NULL DEFAULT 0.0,
            spent REAL NOT NULL DEFAULT 0.0,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL DEFAULT 0.0,
            revoked INTEGER NOT NULL DEFAULT 0,
            metadata TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

        -- Vault: encrypted secrets
        CREATE TABLE IF NOT EXISTS secrets (
            name TEXT PRIMARY KEY,
            encrypted_value BLOB NOT NULL,
            scope_required TEXT NOT NULL DEFAULT 'read',
            created_at REAL NOT NULL,
            last_accessed REAL NOT NULL DEFAULT 0.0,
            access_count INTEGER NOT NULL DEFAULT 0,
            metadata TEXT NOT NULL DEFAULT '{}'
        );

        -- Vault: payment authorizations
        CREATE TABLE IF NOT EXISTS payments (
            authorization_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL DEFAULT 'USD',
            description TEXT NOT NULL DEFAULT '',
            remaining_budget REAL NOT NULL DEFAULT 0.0,
            timestamp REAL NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        );

        CREATE INDEX IF NOT EXISTS idx_payments_session ON payments(session_id);
        CREATE INDEX IF NOT EXISTS idx_payments_agent ON payments(agent_id);

        -- Watch: audit log
        CREATE TABLE IF NOT EXISTS audit_log (
            entry_id TEXT PRIMARY KEY,
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
        CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_flagged ON audit_log(flagged);

        -- Watch: anomaly rules
        CREATE TABLE IF NOT EXISTS anomaly_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_type TEXT NOT NULL,
            threshold REAL NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        );
    """)
    conn.commit()
    conn.close()
