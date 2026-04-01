"""
Haldir Gate — Core identity and permission engine with SQLite persistence.
"""

import json
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum


class Permission(Enum):
    READ = "read"
    WRITE = "write"
    SPEND = "spend"
    EXECUTE = "execute"
    BROWSE = "browse"
    SEND = "send"
    DELETE = "delete"
    ADMIN = "admin"


@dataclass
class Session:
    session_id: str
    agent_id: str
    scopes: list[str]
    spend_limit: float = 0.0
    spent: float = 0.0
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    revoked: bool = False
    metadata: dict = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        if self.revoked:
            return False
        if self.expires_at > 0 and time.time() > self.expires_at:
            return False
        return True

    @property
    def remaining_budget(self) -> float:
        return max(0.0, self.spend_limit - self.spent)

    def has_permission(self, scope: str) -> bool:
        if "admin" in self.scopes:
            return True
        base_scope = scope.split(":")[0]
        return base_scope in self.scopes or scope in self.scopes

    def authorize_spend(self, amount: float) -> bool:
        if not self.has_permission("spend"):
            return False
        if self.spend_limit > 0 and (self.spent + amount) > self.spend_limit:
            return False
        return True

    def record_spend(self, amount: float):
        self.spent += amount


class Gate:
    """Central identity and permission authority with persistent storage."""

    def __init__(self, api_key: str | None = None, db_path: str | None = None):
        self.api_key = api_key
        self._db_path = db_path
        # In-memory fallback when no DB
        self._sessions: dict[str, Session] = {}
        self._agent_policies: dict[str, dict] = {}

    def _get_db(self):
        if not self._db_path:
            return None
        from haldir_db import get_db
        return get_db(self._db_path)

    def register_agent(self, agent_id: str, default_scopes: list[str] | None = None,
                       max_spend: float = 0.0, metadata: dict | None = None):
        scopes = default_scopes or ["read", "browse"]
        policy = {
            "default_scopes": scopes,
            "max_spend": max_spend,
            "metadata": metadata or {},
        }
        self._agent_policies[agent_id] = policy

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT OR REPLACE INTO agents (agent_id, default_scopes, max_spend, metadata, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (agent_id, json.dumps(scopes), max_spend, json.dumps(metadata or {}), time.time())
            )
            conn.commit()
            conn.close()

    def create_session(self, agent_id: str, scopes: list[str] | None = None,
                       ttl: int = 3600, spend_limit: float | None = None) -> Session:
        policy = self._agent_policies.get(agent_id, {})
        effective_scopes = scopes or policy.get("default_scopes", ["read"])

        effective_spend = spend_limit
        if effective_spend is None:
            for s in effective_scopes:
                if s.startswith("spend:"):
                    try:
                        effective_spend = float(s.split(":")[1])
                    except (ValueError, IndexError):
                        pass
        if effective_spend is None:
            effective_spend = policy.get("max_spend", 0.0)

        session = Session(
            session_id=f"ses_{secrets.token_urlsafe(24)}",
            agent_id=agent_id,
            scopes=[s.split(":")[0] for s in effective_scopes],
            spend_limit=effective_spend,
            expires_at=time.time() + ttl if ttl > 0 else 0,
        )
        self._sessions[session.session_id] = session

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT INTO sessions (session_id, agent_id, scopes, spend_limit, spent, created_at, expires_at, revoked) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (session.session_id, session.agent_id, json.dumps(session.scopes),
                 session.spend_limit, 0.0, session.created_at, session.expires_at, 0)
            )
            conn.commit()
            conn.close()

        return session

    def get_session(self, session_id: str) -> Session | None:
        # If we have a DB, always check it for fresh revocation status
        conn = self._get_db()
        if conn:
            row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            conn.close()
            if not row or int(row["revoked"]):
                self._sessions.pop(session_id, None)
                return None
            session = Session(
                session_id=row["session_id"],
                agent_id=row["agent_id"],
                scopes=json.loads(row["scopes"]),
                spend_limit=row["spend_limit"],
                spent=row["spent"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                revoked=bool(int(row["revoked"])),
            )
            if session.is_valid:
                self._sessions[session_id] = session
                return session
            return None

        # In-memory fallback
        session = self._sessions.get(session_id)
        if session and session.is_valid:
            return session

        # Check DB
        conn = self._get_db()
        if conn:
            row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            conn.close()
            if row and not int(row["revoked"]):
                session = Session(
                    session_id=row["session_id"],
                    agent_id=row["agent_id"],
                    scopes=json.loads(row["scopes"]),
                    spend_limit=row["spend_limit"],
                    spent=row["spent"],
                    created_at=row["created_at"],
                    expires_at=row["expires_at"],
                    revoked=bool(row["revoked"]),
                )
                if session.is_valid:
                    self._sessions[session_id] = session
                    return session
        return None

    def check_permission(self, session_id: str, scope: str) -> bool:
        session = self.get_session(session_id)
        if not session:
            return False
        return session.has_permission(scope)

    def authorize_spend(self, session_id: str, amount: float) -> bool:
        session = self.get_session(session_id)
        if not session:
            return False
        return session.authorize_spend(amount)

    def record_spend(self, session_id: str, amount: float) -> bool:
        session = self.get_session(session_id)
        if not session or not session.authorize_spend(amount):
            return False
        session.record_spend(amount)

        conn = self._get_db()
        if conn:
            conn.execute("UPDATE sessions SET spent = ? WHERE session_id = ?",
                         (session.spent, session_id))
            conn.commit()
            conn.close()
        return True

    def revoke_session(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if session:
            session.revoked = True

        conn = self._get_db()
        if conn:
            conn.execute("UPDATE sessions SET revoked = 1 WHERE session_id = ?", (session_id,))
            conn.commit()
            conn.close()
            return True
        return session is not None

    def list_sessions(self, agent_id: str | None = None) -> list[Session]:
        sessions = [s for s in self._sessions.values() if s.is_valid]
        if agent_id:
            sessions = [s for s in sessions if s.agent_id == agent_id]
        return sessions
