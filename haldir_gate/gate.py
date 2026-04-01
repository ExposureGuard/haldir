"""
Haldir Gate — Core identity and permission engine.

Sessions are short-lived, scoped tokens that agents use to prove identity
and authorization for every action they take.
"""

import secrets
import time
from dataclasses import dataclass, field
from enum import Enum


class Permission(Enum):
    READ = "read"                    # Read data from tools
    WRITE = "write"                  # Write/modify data
    SPEND = "spend"                  # Authorize payments
    EXECUTE = "execute"              # Run commands/code
    BROWSE = "browse"                # Visit URLs
    SEND = "send"                    # Send emails/messages
    DELETE = "delete"                # Destructive operations
    ADMIN = "admin"                  # Full access


@dataclass
class Session:
    session_id: str
    agent_id: str
    scopes: list[str]
    spend_limit: float = 0.0        # Max spend in USD for this session
    spent: float = 0.0              # Running total spent
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0         # 0 = no expiry
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
        # Handle parameterized scopes like "spend:50"
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
    """
    Central identity and permission authority.

    Every agent interaction starts with Gate.create_session().
    Every tool call checks Gate.check_permission().
    """

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key
        self._sessions: dict[str, Session] = {}
        self._agent_policies: dict[str, dict] = {}

    def register_agent(self, agent_id: str, default_scopes: list[str] | None = None,
                       max_spend: float = 0.0, metadata: dict | None = None):
        """Register an agent with default policies."""
        self._agent_policies[agent_id] = {
            "default_scopes": default_scopes or ["read", "browse"],
            "max_spend": max_spend,
            "metadata": metadata or {},
        }

    def create_session(self, agent_id: str, scopes: list[str] | None = None,
                       ttl: int = 3600, spend_limit: float | None = None) -> Session:
        """Create a scoped session for an agent."""
        policy = self._agent_policies.get(agent_id, {})
        effective_scopes = scopes or policy.get("default_scopes", ["read"])

        # Parse spend limit from scopes like "spend:50"
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
        return session

    def get_session(self, session_id: str) -> Session | None:
        session = self._sessions.get(session_id)
        if session and session.is_valid:
            return session
        return None

    def check_permission(self, session_id: str, scope: str) -> bool:
        """Check if a session has a specific permission."""
        session = self.get_session(session_id)
        if not session:
            return False
        return session.has_permission(scope)

    def authorize_spend(self, session_id: str, amount: float) -> bool:
        """Check if a session can spend a given amount."""
        session = self.get_session(session_id)
        if not session:
            return False
        return session.authorize_spend(amount)

    def record_spend(self, session_id: str, amount: float) -> bool:
        """Record a spend against a session's budget."""
        session = self.get_session(session_id)
        if not session:
            return False
        if not session.authorize_spend(amount):
            return False
        session.record_spend(amount)
        return True

    def revoke_session(self, session_id: str) -> bool:
        """Immediately revoke a session."""
        session = self._sessions.get(session_id)
        if session:
            session.revoked = True
            return True
        return False

    def list_sessions(self, agent_id: str | None = None) -> list[Session]:
        """List active sessions, optionally filtered by agent."""
        sessions = [s for s in self._sessions.values() if s.is_valid]
        if agent_id:
            sessions = [s for s in sessions if s.agent_id == agent_id]
        return sessions
