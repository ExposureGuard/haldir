"""
Haldir Gate — Core identity and permission engine with persistent storage.
"""

import json
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from haldir_tracing import traced_span


# Ceiling on agent→subagent nesting. A runaway fan-out (an agent that spawns
# an agent that spawns an agent…) is indistinguishable from a fork bomb at the
# governance layer, so the chain is bounded here rather than left to the caller.
# Set generously: legitimate orchestrators nest a handful of levels, not eight.
MAX_DELEGATION_DEPTH = 8


class DelegationError(ValueError):
    """A parent/child session link would be invalid (missing, cross-tenant, too deep)."""


def reserve_spend(conn: Any, session_id: str, tenant_id: str, amount: float,
                  now: float | None = None) -> bool:
    """Atomically reserve `amount` against a session's budget.

    One statement, and that is the entire point. The check and the increment
    used to be two — `authorize_spend()` then `record_spend()` then
    `UPDATE sessions SET spent = ?` — which made the budget advisory rather
    than enforced:

      * `Gate.record_spend` reloads the session from the database on every
        call, so every concurrent caller read `spent = 0` and every one
        passed the check.
      * The write then set `spent` to that caller's own idea of the total,
        so the last writer won and the rest vanished. Ten simultaneous $20
        authorizations against a $100 cap all succeeded, and the row ended
        up recording $20 of the $200 handed out.

    Doing the arithmetic in the UPDATE means the database evaluates the limit
    against the committed value, and `rowcount` reports whether the
    reservation happened. It is also the only formulation that stays correct
    across processes and replicas without a distributed lock — a Python lock
    would not have helped the second uvicorn worker.

    Returns True if the reservation succeeded, False if it would have
    exceeded the cap, the session is revoked, or it has expired. `spend_limit`
    of 0 means unlimited, matching `Session.authorize_spend`.
    """
    if amount < 0:
        # Refunds are a separate operation; silently accepting a negative
        # reservation here would let a caller raise its own cap.
        raise ValueError("amount must be non-negative")

    cur = conn.execute(
        "UPDATE sessions SET spent = spent + ? "
        "WHERE session_id = ? AND tenant_id = ? "
        "  AND revoked = 0 "
        "  AND (expires_at = 0 OR expires_at > ?) "
        "  AND (spend_limit <= 0 OR spent + ? <= spend_limit)",
        (amount, session_id, tenant_id, now if now is not None else time.time(), amount),
    )
    return bool(cur.rowcount == 1)


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
    tenant_id: str = ""
    # Empty string means this session is a delegation root. Kept as '' rather
    # than None to match the column sentinel used across the schema.
    parent_session_id: str = ""

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

    def record_spend(self, amount: float) -> None:
        self.spent += amount


class Gate:
    """Central identity and permission authority with persistent storage."""

    def __init__(self, api_key: str | None = None, db_path: str | None = None):
        self.api_key = api_key
        self._db_path = db_path
        # In-memory fallback when no DB
        self._sessions: dict[str, Session] = {}
        self._agent_policies: dict[str, dict] = {}

    def _get_db(self) -> Any:
        if not self._db_path:
            return None
        from haldir_db import get_db
        return get_db(self._db_path)

    def register_agent(self, agent_id: str, default_scopes: list[str] | None = None,
                       max_spend: float = 0.0, metadata: dict | None = None,
                       tenant_id: str = "") -> None:
        scopes = default_scopes or ["read", "browse"]
        policy = {
            "default_scopes": scopes,
            "max_spend": max_spend,
            "metadata": metadata or {},
        }
        self._agent_policies[f"{tenant_id}:{agent_id}"] = policy

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT OR REPLACE INTO agents (agent_id, tenant_id, default_scopes, max_spend, metadata, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (agent_id, tenant_id, json.dumps(scopes), max_spend, json.dumps(metadata or {}), time.time())
            )
            conn.commit()
            conn.close()

    @staticmethod
    def _row_to_session(row: Any) -> Session:
        """Map a sessions row to a Session.

        Columns introduced after the initial schema are absent on databases
        that predate them, so optionally-added fields are read defensively.
        """
        keys = row.keys()
        return Session(
            session_id=row["session_id"],
            agent_id=row["agent_id"],
            scopes=json.loads(row["scopes"]),
            spend_limit=row["spend_limit"],
            spent=row["spent"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            revoked=bool(int(row["revoked"])),
            tenant_id=row["tenant_id"],
            parent_session_id=(row["parent_session_id"] or "")
            if "parent_session_id" in keys else "",
        )

    def _raw_parent(self, session_id: str, tenant_id: str) -> str | None:
        """Parent link for a session, ignoring revoked/expired state.

        Ancestry walks must stay stable even once an ancestor has lapsed, so
        this deliberately bypasses get_session's validity filter. Returns None
        when the session is not visible in this tenant.
        """
        conn = self._get_db()
        if conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ? AND tenant_id = ?",
                (session_id, tenant_id)
            ).fetchone()
            conn.close()
            if not row:
                return None
            # Tolerate a database that predates the hierarchy column.
            if "parent_session_id" not in row.keys():
                return ""
            return row["parent_session_id"] or ""
        session = self._sessions.get(session_id)
        if session and session.tenant_id == tenant_id:
            return session.parent_session_id
        return None

    def delegation_depth(self, session_id: str, tenant_id: str = "") -> int:
        """Depth of a session in the delegation chain. Roots are depth 0."""
        depth = 0
        seen = {session_id}
        current = session_id
        while True:
            parent = self._raw_parent(current, tenant_id)
            if not parent or parent in seen:
                # No parent, or stored data describing a cycle — stop rather
                # than spin. Either way the reported chain is bounded.
                return depth
            seen.add(parent)
            depth += 1
            current = parent

    @traced_span("haldir.gate.create_session")
    def create_session(self, agent_id: str, scopes: list[str] | None = None,
                       ttl: int = 3600, spend_limit: float | None = None,
                       tenant_id: str = "", parent_session_id: str = "") -> Session:
        # Validate the delegation link before minting anything, so a rejected
        # spawn leaves no partial state behind.
        if parent_session_id:
            parent = self.get_session(parent_session_id, tenant_id=tenant_id)
            if not parent:
                raise DelegationError(
                    f"parent session {parent_session_id!r} does not exist in this tenant"
                )
            depth = self.delegation_depth(parent_session_id, tenant_id=tenant_id) + 1
            if depth > MAX_DELEGATION_DEPTH:
                raise DelegationError(
                    f"delegation depth {depth} exceeds the maximum of {MAX_DELEGATION_DEPTH}"
                )

        policy = self._agent_policies.get(f"{tenant_id}:{agent_id}", {})
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
            tenant_id=tenant_id,
            parent_session_id=parent_session_id,
        )
        self._sessions[session.session_id] = session

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT INTO sessions (session_id, tenant_id, agent_id, scopes, spend_limit, spent, created_at, expires_at, revoked, parent_session_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (session.session_id, tenant_id, session.agent_id, json.dumps(session.scopes),
                 session.spend_limit, 0.0, session.created_at, session.expires_at, 0,
                 parent_session_id)
            )
            conn.commit()
            conn.close()

        return session

    def get_session(self, session_id: str, tenant_id: str = "") -> Session | None:
        conn = self._get_db()
        if conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ? AND tenant_id = ?",
                (session_id, tenant_id)
            ).fetchone()
            conn.close()
            if not row or int(row["revoked"]):
                self._sessions.pop(session_id, None)
                return None
            session = self._row_to_session(row)
            if session.is_valid:
                self._sessions[session_id] = session
                return session
            return None

        # In-memory fallback. Named separately from `session` above because
        # that one is bound from a database row and is never None; reusing
        # the name made its type `Session` then `Session | None`.
        cached = self._sessions.get(session_id)
        if cached and cached.is_valid and cached.tenant_id == tenant_id:
            return cached
        return None

    @traced_span("haldir.gate.check_permission")
    def check_permission(self, session_id: str, scope: str, tenant_id: str = "") -> bool:
        session = self.get_session(session_id, tenant_id=tenant_id)
        if not session:
            return False
        return session.has_permission(scope)

    def authorize_spend(self, session_id: str, amount: float, tenant_id: str = "") -> bool:
        session = self.get_session(session_id, tenant_id=tenant_id)
        if not session:
            return False
        return session.authorize_spend(amount)

    def record_spend(self, session_id: str, amount: float, tenant_id: str = "") -> bool:
        """Reserve `amount` against the session's budget, or refuse.

        Delegates the decision to `reserve_spend` so that the check and the
        increment happen in one statement. See that function for what went
        wrong when they were two.
        """
        conn = self._get_db()
        if not conn:
            # No database: fall back to the in-process session, which is the
            # only state there is. Same semantics, no persistence.
            session = self.get_session(session_id, tenant_id=tenant_id)
            if not session or not session.authorize_spend(amount):
                return False
            session.record_spend(amount)
            return True

        granted = reserve_spend(conn, session_id, tenant_id, amount)
        conn.commit()
        conn.close()

        if not granted:
            return False

        # Keep the cached object consistent with what the database now holds,
        # so a caller that reads session.remaining_budget right after this
        # sees the reservation it just made.
        session = self.get_session(session_id, tenant_id=tenant_id)
        if session:
            session.spent += amount
        return True

    @traced_span("haldir.gate.revoke_session")
    def revoke_session(self, session_id: str, tenant_id: str = "") -> bool:
        session = self._sessions.get(session_id)
        if session and session.tenant_id == tenant_id:
            session.revoked = True

        conn = self._get_db()
        if conn:
            conn.execute("UPDATE sessions SET revoked = 1 WHERE session_id = ? AND tenant_id = ?",
                         (session_id, tenant_id))
            conn.commit()
            affected = conn.total_changes
            conn.close()
            return bool(affected > 0)
        return session is not None

    def list_sessions(self, agent_id: str | None = None, tenant_id: str = "",
                      roots_only: bool = False,
                      parent_session_id: str | None = None,
                      include_revoked: bool = False) -> list[Session]:
        """List sessions for a tenant.

        `roots_only` returns just the tops of delegation chains — the natural
        entry point for a run tree. `parent_session_id` returns the direct
        children of one session. `include_revoked` admits finished sessions,
        which a monitoring view needs but the agent-cap count must not see.
        Defaults reproduce the original behaviour.
        """
        conn = self._get_db()
        if conn:
            query = "SELECT * FROM sessions WHERE tenant_id = ?"
            params = [tenant_id]
            if not include_revoked:
                query += " AND revoked = 0"
            if agent_id:
                query += " AND agent_id = ?"
                params.append(agent_id)
            if roots_only:
                query += " AND parent_session_id = ''"
            if parent_session_id is not None:
                query += " AND parent_session_id = ?"
                params.append(parent_session_id)
            rows = conn.execute(query, params).fetchall()
            conn.close()
            return [self._row_to_session(r) for r in rows]

        sessions = [s for s in self._sessions.values() if s.tenant_id == tenant_id]
        if not include_revoked:
            sessions = [s for s in sessions if s.is_valid]
        if agent_id:
            sessions = [s for s in sessions if s.agent_id == agent_id]
        if roots_only:
            sessions = [s for s in sessions if not s.parent_session_id]
        if parent_session_id is not None:
            sessions = [s for s in sessions if s.parent_session_id == parent_session_id]
        return sessions

    def get_children(self, session_id: str, tenant_id: str = "",
                     include_revoked: bool = False) -> list[Session]:
        """Direct children of a session in the delegation chain."""
        return self.list_sessions(
            tenant_id=tenant_id,
            parent_session_id=session_id,
            include_revoked=include_revoked,
        )

    def get_descendants(self, session_id: str, tenant_id: str = "",
                        include_revoked: bool = False) -> list[Session]:
        """Every session beneath `session_id`, breadth-first.

        Bounded by MAX_DELEGATION_DEPTH, so a corrupted set of links cannot
        make this walk unbounded.
        """
        descendants: list[Session] = []
        seen = {session_id}
        frontier = [session_id]
        depth = 0
        while frontier and depth < MAX_DELEGATION_DEPTH:
            depth += 1
            next_frontier: list[str] = []
            for current in frontier:
                for child in self.get_children(
                    current, tenant_id=tenant_id, include_revoked=include_revoked
                ):
                    if child.session_id in seen:
                        continue
                    seen.add(child.session_id)
                    descendants.append(child)
                    next_frontier.append(child.session_id)
            frontier = next_frontier
        return descendants
