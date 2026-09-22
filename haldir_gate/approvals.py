"""
Haldir Gate — Human-in-the-loop approval system.

When an agent attempts a sensitive action (spend over threshold, destructive operation,
external API call), Gate can pause execution and request human approval before proceeding.

Approval flow:
1. Agent calls a tool that requires approval
2. Gate creates a pending approval request
3. Human receives notification (webhook, email, or polling)
4. Human approves or denies
5. Agent receives the decision and continues or stops

This is THE killer feature for enterprise adoption. No other MCP governance
layer has this. It's the reason a bank would choose Haldir over rolling their own.
"""

import json
import time
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from haldir_outbound import safe_outbound_url


class ApprovalStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    request_id: str
    session_id: str
    agent_id: str
    action: str
    tool: str
    tenant_id: str = ""                  # Whose request this is. Every read
                                         # and every decision is scoped by it.
    details: dict = field(default_factory=dict)
    reason: str = ""                     # Why approval is needed
    amount: float = 0.0                  # If spend-related
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0              # 0 = no expiry
    decided_at: float = 0.0
    decided_by: str = ""                 # Who approved/denied
    decision_note: str = ""              # Optional note from approver

    @property
    def is_expired(self) -> bool:
        if self.expires_at > 0 and time.time() > self.expires_at:
            return True
        return False


class ApprovalEngine:
    """
    Manages human-in-the-loop approval requests.

    Usage:
        engine = ApprovalEngine(db_path="haldir.db")

        # Agent wants to spend $500
        req = engine.request_approval(
            session=session,
            tool="stripe",
            action="charge",
            amount=500.00,
            reason="Agent wants to purchase premium API access"
        )

        # Human checks pending approvals
        pending = engine.get_pending(agent_id="research-bot")

        # Human approves
        engine.approve(req.request_id, decided_by="sterling", note="ok for this vendor")

        # Agent checks result
        result = engine.check(req.request_id)
        if result.status == ApprovalStatus.APPROVED:
            # proceed with action
    """

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path
        self._requests: dict[str, ApprovalRequest] = {}
        self._rules: list[dict] = []
        self._webhooks: list[str] = []

        if db_path:
            self._init_table()

    def _get_db(self) -> Any:
        if not self._db_path:
            return None
        from haldir_db import get_db
        return get_db(self._db_path)

    def _init_table(self) -> None:
        conn = self._get_db()
        if conn:
            conn.execute("""
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
                )
            """)
            # A database created before this column existed gets it added
            # rather than left to fail every scoped query below. SQLite has
            # no IF NOT EXISTS for ADD COLUMN, so the error is the check.
            try:
                conn.execute(
                    "ALTER TABLE approval_requests ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''"
                )
            except Exception:  # noqa: BLE001 — already present
                pass
            conn.execute("CREATE INDEX IF NOT EXISTS idx_approvals_status ON approval_requests(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_approvals_agent ON approval_requests(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_approvals_tenant ON approval_requests(tenant_id)")
            conn.commit()
            conn.close()

    def add_rule(self, rule_type: str, threshold: float = 0,
                 tools: list[str] | None = None) -> None:
        """
        Add an auto-approval-required rule.

        Types:
        - "spend_over": require approval for spend above threshold
        - "tool_blocked": require approval for specific tools
        - "destructive": require approval for delete/write actions
        - "all": require approval for everything (paranoid mode)
        """
        self._rules.append({
            "type": rule_type,
            "threshold": threshold,
            "tools": tools or [],
        })

    def add_webhook(self, url: str) -> None:
        """Add a webhook URL to notify on new approval requests.

        Validated here and again at fire time. `urlopen` honours whatever
        scheme it is handed, so an unvalidated URL made this a local file
        read: `file:///etc/passwd` would be fetched and its contents taken
        as the response. Raises UnsafeURL, which the API surfaces as a 400.
        """
        safe_outbound_url(url)
        self._webhooks.append(url)

    def needs_approval(self, tool: str, action: str, amount: float = 0.0) -> tuple[bool, str]:
        """Check if an action requires human approval. Returns (needs_approval, reason)."""
        for rule in self._rules:
            if rule["type"] == "all":
                return True, "All actions require approval"
            if rule["type"] == "spend_over" and amount > rule["threshold"]:
                return True, f"Spend ${amount:.2f} exceeds ${rule['threshold']:.2f} threshold"
            if rule["type"] == "tool_blocked" and tool in rule["tools"]:
                return True, f"Tool '{tool}' requires approval"
            if rule["type"] == "destructive" and action in ("delete", "write", "execute", "send"):
                return True, f"Destructive action '{action}' requires approval"
        return False, ""

    def request_approval(self, session: Any, tool: str, action: str,
                         amount: float = 0.0, reason: str = "",
                         details: dict | None = None,
                         ttl: int = 3600, tenant_id: str = "") -> ApprovalRequest:
        """Create a pending approval request.

        `tenant_id` is stored, not merely accepted. It is the only thing that
        scopes the read and decision paths below, and until it was recorded
        here every request was filed under the empty tenant — which is how
        one tenant came to read, list and approve another's.
        """
        req = ApprovalRequest(
            request_id=f"apr_{secrets.token_urlsafe(16)}",
            session_id=session.session_id,
            agent_id=session.agent_id,
            action=action,
            tool=tool,
            tenant_id=tenant_id,
            details=details or {},
            reason=reason,
            amount=amount,
            expires_at=time.time() + ttl if ttl > 0 else 0,
        )
        self._requests[req.request_id] = req

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT INTO approval_requests "
                "(request_id, tenant_id, session_id, agent_id, action, tool, details, reason, amount, status, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (req.request_id, req.tenant_id, req.session_id, req.agent_id,
                 req.action, req.tool,
                 json.dumps(req.details), req.reason, req.amount, req.status.value,
                 req.created_at, req.expires_at)
            )
            conn.commit()
            conn.close()

        # Fire webhooks
        self._notify_webhooks(req)

        return req

    def approve(self, request_id: str, decided_by: str = "", note: str = "",
                tenant_id: str = "") -> bool:
        """Approve a pending request belonging to `tenant_id`."""
        return self._decide(request_id, ApprovalStatus.APPROVED, decided_by, note,
                            tenant_id=tenant_id)

    def deny(self, request_id: str, decided_by: str = "", note: str = "",
             tenant_id: str = "") -> bool:
        """Deny a pending request belonging to `tenant_id`."""
        return self._decide(request_id, ApprovalStatus.DENIED, decided_by, note,
                            tenant_id=tenant_id)

    def _decide(self, request_id: str, status: ApprovalStatus,
                decided_by: str, note: str, tenant_id: str = "") -> bool:
        """Decide a request, but only one filed under `tenant_id`.

        Another tenant's request is reported exactly as a nonexistent one.
        Answering "forbidden" would confirm the id exists, which is the
        enumeration oracle this is meant to close.
        """
        req = self._requests.get(request_id)
        if req is not None and req.tenant_id != tenant_id:
            req = None

        conn = self._get_db()
        if not req and conn:
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE request_id = ? AND tenant_id = ?",
                (request_id, tenant_id)
            ).fetchone()
            if row:
                req = self._row_to_request(row)
                self._requests[request_id] = req

        if not req:
            if conn:
                conn.close()
            return False

        if req.status != ApprovalStatus.PENDING:
            if conn:
                conn.close()
            return False

        if req.is_expired:
            req.status = ApprovalStatus.EXPIRED
            if conn:
                conn.execute("UPDATE approval_requests SET status = 'expired' WHERE request_id = ?",
                             (request_id,))
                conn.commit()
                conn.close()
            return False

        req.status = status
        req.decided_at = time.time()
        req.decided_by = decided_by
        req.decision_note = note

        if conn:
            conn.execute(
                "UPDATE approval_requests SET status = ?, decided_at = ?, decided_by = ?, decision_note = ? "
                "WHERE request_id = ?",
                (status.value, req.decided_at, decided_by, note, request_id)
            )
            conn.commit()
            conn.close()

        return True

    def check(self, request_id: str, tenant_id: str = "") -> ApprovalRequest | None:
        """Check the status of an approval request. Used by agents to poll.

        Returns None for another tenant's request — indistinguishable from a
        request that does not exist, deliberately.
        """
        req = self._requests.get(request_id)
        if req is not None and req.tenant_id != tenant_id:
            req = None

        if not req:
            conn = self._get_db()
            if conn:
                row = conn.execute(
                    "SELECT * FROM approval_requests WHERE request_id = ? AND tenant_id = ?",
                    (request_id, tenant_id)).fetchone()
                conn.close()
                if row:
                    req = self._row_to_request(row)
                    self._requests[request_id] = req

        if req and req.status == ApprovalStatus.PENDING and req.is_expired:
            req.status = ApprovalStatus.EXPIRED
            conn = self._get_db()
            if conn:
                conn.execute("UPDATE approval_requests SET status = 'expired' WHERE request_id = ?",
                             (request_id,))
                conn.commit()
                conn.close()

        return req

    def get_pending(self, agent_id: str | None = None,
                    tenant_id: str = "") -> list[ApprovalRequest]:
        """Get this tenant's pending approval requests.

        Unscoped, this returned every tenant's queue — which handed any
        caller the request ids they would otherwise have to guess.
        """
        conn = self._get_db()
        if conn:
            if agent_id:
                rows = conn.execute(
                    "SELECT * FROM approval_requests WHERE status = 'pending' AND tenant_id = ? AND agent_id = ? ORDER BY created_at DESC",
                    (tenant_id, agent_id)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM approval_requests WHERE status = 'pending' AND tenant_id = ? ORDER BY created_at DESC",
                    (tenant_id,)
                ).fetchall()
            conn.close()
            return [self._row_to_request(r) for r in rows]
        return [r for r in self._requests.values()
                if r.status == ApprovalStatus.PENDING and not r.is_expired
                and r.tenant_id == tenant_id]

    def get_history(self, agent_id: str | None = None, limit: int = 50,
                    tenant_id: str = "") -> list[ApprovalRequest]:
        """Get this tenant's approval history."""
        conn = self._get_db()
        if conn:
            if agent_id:
                rows = conn.execute(
                    "SELECT * FROM approval_requests WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT ?",
                    (tenant_id, agent_id, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM approval_requests WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
                    (tenant_id, limit)
                ).fetchall()
            conn.close()
            return [self._row_to_request(r) for r in rows]
        return [r for r in self._requests.values() if r.tenant_id == tenant_id][-limit:]

    def _row_to_request(self, row: Any) -> ApprovalRequest:
        keys = row.keys() if hasattr(row, "keys") else []
        return ApprovalRequest(
            request_id=row["request_id"],
            # Defensive: a row read from a database that predates the column
            # has no tenant, and an unattributed request must not be visible
            # to a tenant that happens to match on everything else.
            tenant_id=row["tenant_id"] if "tenant_id" in keys else "",
            session_id=row["session_id"],
            agent_id=row["agent_id"],
            action=row["action"],
            tool=row["tool"],
            details=json.loads(row["details"]),
            reason=row["reason"],
            amount=row["amount"],
            status=ApprovalStatus(row["status"]),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            decided_at=row["decided_at"],
            decided_by=row["decided_by"],
            decision_note=row["decision_note"],
        )

    def _notify_webhooks(self, req: ApprovalRequest) -> None:
        """Fire webhooks for new approval requests (non-blocking)."""
        if not self._webhooks:
            return
        import threading
        import urllib.request

        payload = json.dumps({
            "event": "approval_requested",
            "request_id": req.request_id,
            "agent_id": req.agent_id,
            "tool": req.tool,
            "action": req.action,
            "amount": req.amount,
            "reason": req.reason,
            "created_at": req.created_at,
            "approve_url": f"https://haldir.xyz/v1/approvals/{req.request_id}/approve",
            "deny_url": f"https://haldir.xyz/v1/approvals/{req.request_id}/deny",
        }).encode()

        def fire(url: str) -> None:
            try:
                # Re-checked at fire time: a name that resolved public at
                # registration can resolve inward later.
                safe_outbound_url(url)
                r = urllib.request.Request(url, data=payload,
                                           headers={"Content-Type": "application/json"})
                # nosec B310 — the URL passed safe_outbound_url above.
                urllib.request.urlopen(r, timeout=5)  # nosec B310
            except Exception:
                pass

        for url in self._webhooks:
            threading.Thread(target=fire, args=(url,), daemon=True).start()
