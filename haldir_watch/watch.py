"""
Haldir Watch — Audit trail and cost tracking with persistent storage.

Audit entries are hash-chained: each entry contains a SHA-256 hash of its
contents plus the hash of the previous entry, creating a tamper-evident chain.
If any past entry is modified, all subsequent hashes break.
"""

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field


@dataclass
class AuditEntry:
    entry_id: str
    session_id: str
    agent_id: str
    action: str
    tool: str = ""
    details: dict = field(default_factory=dict)
    cost_usd: float = 0.0
    timestamp: float = field(default_factory=time.time)
    flagged: bool = False
    flag_reason: str = ""
    tenant_id: str = ""
    prev_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self) -> str:
        """SHA-256 hash of entry contents + previous hash = tamper-evident chain.

        Uses normalized representations (2 decimal places for cost, integer seconds
        for timestamp) to avoid precision drift between Python float and Postgres
        REAL column storage.
        """
        ts_int = int(self.timestamp)
        payload = (
            f"{self.entry_id}|{self.session_id}|{self.agent_id}|{self.action}|"
            f"{self.tool}|{json.dumps(self.details, sort_keys=True)}|"
            f"{self.cost_usd:.2f}|{ts_int}|"
            f"{1 if self.flagged else 0}|{self.prev_hash}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class Watch:
    """Audit and compliance engine with persistent storage."""

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path
        self._anomaly_rules: list[dict] = []

        conn = self._get_db()
        if conn:
            rows = conn.execute("SELECT * FROM anomaly_rules").fetchall()
            conn.close()
            for r in rows:
                self._anomaly_rules.append({
                    "type": r["rule_type"],
                    "threshold": r["threshold"],
                    "reason": r["reason"],
                })

    def _get_db(self):
        if not self._db_path:
            return None
        from haldir_db import get_db
        return get_db(self._db_path)

    def log_action(self, session, tool: str, action: str,
                   details: dict | None = None, cost_usd: float = 0.0,
                   tenant_id: str = "") -> AuditEntry:
        # Get previous entry hash for chaining
        prev_hash = ""
        conn = self._get_db()
        if conn:
            row = conn.execute(
                "SELECT entry_hash FROM audit_log WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT 1",
                (tenant_id,)
            ).fetchone()
            if row:
                prev_hash = row["entry_hash"]
            conn.close()

        entry = AuditEntry(
            entry_id=f"aud_{secrets.token_urlsafe(16)}",
            session_id=session.session_id,
            agent_id=session.agent_id,
            action=action,
            tool=tool,
            details=details or {},
            cost_usd=round(cost_usd, 2),
            timestamp=float(int(time.time())),  # integer seconds to match Postgres REAL precision
            tenant_id=tenant_id,
            prev_hash=prev_hash,
        )

        # Apply anomaly rules BEFORE hashing so flagged state is part of the hash
        for rule in self._anomaly_rules:
            if self._check_anomaly(entry, rule):
                entry.flagged = True
                entry.flag_reason = rule.get("reason", "Anomaly detected")
                break

        entry.entry_hash = entry.compute_hash()

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT INTO audit_log (entry_id, tenant_id, session_id, agent_id, action, tool, details, cost_usd, timestamp, flagged, flag_reason, prev_hash, entry_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (entry.entry_id, tenant_id, entry.session_id, entry.agent_id, entry.action,
                 entry.tool, json.dumps(entry.details), entry.cost_usd,
                 entry.timestamp, int(entry.flagged), entry.flag_reason,
                 entry.prev_hash, entry.entry_hash)
            )
            conn.commit()
            conn.close()

        return entry

    def get_audit_trail(self, session_id: str | None = None,
                        agent_id: str | None = None,
                        tool: str | None = None,
                        since: float | None = None,
                        flagged_only: bool = False,
                        limit: int = 100,
                        tenant_id: str = "") -> list[AuditEntry]:
        conn = self._get_db()
        if conn:
            query = "SELECT * FROM audit_log WHERE tenant_id = ?"
            params = [tenant_id]
            if session_id:
                query += " AND session_id = ?"
                params.append(session_id)
            if agent_id:
                query += " AND agent_id = ?"
                params.append(agent_id)
            if tool:
                query += " AND tool = ?"
                params.append(tool)
            if since:
                query += " AND timestamp >= ?"
                params.append(since)
            if flagged_only:
                query += " AND flagged = 1"
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            conn.close()
            return [
                AuditEntry(
                    entry_id=r["entry_id"],
                    session_id=r["session_id"],
                    agent_id=r["agent_id"],
                    action=r["action"],
                    tool=r["tool"],
                    details=json.loads(r["details"]),
                    cost_usd=r["cost_usd"],
                    timestamp=r["timestamp"],
                    flagged=bool(r["flagged"]),
                    flag_reason=r["flag_reason"],
                    tenant_id=tenant_id,
                    prev_hash=r["prev_hash"] if "prev_hash" in r.keys() else "",
                    entry_hash=r["entry_hash"] if "entry_hash" in r.keys() else "",
                )
                for r in rows
            ]
        return []

    def get_spend(self, session_id: str | None = None,
                  agent_id: str | None = None,
                  tenant_id: str = "") -> dict:
        conn = self._get_db()
        if conn:
            query = "SELECT tool, SUM(cost_usd) as total, COUNT(*) as cnt FROM audit_log WHERE tenant_id = ?"
            params = [tenant_id]
            if session_id:
                query += " AND session_id = ?"
                params.append(session_id)
            if agent_id:
                query += " AND agent_id = ?"
                params.append(agent_id)
            query += " GROUP BY tool"
            rows = conn.execute(query, params).fetchall()

            total_query = "SELECT SUM(cost_usd) as total, COUNT(*) as cnt FROM audit_log WHERE tenant_id = ?"
            total_params = [tenant_id]
            if session_id:
                total_query += " AND session_id = ?"
                total_params.append(session_id)
            elif agent_id:
                total_query += " AND agent_id = ?"
                total_params.append(agent_id)
            total_row = conn.execute(total_query, total_params).fetchone()
            conn.close()

            by_tool = {r["tool"]: round(r["total"], 4) for r in rows if r["tool"]}
            return {
                "total_usd": round(total_row["total"] or 0, 4),
                "action_count": total_row["cnt"] or 0,
                "by_tool": by_tool,
            }
        return {"total_usd": 0, "action_count": 0, "by_tool": {}}

    def add_anomaly_rule(self, rule_type: str, threshold: float, reason: str = "",
                         tenant_id: str = ""):
        rule = {
            "type": rule_type,
            "threshold": threshold,
            "reason": reason or f"{rule_type} exceeded {threshold}",
        }
        self._anomaly_rules.append(rule)

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT INTO anomaly_rules (tenant_id, rule_type, threshold, reason, created_at) VALUES (?, ?, ?, ?, ?)",
                (tenant_id, rule_type, threshold, rule["reason"], time.time())
            )
            conn.commit()
            conn.close()

    def _check_anomaly(self, entry: AuditEntry, rule: dict) -> bool:
        if rule["type"] == "spend_per_action":
            return entry.cost_usd > rule["threshold"]
        if rule["type"] == "actions_per_minute":
            conn = self._get_db()
            if conn:
                one_min_ago = time.time() - 60
                count = conn.execute(
                    "SELECT COUNT(*) FROM audit_log WHERE agent_id = ? AND tenant_id = ? AND timestamp >= ?",
                    (entry.agent_id, entry.tenant_id, one_min_ago)
                ).fetchone()[0]
                conn.close()
                return count >= rule["threshold"]
        if rule["type"] == "tool_blocked":
            return entry.tool == str(rule["threshold"])
        return False

    def flag_anomaly(self, entry_id: str, reason: str, tenant_id: str = "") -> bool:
        conn = self._get_db()
        if conn:
            conn.execute(
                "UPDATE audit_log SET flagged = 1, flag_reason = ? WHERE entry_id = ? AND tenant_id = ?",
                (reason, entry_id, tenant_id))
            conn.commit()
            affected = conn.total_changes
            conn.close()
            return affected > 0
        return False

    def verify_chain(self, tenant_id: str = "", limit: int = 10000) -> dict:
        """Verify the hash chain integrity of the audit log.

        Walks the chain from oldest to newest, recomputing each hash.
        If any entry was tampered with, the chain breaks at that point.
        """
        conn = self._get_db()
        if not conn:
            return {"verified": False, "error": "No database"}

        rows = conn.execute(
            "SELECT * FROM audit_log WHERE tenant_id = ? ORDER BY timestamp ASC LIMIT ?",
            (tenant_id, limit)
        ).fetchall()
        conn.close()

        if not rows:
            return {"verified": True, "entries_checked": 0, "message": "Empty audit log"}

        prev_hash = ""
        for i, r in enumerate(rows):
            entry = AuditEntry(
                entry_id=r["entry_id"], session_id=r["session_id"],
                agent_id=r["agent_id"], action=r["action"], tool=r["tool"],
                details=json.loads(r["details"]), cost_usd=r["cost_usd"],
                timestamp=r["timestamp"], flagged=bool(r["flagged"]),
                prev_hash=r["prev_hash"],
            )
            expected_hash = entry.compute_hash()
            stored_hash = r["entry_hash"]

            if stored_hash and stored_hash != expected_hash:
                return {
                    "verified": False,
                    "entries_checked": i + 1,
                    "tampered_entry": r["entry_id"],
                    "error": "Entry hash mismatch — data was modified",
                }
            if entry.prev_hash and entry.prev_hash != prev_hash:
                return {
                    "verified": False,
                    "entries_checked": i + 1,
                    "broken_at": r["entry_id"],
                    "error": "Chain broken — previous entry was modified or deleted",
                }
            prev_hash = stored_hash or expected_hash

        return {
            "verified": True,
            "entries_checked": len(rows),
            "message": "Audit chain integrity verified",
        }

    def export_log(self, format: str = "json", limit: int = 1000, tenant_id: str = "") -> str | list[dict]:
        entries = self.get_audit_trail(limit=limit, tenant_id=tenant_id)
        records = [
            {"id": e.entry_id, "session": e.session_id, "agent": e.agent_id,
             "action": e.action, "tool": e.tool, "cost_usd": e.cost_usd,
             "flagged": e.flagged, "flag_reason": e.flag_reason,
             "timestamp": e.timestamp, "details": e.details}
            for e in entries
        ]
        if format == "json":
            return json.dumps(records, indent=2)
        return records
