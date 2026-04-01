"""
Haldir Watch — Audit trail and cost tracking with SQLite persistence.
"""

import json
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


class Watch:
    """Audit and compliance engine with persistent storage."""

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path
        self._anomaly_rules: list[dict] = []

        # Load anomaly rules from DB
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
                   details: dict | None = None, cost_usd: float = 0.0) -> AuditEntry:
        entry = AuditEntry(
            entry_id=f"aud_{int(time.time() * 1000)}",
            session_id=session.session_id,
            agent_id=session.agent_id,
            action=action,
            tool=tool,
            details=details or {},
            cost_usd=cost_usd,
        )

        # Check anomaly rules
        for rule in self._anomaly_rules:
            if self._check_anomaly(entry, rule):
                entry.flagged = True
                entry.flag_reason = rule.get("reason", "Anomaly detected")
                break

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT INTO audit_log (entry_id, session_id, agent_id, action, tool, details, cost_usd, timestamp, flagged, flag_reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (entry.entry_id, entry.session_id, entry.agent_id, entry.action,
                 entry.tool, json.dumps(entry.details), entry.cost_usd,
                 entry.timestamp, int(entry.flagged), entry.flag_reason)
            )
            conn.commit()
            conn.close()

        return entry

    def get_audit_trail(self, session_id: str | None = None,
                        agent_id: str | None = None,
                        tool: str | None = None,
                        since: float | None = None,
                        flagged_only: bool = False,
                        limit: int = 100) -> list[AuditEntry]:
        conn = self._get_db()
        if conn:
            query = "SELECT * FROM audit_log WHERE 1=1"
            params = []
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
                )
                for r in rows
            ]
        return []

    def get_spend(self, session_id: str | None = None,
                  agent_id: str | None = None) -> dict:
        conn = self._get_db()
        if conn:
            query = "SELECT tool, SUM(cost_usd) as total, COUNT(*) as cnt FROM audit_log WHERE 1=1"
            params = []
            if session_id:
                query += " AND session_id = ?"
                params.append(session_id)
            if agent_id:
                query += " AND agent_id = ?"
                params.append(agent_id)
            query += " GROUP BY tool"
            rows = conn.execute(query, params).fetchall()

            total_row = conn.execute(
                "SELECT SUM(cost_usd) as total, COUNT(*) as cnt FROM audit_log" +
                (" WHERE session_id = ?" if session_id else " WHERE agent_id = ?" if agent_id else ""),
                [session_id or agent_id] if (session_id or agent_id) else []
            ).fetchone()
            conn.close()

            by_tool = {r["tool"]: round(r["total"], 4) for r in rows if r["tool"]}
            return {
                "total_usd": round(total_row["total"] or 0, 4),
                "action_count": total_row["cnt"] or 0,
                "by_tool": by_tool,
            }
        return {"total_usd": 0, "action_count": 0, "by_tool": {}}

    def add_anomaly_rule(self, rule_type: str, threshold: float, reason: str = ""):
        rule = {
            "type": rule_type,
            "threshold": threshold,
            "reason": reason or f"{rule_type} exceeded {threshold}",
        }
        self._anomaly_rules.append(rule)

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT INTO anomaly_rules (rule_type, threshold, reason, created_at) VALUES (?, ?, ?, ?)",
                (rule_type, threshold, rule["reason"], time.time())
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
                    "SELECT COUNT(*) FROM audit_log WHERE agent_id = ? AND timestamp >= ?",
                    (entry.agent_id, one_min_ago)
                ).fetchone()[0]
                conn.close()
                return count >= rule["threshold"]
        if rule["type"] == "tool_blocked":
            return entry.tool == str(rule["threshold"])
        return False

    def flag_anomaly(self, entry_id: str, reason: str) -> bool:
        conn = self._get_db()
        if conn:
            conn.execute("UPDATE audit_log SET flagged = 1, flag_reason = ? WHERE entry_id = ?",
                         (reason, entry_id))
            conn.commit()
            affected = conn.total_changes
            conn.close()
            return affected > 0
        return False

    def export_log(self, format: str = "json", limit: int = 1000) -> str | list[dict]:
        entries = self.get_audit_trail(limit=limit)
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
