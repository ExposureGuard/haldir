"""
Haldir Watch — Audit trail and cost tracking.

Every agent action flows through Watch. This creates an immutable audit log
that can be queried, exported, and used for compliance reporting.
"""

import time
from dataclasses import dataclass, field


@dataclass
class AuditEntry:
    entry_id: str
    session_id: str
    agent_id: str
    action: str                      # e.g. "tool_call", "payment", "secret_access"
    tool: str = ""                   # Which tool/MCP server
    details: dict = field(default_factory=dict)
    cost_usd: float = 0.0
    timestamp: float = field(default_factory=time.time)
    flagged: bool = False
    flag_reason: str = ""


class Watch:
    """
    Audit and compliance engine.

    Records every agent action for review, anomaly detection, and reporting.
    """

    def __init__(self):
        self._log: list[AuditEntry] = []
        self._anomaly_rules: list[dict] = []
        self._total_cost: float = 0.0

    def log_action(self, session, tool: str, action: str,
                   details: dict | None = None, cost_usd: float = 0.0) -> AuditEntry:
        """Record an agent action."""
        entry = AuditEntry(
            entry_id=f"aud_{int(time.time())}_{len(self._log)}",
            session_id=session.session_id,
            agent_id=session.agent_id,
            action=action,
            tool=tool,
            details=details or {},
            cost_usd=cost_usd,
        )
        self._total_cost += cost_usd

        # Check anomaly rules
        for rule in self._anomaly_rules:
            if self._check_anomaly(entry, rule):
                entry.flagged = True
                entry.flag_reason = rule.get("reason", "Anomaly detected")
                break

        self._log.append(entry)
        return entry

    def get_audit_trail(self, session_id: str | None = None,
                        agent_id: str | None = None,
                        tool: str | None = None,
                        since: float | None = None,
                        flagged_only: bool = False) -> list[AuditEntry]:
        """Query the audit log with filters."""
        entries = self._log
        if session_id:
            entries = [e for e in entries if e.session_id == session_id]
        if agent_id:
            entries = [e for e in entries if e.agent_id == agent_id]
        if tool:
            entries = [e for e in entries if e.tool == tool]
        if since:
            entries = [e for e in entries if e.timestamp >= since]
        if flagged_only:
            entries = [e for e in entries if e.flagged]
        return entries

    def get_spend(self, session_id: str | None = None,
                  agent_id: str | None = None) -> dict:
        """Get spend summary."""
        entries = self._log
        if session_id:
            entries = [e for e in entries if e.session_id == session_id]
        if agent_id:
            entries = [e for e in entries if e.agent_id == agent_id]
        total = sum(e.cost_usd for e in entries)
        by_tool = {}
        for e in entries:
            if e.tool:
                by_tool[e.tool] = by_tool.get(e.tool, 0.0) + e.cost_usd
        return {
            "total_usd": round(total, 4),
            "action_count": len(entries),
            "by_tool": by_tool,
        }

    def add_anomaly_rule(self, rule_type: str, threshold: float,
                         reason: str = ""):
        """
        Add an anomaly detection rule.

        Types:
        - "spend_per_action": flag if a single action costs more than threshold
        - "actions_per_minute": flag if agent exceeds threshold actions/min
        - "tool_blocked": flag if agent tries to use a specific tool
        """
        self._anomaly_rules.append({
            "type": rule_type,
            "threshold": threshold,
            "reason": reason or f"{rule_type} exceeded {threshold}",
        })

    def _check_anomaly(self, entry: AuditEntry, rule: dict) -> bool:
        if rule["type"] == "spend_per_action":
            return entry.cost_usd > rule["threshold"]
        if rule["type"] == "actions_per_minute":
            one_min_ago = time.time() - 60
            recent = [e for e in self._log
                      if e.agent_id == entry.agent_id and e.timestamp >= one_min_ago]
            return len(recent) >= rule["threshold"]
        if rule["type"] == "tool_blocked":
            return entry.tool == str(rule["threshold"])
        return False

    def flag_anomaly(self, entry_id: str, reason: str) -> bool:
        """Manually flag an audit entry."""
        for entry in self._log:
            if entry.entry_id == entry_id:
                entry.flagged = True
                entry.flag_reason = reason
                return True
        return False

    def export_log(self, format: str = "json") -> str | list[dict]:
        """Export audit log for compliance."""
        records = []
        for e in self._log:
            records.append({
                "id": e.entry_id,
                "session": e.session_id,
                "agent": e.agent_id,
                "action": e.action,
                "tool": e.tool,
                "cost_usd": e.cost_usd,
                "flagged": e.flagged,
                "flag_reason": e.flag_reason,
                "timestamp": e.timestamp,
                "details": e.details,
            })
        if format == "json":
            import json
            return json.dumps(records, indent=2)
        return records
