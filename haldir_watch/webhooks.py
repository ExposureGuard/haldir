"""
Haldir Watch — Webhook system for real-time alerting.

Fires webhooks when:
- Anomalies are detected (spend spikes, rate abuse, blocked tool usage)
- Approval requests are created
- Session budget is exhausted
- Agent actions are flagged

Supports Slack, Discord, and generic HTTP endpoints.
"""

import json
import time
import threading
import urllib.request
from dataclasses import dataclass, field


@dataclass
class WebhookConfig:
    url: str
    name: str = ""
    events: list[str] = field(default_factory=lambda: ["all"])  # "all", "anomaly", "approval", "budget_exhausted", "flagged"
    active: bool = True
    created_at: float = field(default_factory=time.time)
    last_fired: float = 0.0
    fire_count: int = 0
    fail_count: int = 0


class WebhookManager:
    """Manages webhook registrations and fires events."""

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path
        self._webhooks: list[WebhookConfig] = []

        if db_path:
            self._init_table()
            self._load_webhooks()

    def _get_db(self):
        if not self._db_path:
            return None
        from haldir_db import get_db
        return get_db(self._db_path)

    def _init_table(self):
        conn = self._get_db()
        if conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS webhooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    events TEXT NOT NULL DEFAULT '["all"]',
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    last_fired REAL NOT NULL DEFAULT 0,
                    fire_count INTEGER NOT NULL DEFAULT 0,
                    fail_count INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.commit()
            conn.close()

    def _load_webhooks(self):
        conn = self._get_db()
        if conn:
            rows = conn.execute("SELECT * FROM webhooks WHERE active = 1").fetchall()
            conn.close()
            self._webhooks = [
                WebhookConfig(
                    url=r["url"],
                    name=r["name"],
                    events=json.loads(r["events"]),
                    active=bool(r["active"]),
                    created_at=r["created_at"],
                    last_fired=r["last_fired"],
                    fire_count=r["fire_count"],
                    fail_count=r["fail_count"],
                )
                for r in rows
            ]

    def register(self, url: str, name: str = "", events: list[str] | None = None) -> WebhookConfig:
        """Register a new webhook endpoint."""
        wh = WebhookConfig(
            url=url,
            name=name,
            events=events or ["all"],
        )
        self._webhooks.append(wh)

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT INTO webhooks (url, name, events, active, created_at) VALUES (?, ?, ?, 1, ?)",
                (url, name, json.dumps(wh.events), time.time())
            )
            conn.commit()
            conn.close()

        return wh

    def fire(self, event_type: str, payload: dict):
        """Fire an event to all matching webhooks (non-blocking)."""
        payload["event"] = event_type
        payload["timestamp"] = time.time()
        payload["source"] = "haldir"

        data = json.dumps(payload).encode()

        for wh in self._webhooks:
            if not wh.active:
                continue
            if "all" not in wh.events and event_type not in wh.events:
                continue

            threading.Thread(
                target=self._send, args=(wh, data), daemon=True
            ).start()

    def _send(self, wh: WebhookConfig, data: bytes):
        try:
            req = urllib.request.Request(
                wh.url, data=data,
                headers={"Content-Type": "application/json", "User-Agent": "Haldir/0.1.0"},
            )
            urllib.request.urlopen(req, timeout=10)
            wh.last_fired = time.time()
            wh.fire_count += 1

            conn = self._get_db()
            if conn:
                conn.execute("UPDATE webhooks SET last_fired = ?, fire_count = ? WHERE url = ?",
                             (wh.last_fired, wh.fire_count, wh.url))
                conn.commit()
                conn.close()
        except Exception:
            wh.fail_count += 1
            conn = self._get_db()
            if conn:
                conn.execute("UPDATE webhooks SET fail_count = ? WHERE url = ?",
                             (wh.fail_count, wh.url))
                conn.commit()
                conn.close()

    def fire_anomaly(self, agent_id: str, tool: str, action: str,
                     reason: str, cost_usd: float = 0.0):
        """Convenience: fire an anomaly event."""
        self.fire("anomaly", {
            "agent_id": agent_id,
            "tool": tool,
            "action": action,
            "reason": reason,
            "cost_usd": cost_usd,
        })

    def fire_budget_exhausted(self, session_id: str, agent_id: str,
                              spent: float, limit: float):
        """Convenience: fire when a session's budget is used up."""
        self.fire("budget_exhausted", {
            "session_id": session_id,
            "agent_id": agent_id,
            "spent": spent,
            "limit": limit,
        })

    def fire_approval_requested(self, request_id: str, agent_id: str,
                                tool: str, action: str, amount: float, reason: str):
        """Convenience: fire when human approval is needed."""
        self.fire("approval_requested", {
            "request_id": request_id,
            "agent_id": agent_id,
            "tool": tool,
            "action": action,
            "amount": amount,
            "reason": reason,
        })

    def list_webhooks(self) -> list[dict]:
        return [
            {
                "url": wh.url,
                "name": wh.name,
                "events": wh.events,
                "active": wh.active,
                "fire_count": wh.fire_count,
                "fail_count": wh.fail_count,
            }
            for wh in self._webhooks
        ]
