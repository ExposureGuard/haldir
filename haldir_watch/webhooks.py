"""
Haldir Watch — Webhook system for real-time alerting.

Fires webhooks when:
- Anomalies are detected (spend spikes, rate abuse, blocked tool usage)
- Approval requests are created
- Session budget is exhausted
- Agent actions are flagged

Supports Slack, Discord, and generic HTTP endpoints.

Every outgoing request is HMAC-SHA256 signed (when the webhook has a
shared secret) so the receiver can verify the payload came from Haldir
and was not modified in transit. See `verify_signature()` at module
level for the receiver-side helper.

Signature scheme (compatible with the GitHub / Stripe convention):

    X-Haldir-Signature: sha256=<hex digest>
    X-Haldir-Timestamp: <unix seconds>
    X-Haldir-Event:     <event name>

The MAC is computed over `f"{timestamp}.{raw_body}".encode()` with the
shared secret as the HMAC key. The timestamp is included to defeat
replay attacks (verify_signature checks that the timestamp is within
`tolerance` seconds of now by default).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets as _secrets
import threading
import time
import urllib.request
from dataclasses import dataclass, field


# ── Public verifier (importable by webhook receivers) ────────────────────

class WebhookVerificationError(Exception):
    """Raised by verify_signature when a webhook can't be authenticated."""


def verify_signature(
    payload: bytes | str,
    signature_header: str,
    timestamp_header: str,
    secret: str,
    *,
    tolerance_seconds: int = 300,
    now: float | None = None,
) -> None:
    """Verify an incoming Haldir webhook.

    Args:
        payload: Raw request body bytes (or str — will be UTF-8 encoded).
                 Must be the *exact* bytes Haldir signed; do not re-serialize
                 a parsed JSON dict, since dict ordering / whitespace will
                 break the MAC.
        signature_header: The full value of `X-Haldir-Signature`,
                          e.g. `"sha256=abc123..."`.
        timestamp_header: The value of `X-Haldir-Timestamp` (unix seconds).
        secret: The shared secret you configured when registering the
                webhook with Haldir.
        tolerance_seconds: Reject signatures whose timestamp differs from
                           `now` by more than this many seconds (default
                           300s = 5 minutes). Defends against replay.
        now: Override "now" for testing. Default: `time.time()`.

    Raises:
        WebhookVerificationError: if the signature is invalid, the
            timestamp is outside the tolerance window, or any header is
            malformed.
    """
    if not signature_header.startswith("sha256="):
        raise WebhookVerificationError(
            "Signature header missing 'sha256=' prefix"
        )
    expected_sig = signature_header[len("sha256="):]

    try:
        ts = float(timestamp_header)
    except (TypeError, ValueError) as e:
        raise WebhookVerificationError(f"Invalid timestamp header: {e}")

    current = now if now is not None else time.time()
    if abs(current - ts) > tolerance_seconds:
        raise WebhookVerificationError(
            f"Signature timestamp {ts} is outside tolerance "
            f"({tolerance_seconds}s) of now ({current})"
        )

    body_bytes = payload if isinstance(payload, bytes) else payload.encode()
    signing_input = f"{int(ts)}.".encode() + body_bytes
    computed = hmac.new(secret.encode(), signing_input, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(computed, expected_sig):
        raise WebhookVerificationError("Signature does not match")


# ── Internal: WebhookConfig + Manager ────────────────────────────────────

@dataclass
class WebhookConfig:
    url: str
    name: str = ""
    events: list[str] = field(default_factory=lambda: ["all"])  # "all", "anomaly", "approval", "budget_exhausted", "flagged"
    active: bool = True
    secret: str = ""               # HMAC-SHA256 shared secret; "" = unsigned
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
        if not conn:
            return
        conn.execute("""
            CREATE TABLE IF NOT EXISTS webhooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                events TEXT NOT NULL DEFAULT '["all"]',
                active INTEGER NOT NULL DEFAULT 1,
                secret TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                last_fired REAL NOT NULL DEFAULT 0,
                fire_count INTEGER NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0
            )
        """)
        # Idempotent migration for existing tables that pre-date the secret column
        try:
            conn.execute("ALTER TABLE webhooks ADD COLUMN secret TEXT NOT NULL DEFAULT ''")
        except Exception:
            # Column already exists — fine
            pass
        conn.commit()
        conn.close()

    def _load_webhooks(self):
        conn = self._get_db()
        if not conn:
            return
        rows = conn.execute("SELECT * FROM webhooks WHERE active = 1").fetchall()
        conn.close()
        self._webhooks = []
        for r in rows:
            keys = r.keys() if hasattr(r, "keys") else []
            self._webhooks.append(WebhookConfig(
                url=r["url"],
                name=r["name"],
                events=json.loads(r["events"]),
                active=bool(r["active"]),
                secret=(r["secret"] if "secret" in keys else "") or "",
                created_at=r["created_at"],
                last_fired=r["last_fired"],
                fire_count=r["fire_count"],
                fail_count=r["fail_count"],
            ))

    def register(self, url: str, name: str = "",
                 events: list[str] | None = None,
                 secret: str | None = None,
                 generate_secret: bool = True) -> WebhookConfig:
        """Register a new webhook endpoint.

        Args:
            url: Endpoint to POST events to.
            name: Friendly identifier (e.g., "slack-eng-channel").
            events: List of event types to subscribe to. ["all"] catches
                    everything.
            secret: Pre-shared HMAC-SHA256 secret. If None and
                    `generate_secret` is True, one is generated for you.
                    Pass `secret=""` explicitly to skip signing entirely
                    (NOT recommended for production endpoints).
            generate_secret: If True (default) and no `secret` is supplied,
                             generate a random one with `secrets.token_urlsafe(32)`.

        Returns:
            The created WebhookConfig. **Save the `secret` field** — the
            receiver needs it to verify signatures, and Haldir will not
            re-display it after registration.
        """
        if secret is None and generate_secret:
            secret = _secrets.token_urlsafe(32)
        elif secret is None:
            secret = ""

        wh = WebhookConfig(
            url=url,
            name=name,
            events=events or ["all"],
            secret=secret,
        )
        self._webhooks.append(wh)

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT INTO webhooks (url, name, events, active, secret, created_at) "
                "VALUES (?, ?, ?, 1, ?, ?)",
                (url, name, json.dumps(wh.events), secret, time.time())
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
                target=self._send, args=(wh, data, event_type), daemon=True
            ).start()

    def _send(self, wh: WebhookConfig, data: bytes, event_type: str = ""):
        ts = int(time.time())
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Haldir/0.2.2",
            "X-Haldir-Event": event_type,
            "X-Haldir-Timestamp": str(ts),
        }
        if wh.secret:
            mac = hmac.new(
                wh.secret.encode(),
                f"{ts}.".encode() + data,
                hashlib.sha256,
            ).hexdigest()
            headers["X-Haldir-Signature"] = f"sha256={mac}"

        try:
            req = urllib.request.Request(wh.url, data=data, headers=headers)
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
        # Note: secret is NOT returned. Once shown at registration time,
        # it lives only in the DB — receivers must persist their own copy.
        return [
            {
                "url": wh.url,
                "name": wh.name,
                "events": wh.events,
                "active": wh.active,
                "fire_count": wh.fire_count,
                "fail_count": wh.fail_count,
                "signed": bool(wh.secret),
            }
            for wh in self._webhooks
        ]
