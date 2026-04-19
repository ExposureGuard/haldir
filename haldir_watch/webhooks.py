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
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# Retry policy for transient delivery failures. Exponential backoff
# bounded by `MAX_ATTEMPTS` — matches Stripe's approach (they retry for
# up to three days; we're shorter since Haldir is single-node today).
MAX_DELIVERY_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 1.0   # attempt 2 waits ~1s, attempt 3 waits ~4s
BACKOFF_FACTOR = 4.0

# Receivers' response bodies can be large; cap what we log so a
# misbehaving receiver can't balloon the audit table.
RESPONSE_EXCERPT_LIMIT = 512


def _is_retriable(status_code: int, error: Exception | None) -> bool:
    """5xx + network errors are retried; 4xx is a receiver config
    problem that won't resolve on retry."""
    if error is not None:
        return True
    return 500 <= status_code < 600


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

    def _get_db(self) -> Any:
        if not self._db_path:
            return None
        from haldir_db import get_db
        return get_db(self._db_path)

    def _init_table(self) -> None:
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

    def _load_webhooks(self) -> None:
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

    def fire(self, event_type: str, payload: dict[str, Any],
             tenant_id: str = "") -> str:
        """Fire an event to all matching webhooks (non-blocking).

        Returns the `event_id` (UUID) assigned to this fire. All
        deliveries to all matching webhook endpoints share the same
        event_id — receivers use it as an idempotency key so a retried
        delivery looks like the same event, not a new one."""
        event_id = uuid.uuid4().hex
        payload["event"] = event_type
        payload["event_id"] = event_id
        payload["timestamp"] = time.time()
        payload["source"] = "haldir"

        data = json.dumps(payload).encode()

        for wh in self._webhooks:
            if not wh.active:
                continue
            if "all" not in wh.events and event_type not in wh.events:
                continue

            threading.Thread(
                target=self._send_with_retry,
                args=(wh, data, event_type, event_id, tenant_id),
                daemon=True,
            ).start()
        return event_id

    # ── Delivery with retries ────────────────────────────────────────

    def _send_with_retry(
        self,
        wh: WebhookConfig,
        data: bytes,
        event_type: str,
        event_id: str,
        tenant_id: str = "",
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Try up to MAX_DELIVERY_ATTEMPTS times with exponential backoff.
        Logs every attempt (success or failure) to webhook_deliveries.
        `sleep` is injectable so tests can drive the retry loop without
        waiting real seconds."""
        for attempt in range(1, MAX_DELIVERY_ATTEMPTS + 1):
            status_code, excerpt, err, duration_ms = self._one_attempt(
                wh, data, event_type, event_id, attempt,
            )
            self._log_delivery(
                event_id=event_id,
                tenant_id=tenant_id,
                webhook_url=wh.url,
                event_type=event_type,
                attempt=attempt,
                status_code=status_code,
                response_excerpt=excerpt,
                error=err,
                duration_ms=duration_ms,
            )
            if not _is_retriable(status_code,
                                 Exception(err) if err else None):
                self._mark_success(wh)
                return
            if attempt < MAX_DELIVERY_ATTEMPTS:
                sleep(BACKOFF_BASE_SECONDS * (BACKOFF_FACTOR ** (attempt - 1)))
        self._mark_failure(wh)

    def _one_attempt(
        self,
        wh: WebhookConfig,
        data: bytes,
        event_type: str,
        event_id: str,
        attempt: int,
    ) -> tuple[int, str, str, int]:
        """Execute a single POST. Returns (status_code, response_excerpt,
        error_message, duration_ms). status_code=0 means no HTTP response
        (network error, timeout)."""
        ts = int(time.time())
        headers = {
            "Content-Type":              "application/json",
            "User-Agent":                "Haldir/0.2.3",
            "X-Haldir-Event":            event_type,
            "X-Haldir-Timestamp":        str(ts),
            "X-Haldir-Webhook-Id":       event_id,
            "X-Haldir-Delivery-Attempt": str(attempt),
        }
        if wh.secret:
            mac = hmac.new(
                wh.secret.encode(),
                f"{ts}.".encode() + data,
                hashlib.sha256,
            ).hexdigest()
            headers["X-Haldir-Signature"] = f"sha256={mac}"

        started = time.time()
        try:
            req = urllib.request.Request(wh.url, data=data, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read(RESPONSE_EXCERPT_LIMIT + 1)
            duration_ms = int((time.time() - started) * 1000)
            excerpt = body[:RESPONSE_EXCERPT_LIMIT].decode("utf-8", "replace")
            return (resp.status, excerpt, "", duration_ms)
        except urllib.error.HTTPError as e:
            duration_ms = int((time.time() - started) * 1000)
            try:
                body = e.read(RESPONSE_EXCERPT_LIMIT + 1)
                excerpt = body[:RESPONSE_EXCERPT_LIMIT].decode("utf-8", "replace")
            except Exception:
                excerpt = ""
            return (e.code, excerpt, "", duration_ms)
        except Exception as e:
            duration_ms = int((time.time() - started) * 1000)
            return (0, "", f"{type(e).__name__}: {e}", duration_ms)

    def _mark_success(self, wh: WebhookConfig) -> None:
        wh.last_fired = time.time()
        wh.fire_count += 1
        conn = self._get_db()
        if conn:
            conn.execute(
                "UPDATE webhooks SET last_fired = ?, fire_count = ? WHERE url = ?",
                (wh.last_fired, wh.fire_count, wh.url),
            )
            conn.commit()
            conn.close()

    def _mark_failure(self, wh: WebhookConfig) -> None:
        wh.fail_count += 1
        conn = self._get_db()
        if conn:
            conn.execute(
                "UPDATE webhooks SET fail_count = ? WHERE url = ?",
                (wh.fail_count, wh.url),
            )
            conn.commit()
            conn.close()

    def _log_delivery(self, **fields: Any) -> None:
        """Record one attempt into webhook_deliveries. Swallows any DB
        error — we'd rather lose the delivery log than crash the fire
        thread (which is a daemon)."""
        conn = self._get_db()
        if not conn:
            return
        try:
            conn.execute(
                "INSERT INTO webhook_deliveries ("
                "delivery_id, event_id, tenant_id, webhook_url, event_type, "
                "attempt, status_code, response_excerpt, error, "
                "duration_ms, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    uuid.uuid4().hex,
                    fields["event_id"],
                    fields["tenant_id"],
                    fields["webhook_url"],
                    fields["event_type"],
                    fields["attempt"],
                    fields["status_code"],
                    fields["response_excerpt"],
                    fields["error"],
                    fields["duration_ms"],
                    time.time(),
                ),
            )
            conn.commit()
        except Exception:
            # webhook_deliveries may not exist if migration 002 hasn't
            # been applied yet; don't fail the delivery thread on it.
            pass
        finally:
            conn.close()

    # ── Read side: delivery log ──────────────────────────────────────

    def list_deliveries(
        self,
        tenant_id: str,
        limit: int = 50,
        event_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return the most recent delivery attempts for a tenant,
        newest first. Optionally filter to a single event_id so
        receivers can answer 'did THIS event reach us?'"""
        conn = self._get_db()
        if not conn:
            return []
        try:
            sql = (
                "SELECT * FROM webhook_deliveries WHERE tenant_id = ?"
            )
            params: list[Any] = [tenant_id]
            if event_id:
                sql += " AND event_id = ?"
                params.append(event_id)
            sql += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(sql, params).fetchall()
        except Exception:
            return []
        finally:
            conn.close()
        return [
            {
                "delivery_id":      r["delivery_id"],
                "event_id":         r["event_id"],
                "webhook_url":      r["webhook_url"],
                "event_type":       r["event_type"],
                "attempt":          r["attempt"],
                "status_code":      r["status_code"],
                "response_excerpt": r["response_excerpt"],
                "error":            r["error"],
                "duration_ms":      r["duration_ms"],
                "created_at":       r["created_at"],
            }
            for r in rows
        ]

    def fire_anomaly(self, agent_id: str, tool: str, action: str,
                     reason: str, cost_usd: float = 0.0,
                     tenant_id: str = "") -> None:
        """Convenience: fire an anomaly event."""
        self.fire("anomaly", {
            "agent_id": agent_id,
            "tool": tool,
            "action": action,
            "reason": reason,
            "cost_usd": cost_usd,
        }, tenant_id=tenant_id)

    def fire_budget_exhausted(self, session_id: str, agent_id: str,
                              spent: float, limit: float,
                              tenant_id: str = "") -> None:
        """Convenience: fire when a session's budget is used up."""
        self.fire("budget_exhausted", {
            "session_id": session_id,
            "agent_id": agent_id,
            "spent": spent,
            "limit": limit,
        }, tenant_id=tenant_id)

    def fire_approval_requested(self, request_id: str, agent_id: str,
                                tool: str, action: str, amount: float,
                                reason: str, tenant_id: str = "") -> None:
        """Convenience: fire when human approval is needed."""
        self.fire("approval_requested", {
            "request_id": request_id,
            "agent_id": agent_id,
            "tool": tool,
            "action": action,
            "amount": amount,
            "reason": reason,
        }, tenant_id=tenant_id)

    def list_webhooks(self) -> list[dict[str, Any]]:
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
