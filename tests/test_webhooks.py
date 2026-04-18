"""
Tests for HMAC-SHA256 webhook signing + the public verify_signature helper.

The signing scheme follows the GitHub / Stripe convention:

    X-Haldir-Signature: sha256=<hex digest>
    X-Haldir-Timestamp: <unix seconds>

The MAC is HMAC-SHA256 over `f"{timestamp}.{raw_body}".encode()` keyed
with the shared secret.

Run: python -m pytest tests/test_webhooks.py -v
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from haldir_watch import (
    WebhookManager,
    WebhookVerificationError,
    verify_signature,
)


# ── Helpers ──────────────────────────────────────────────────────────────

def _sign(secret: str, ts: int, body: bytes) -> str:
    """Compute the same HMAC the manager produces."""
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


# ── Manager: registration auto-generates secrets by default ──────────────

@pytest.fixture
def manager() -> WebhookManager:
    return WebhookManager()


def test_register_auto_generates_secret(manager: WebhookManager) -> None:
    wh = manager.register(url="https://example.com/hook", name="test")
    assert wh.secret != ""
    assert len(wh.secret) >= 32  # token_urlsafe(32) = 43 chars


def test_register_explicit_secret_is_preserved(manager: WebhookManager) -> None:
    wh = manager.register(url="https://example.com/hook", secret="my-shared-secret")
    assert wh.secret == "my-shared-secret"


def test_register_generate_secret_false_yields_empty(manager: WebhookManager) -> None:
    wh = manager.register(url="https://example.com/hook", generate_secret=False)
    assert wh.secret == ""


def test_list_webhooks_does_not_leak_secret(manager: WebhookManager) -> None:
    """Listing webhooks via the public API must not return the shared secret —
    that's only handed back at registration time."""
    manager.register(url="https://example.com/hook", secret="my-secret")
    listed = manager.list_webhooks()
    assert len(listed) == 1
    entry = listed[0]
    assert "secret" not in entry
    # But the `signed` boolean should advertise that a secret is configured
    assert entry["signed"] is True


def test_list_webhooks_signed_false_when_unsigned(manager: WebhookManager) -> None:
    manager.register(url="https://example.com/hook", generate_secret=False)
    listed = manager.list_webhooks()
    assert listed[0]["signed"] is False


# ── verify_signature: the public receiver helper ─────────────────────────

class TestVerifySignature:

    secret = "my-shared-secret"
    body = b'{"event":"anomaly","agent_id":"bot-1"}'

    def _now(self) -> int:
        return int(time.time())

    def test_valid_signature_accepted(self) -> None:
        ts = self._now()
        sig = _sign(self.secret, ts, self.body)
        # Returns None on success
        assert verify_signature(
            payload=self.body,
            signature_header=sig,
            timestamp_header=str(ts),
            secret=self.secret,
        ) is None

    def test_str_payload_is_utf8_encoded(self) -> None:
        """Receivers may pass a string body — should still verify."""
        ts = self._now()
        sig = _sign(self.secret, ts, self.body)
        # Decode the body to str on the way in
        verify_signature(
            payload=self.body.decode(),
            signature_header=sig,
            timestamp_header=str(ts),
            secret=self.secret,
        )

    def test_invalid_signature_rejected(self) -> None:
        ts = self._now()
        # Sign with the WRONG secret
        sig = _sign("wrong-secret", ts, self.body)
        with pytest.raises(WebhookVerificationError, match="Signature does not match"):
            verify_signature(
                payload=self.body,
                signature_header=sig,
                timestamp_header=str(ts),
                secret=self.secret,
            )

    def test_tampered_body_rejected(self) -> None:
        ts = self._now()
        sig = _sign(self.secret, ts, self.body)
        # Change one byte
        with pytest.raises(WebhookVerificationError):
            verify_signature(
                payload=self.body + b"X",
                signature_header=sig,
                timestamp_header=str(ts),
                secret=self.secret,
            )

    def test_missing_sha256_prefix_rejected(self) -> None:
        ts = self._now()
        sig = _sign(self.secret, ts, self.body).removeprefix("sha256=")
        with pytest.raises(WebhookVerificationError, match="sha256="):
            verify_signature(
                payload=self.body,
                signature_header=sig,
                timestamp_header=str(ts),
                secret=self.secret,
            )

    def test_invalid_timestamp_rejected(self) -> None:
        ts = self._now()
        sig = _sign(self.secret, ts, self.body)
        with pytest.raises(WebhookVerificationError, match="Invalid timestamp"):
            verify_signature(
                payload=self.body,
                signature_header=sig,
                timestamp_header="not-a-number",
                secret=self.secret,
            )

    def test_old_timestamp_rejected_replay_protection(self) -> None:
        """A request signed an hour ago should be rejected by default."""
        ts = self._now() - 3700  # > 5 min default tolerance
        sig = _sign(self.secret, ts, self.body)
        with pytest.raises(WebhookVerificationError, match="outside tolerance"):
            verify_signature(
                payload=self.body,
                signature_header=sig,
                timestamp_header=str(ts),
                secret=self.secret,
            )

    def test_future_timestamp_rejected(self) -> None:
        """Clock-skew from the receiver's POV — also rejected."""
        ts = self._now() + 3700
        sig = _sign(self.secret, ts, self.body)
        with pytest.raises(WebhookVerificationError, match="outside tolerance"):
            verify_signature(
                payload=self.body,
                signature_header=sig,
                timestamp_header=str(ts),
                secret=self.secret,
            )

    def test_explicit_now_override_for_deterministic_tests(self) -> None:
        """`now=` override is useful when receivers want deterministic tests."""
        ts = 1_700_000_000
        sig = _sign(self.secret, ts, self.body)
        verify_signature(
            payload=self.body,
            signature_header=sig,
            timestamp_header=str(ts),
            secret=self.secret,
            now=ts + 30,
        )

    def test_tolerance_can_be_widened(self) -> None:
        """Some receivers want a longer tolerance window (queues, retries)."""
        ts = self._now() - 600  # 10 min ago
        sig = _sign(self.secret, ts, self.body)
        # Default tolerance (300s) would reject this; widen it
        verify_signature(
            payload=self.body,
            signature_header=sig,
            timestamp_header=str(ts),
            secret=self.secret,
            tolerance_seconds=900,
        )

    def test_constant_time_comparison_used(self) -> None:
        """`hmac.compare_digest` is used to defeat timing attacks. We can't
        test the timing directly, but we can verify the function never
        accepts a partially-correct signature even if the prefix matches."""
        ts = self._now()
        good_sig = _sign(self.secret, ts, self.body)
        # Same prefix, wrong suffix
        bad_sig = good_sig[:20] + ("a" if good_sig[20] != "a" else "b") + good_sig[21:]
        with pytest.raises(WebhookVerificationError):
            verify_signature(
                payload=self.body,
                signature_header=bad_sig,
                timestamp_header=str(ts),
                secret=self.secret,
            )

    def test_empty_body_signed_correctly(self) -> None:
        ts = self._now()
        sig = _sign(self.secret, ts, b"")
        verify_signature(
            payload=b"",
            signature_header=sig,
            timestamp_header=str(ts),
            secret=self.secret,
        )
