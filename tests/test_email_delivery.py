"""
Tests for haldir_email + the email delivery scheme on
haldir_compliance_scheduler.

Scope:
  - validate_delivery accepts well-formed email: addresses
  - validate_delivery rejects malformed addresses
  - send_evidence_pack with no SMTP config returns smtp_unconfigured
  - send_evidence_pack with config + injected smtp_send composes
    the correct EmailMessage (subject, from, headers, attachment)
  - fire_one with delivery=email:... routes through haldir_email
  - fire_one records status=sent on success, smtp_unconfigured on
    no-config, smtp_failed on dispatcher exception

Run: python -m pytest tests/test_email_delivery.py -v
"""

from __future__ import annotations

import os
import sys
from email.message import EmailMessage

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import haldir_compliance_scheduler as sched  # noqa: E402
import haldir_email  # noqa: E402


# ── Validation ───────────────────────────────────────────────────────

def test_validate_delivery_accepts_email() -> None:
    assert sched.validate_delivery("email:ciso@acme.com") == "email:ciso@acme.com"


def test_validate_delivery_rejects_garbage_email() -> None:
    with pytest.raises(sched.ScheduleValidationError, match="not a valid"):
        sched.validate_delivery("email:not-an-address")


def test_validate_delivery_rejects_empty_email() -> None:
    with pytest.raises(sched.ScheduleValidationError, match="missing target"):
        sched.validate_delivery("email:")


def test_validate_delivery_still_accepts_webhook() -> None:
    """Existing scheme must keep working."""
    assert sched.validate_delivery("webhook:wh_x") == "webhook:wh_x"


# ── send_evidence_pack ──────────────────────────────────────────────

def test_send_returns_unconfigured_without_env(monkeypatch) -> None:
    monkeypatch.delenv("HALDIR_SMTP_HOST", raising=False)
    out = haldir_email.send_evidence_pack(
        "ciso@acme.com",
        pack={"signatures": {"digest": "abc"},
              "period_start": "x", "period_end": "y", "tenant_id": "t"},
        markdown_body="# pack",
    )
    assert out["success"] is False
    assert out["status"] == "smtp_unconfigured"


def test_send_composes_message_correctly(monkeypatch) -> None:
    """Inject a fake smtp_send to capture what would be sent."""
    monkeypatch.setenv("HALDIR_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("HALDIR_SMTP_FROM", "compliance@haldir.xyz")

    captured: dict = {}

    def fake_send(msg: EmailMessage) -> None:
        captured["msg"] = msg

    out = haldir_email.send_evidence_pack(
        "ciso@acme.com",
        pack={
            "tenant_id": "tenant_xyz",
            "period_start": "2026-04-01T00:00:00+00:00",
            "period_end":   "2026-05-01T00:00:00+00:00",
            "signatures": {"digest": "deadbeef" * 8},
        },
        markdown_body="# Evidence Pack\n\n...content...",
        smtp_send=fake_send,
    )
    assert out["success"] is True
    assert out["status"] == "sent"
    assert out["message_id"]

    msg = captured["msg"]
    assert msg["To"] == "ciso@acme.com"
    assert msg["From"] == "compliance@haldir.xyz"
    assert "audit-prep evidence pack" in msg["Subject"].lower()
    assert msg["X-Haldir-Tenant"] == "tenant_xyz"
    assert msg["X-Haldir-Evidence-Digest"].startswith("deadbeef")

    # The body has the digest inline.
    body = msg.get_body(preferencelist=("plain",))
    assert body is not None
    assert "deadbeef" in body.get_content()

    # Markdown attachment is present.
    attachments = list(msg.iter_attachments())
    assert len(attachments) == 1
    att = attachments[0]
    assert att.get_content_type() == "text/markdown"
    assert "haldir-evidence-tenant_xyz" in att.get_filename()
    content = att.get_content()
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    assert "# Evidence Pack" in content


def test_send_records_smtp_failure(monkeypatch) -> None:
    monkeypatch.setenv("HALDIR_SMTP_HOST", "smtp.example.com")

    def boom(msg: EmailMessage) -> None:
        raise ConnectionError("network unreachable")

    out = haldir_email.send_evidence_pack(
        "ciso@acme.com",
        pack={"signatures": {"digest": "x"},
              "period_start": "a", "period_end": "b", "tenant_id": "t"},
        markdown_body="md",
        smtp_send=boom,
    )
    assert out["success"] is False
    assert out["status"] == "smtp_failed"
    assert "ConnectionError" in out["error"]


# ── fire_one routing through email path ─────────────────────────────

def test_fire_one_email_delivery_routes_through_haldir_email(
    tmp_path, monkeypatch
) -> None:
    """Build an isolated DB + schedule with email delivery; assert
    haldir_email.send_evidence_pack is called with the right addr."""
    import haldir_migrate
    db = str(tmp_path / "email.db")
    haldir_migrate.apply_pending(db)
    s = sched.create_schedule(db, "tnt-email", "x", "daily",
                                "email:cto@example.com")

    captured: dict = {}

    def fake_send_pack(to_addr, pack, markdown_body, **_):
        captured["to"] = to_addr
        captured["pack"] = pack
        captured["md"] = markdown_body
        return {"success": True, "status": "sent",
                "error": "", "message_id": "<test@haldir>"}

    monkeypatch.setattr(haldir_email, "send_evidence_pack", fake_send_pack)
    out = sched.fire_one(db, s)
    assert out["success"] is True
    assert out["status"] == "sent"
    assert captured["to"] == "cto@example.com"
    assert "Audit-Prep Evidence Pack" in captured["md"]


def test_fire_one_email_records_unconfigured(tmp_path, monkeypatch) -> None:
    """Without HALDIR_SMTP_HOST, fire_one's email path returns
    smtp_unconfigured and bumps fail_count."""
    import haldir_migrate
    db = str(tmp_path / "email_no.db")
    haldir_migrate.apply_pending(db)
    monkeypatch.delenv("HALDIR_SMTP_HOST", raising=False)
    s = sched.create_schedule(db, "tnt-noconf", "x", "daily",
                                "email:cto@example.com")
    out = sched.fire_one(db, s)
    assert out["success"] is False
    assert out["status"] == "smtp_unconfigured"
    rows = sched.list_schedules(db, "tnt-noconf")
    assert rows[0]["fail_count"] == 1
