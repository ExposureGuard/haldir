"""
Haldir email dispatcher — SMTP send for compliance evidence packs.

Stdlib-only. Uses smtplib + email.message.EmailMessage so there's no
new wheel in the runtime image. Configuration is via env vars (12-
factor — operators set them in Railway / kubectl / docker-compose,
not in code):

  HALDIR_SMTP_HOST       hostname (e.g. smtp.sendgrid.net)
  HALDIR_SMTP_PORT       int (default 587)
  HALDIR_SMTP_USER       optional username
  HALDIR_SMTP_PASSWORD   optional password / API token
  HALDIR_SMTP_FROM       sender address (default: noreply@haldir.xyz)
  HALDIR_SMTP_USE_TLS    "1" to STARTTLS upgrade after EHLO (default 1)

Dispatch is a one-shot helper — there is no retry queue at this
layer. The compliance scheduler treats a delivery failure as a
recorded run with success=False, so operators see it in
`haldir compliance schedules list` and can investigate. Adding a
proper retry loop with exponential backoff is a follow-up; for v1
the SMTP server's own queue handles transient blips.

Returns a result dict so callers can record what happened:
  {success: bool, status: str, error: str, message_id: str | None}
"""

from __future__ import annotations

import os
import smtplib
import ssl
import time
import uuid
from email.message import EmailMessage
from typing import Any

from haldir_logging import get_logger


log = get_logger("haldir.email")


# ── Configuration ────────────────────────────────────────────────────

def _is_configured() -> bool:
    return bool(os.environ.get("HALDIR_SMTP_HOST"))


def _from_addr() -> str:
    return os.environ.get("HALDIR_SMTP_FROM", "noreply@haldir.xyz")


# ── Dispatch ────────────────────────────────────────────────────────

def send_evidence_pack(
    to_addr: str,
    pack: dict[str, Any],
    markdown_body: str,
    *,
    smtp_send: Any = None,
) -> dict[str, Any]:
    """Send the evidence pack as a multipart message: a short text
    summary + the Markdown body as a `.md` attachment.

    `smtp_send` lets tests inject a fake send function — production
    callers leave it None and we use smtplib."""
    if not _is_configured():
        return {
            "success":    False,
            "status":     "smtp_unconfigured",
            "error":      "HALDIR_SMTP_HOST not set",
            "message_id": None,
        }

    msg = _build_message(to_addr, pack, markdown_body)
    sender = smtp_send or _smtp_send_real

    try:
        sender(msg)
    except Exception as e:
        log.exception("smtp send failed", extra={"to": to_addr})
        return {
            "success":    False,
            "status":     "smtp_failed",
            "error":      f"{type(e).__name__}: {e}",
            "message_id": msg["Message-ID"],
        }
    return {
        "success":    True,
        "status":     "sent",
        "error":      "",
        "message_id": msg["Message-ID"],
    }


def _build_message(to_addr: str, pack: dict[str, Any],
                    markdown_body: str) -> EmailMessage:
    """Compose the EmailMessage. Uses the IMF Message-ID format so the
    receiver-side dedupe + reply threading works."""
    digest = pack["signatures"]["digest"]
    period = f"{pack['period_start']} → {pack['period_end']}"
    tenant = pack["tenant_id"]
    msg_id = f"<{uuid.uuid4().hex}.{int(time.time())}@haldir.xyz>"

    msg = EmailMessage()
    msg["From"] = _from_addr()
    msg["To"] = to_addr
    msg["Subject"] = f"Haldir compliance evidence pack — {period}"
    msg["Message-ID"] = msg_id
    msg["X-Haldir-Tenant"] = tenant
    msg["X-Haldir-Evidence-Digest"] = digest

    summary = (
        f"Haldir compliance evidence pack\n"
        f"\n"
        f"Tenant:   {tenant}\n"
        f"Period:   {period}\n"
        f"Digest:   {digest}\n"
        f"\n"
        f"The full evidence pack is attached as Markdown. Sections:\n"
        f"  1. Identity\n"
        f"  2. Access control          (SOC2 CC6.1)\n"
        f"  3. Encryption              (SOC2 CC6.7)\n"
        f"  4. Audit trail             (SOC2 CC7.2)\n"
        f"  5. Spend governance        (SOC2 CC5.2)\n"
        f"  6. Human approvals         (SOC2 CC8.1)\n"
        f"  7. Outbound alerting       (SOC2 CC7.3)\n"
        f"  8. Document signature\n"
        f"\n"
        f"Verify the digest by re-issuing the pack against the same\n"
        f"period via /v1/compliance/evidence/manifest and comparing.\n"
        f"\n"
        f"-- Haldir\n"
    )
    msg.set_content(summary)

    # Attach the Markdown body. Filename includes tenant + ISO date so
    # operators dropping it in evidence lockers don't collide.
    safe_tenant = tenant.replace("/", "_")[:32] or "tenant"
    filename = f"haldir-evidence-{safe_tenant}-{digest[:12]}.md"
    msg.add_attachment(
        markdown_body.encode("utf-8"),
        maintype="text", subtype="markdown",
        filename=filename,
    )
    return msg


def _smtp_send_real(msg: EmailMessage) -> None:
    """Real SMTP send. Honors HALDIR_SMTP_PORT + STARTTLS env."""
    host = os.environ["HALDIR_SMTP_HOST"]
    port = int(os.environ.get("HALDIR_SMTP_PORT", "587"))
    user = os.environ.get("HALDIR_SMTP_USER", "")
    password = os.environ.get("HALDIR_SMTP_PASSWORD", "")
    use_tls = os.environ.get("HALDIR_SMTP_USE_TLS", "1") == "1"

    with smtplib.SMTP(host, port, timeout=15) as s:
        s.ehlo()
        if use_tls:
            s.starttls(context=ssl.create_default_context())
            s.ehlo()
        if user and password:
            s.login(user, password)
        s.send_message(msg)
