"""
Haldir Watch — Audit logging, compliance, and cost tracking for agents.

Every tool call, every spend, every permission check is recorded.
Watch is the compliance layer that enterprises require before deploying agents.
"""

from .watch import Watch, AuditEntry
from .webhooks import (
    WebhookConfig,
    WebhookManager,
    WebhookVerificationError,
    verify_signature,
)

__all__ = [
    "Watch",
    "AuditEntry",
    "WebhookConfig",
    "WebhookManager",
    "WebhookVerificationError",
    "verify_signature",
]
