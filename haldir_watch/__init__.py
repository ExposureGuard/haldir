"""
Haldir Watch — Audit logging, compliance, and cost tracking for agents.

Every tool call, every spend, every permission check is recorded.
Watch is the compliance layer that enterprises require before deploying agents.
"""

from .watch import (
    HASH_VERSION_COST_PRECISION,
    HASH_VERSION_CURRENT,
    HASH_VERSION_FLAG_REASON,
    HASH_VERSION_LEGACY,
    AuditEntry,
    Watch,
)
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
    # Exported because they are part of the verification contract: anyone
    # checking a chain independently, including a customer's auditor, has to
    # know which rule a given entry was hashed under. An entry carries its
    # own version; these name the versions that exist.
    "HASH_VERSION_LEGACY",
    "HASH_VERSION_FLAG_REASON",
    "HASH_VERSION_COST_PRECISION",
    "HASH_VERSION_CURRENT",
]
