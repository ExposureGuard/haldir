"""
Haldir SDK — Python client for the Haldir REST API.

Sync and async wrappers for Gate, Vault, Watch, and Payments.
"""

from .client import (
    HaldirClient,
    HaldirAsyncClient,
    HaldirAPIError,
    HaldirAuthError,
    HaldirPermissionError,
    HaldirNotFoundError,
)

# Receiver-side helper. Re-exported so customers writing webhook
# handlers do `from haldir import verify_webhook_signature` instead of
# reaching into `haldir_watch.webhooks` — one public import path for
# the security-critical surface.
from haldir_watch.webhooks import (  # noqa: E402
    verify_signature as verify_webhook_signature,
    WebhookVerificationError,
)

# RFC 6962 audit-tree verification helpers. Customers or auditors
# holding an inclusion or consistency proof (returned by the
# /v1/audit/* Merkle endpoints) can verify it offline — no network,
# no trust in the Haldir server beyond the STH signing key they
# already hold. One public import path for the whole tamper-evidence
# story.
from haldir_merkle import (  # noqa: E402
    verify_inclusion_hex as verify_inclusion_proof,
    verify_consistency_hex as verify_consistency_proof,
    verify_sth,
)

__all__ = [
    "HaldirClient",
    "HaldirAsyncClient",
    "HaldirAPIError",
    "HaldirAuthError",
    "HaldirPermissionError",
    "HaldirNotFoundError",
    "verify_webhook_signature",
    "WebhookVerificationError",
    "verify_inclusion_proof",
    "verify_consistency_proof",
    "verify_sth",
]
