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

__all__ = [
    "HaldirClient",
    "HaldirAsyncClient",
    "HaldirAPIError",
    "HaldirAuthError",
    "HaldirPermissionError",
    "HaldirNotFoundError",
    "verify_webhook_signature",
    "WebhookVerificationError",
]
