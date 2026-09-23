"""
Haldir — the public import surface.

`from haldir import HaldirClient` is the import every published example uses:
the README, the integration READMEs, six blog posts, the CHANGELOG, and the
SDK's own docstring. Until this file existed it had never worked. The
distribution is named `haldir`, but installing it provided `sdk`, `cli`,
`api` and the `haldir_*` modules — and nothing importable as `haldir` — so
every one of those examples raised ModuleNotFoundError on its first line.
The README was the only surface that worked, because it had been written
against the internal name `sdk.client` instead.

Re-exporting here rather than renaming `sdk` leaves the internal layout
alone while giving the documented name something to resolve to.

These are the same objects, not copies — `haldir.HaldirClient is
sdk.HaldirClient`. A copy is the drift this module exists to prevent: two
names that look interchangeable until one is updated.
"""

from sdk import (
    # Client, and the exception hierarchy callers are expected to catch.
    HaldirClient,
    HaldirAsyncClient,
    HaldirAPIError,
    HaldirAuthError,
    HaldirPermissionError,
    HaldirNotFoundError,
    # Receiver-side webhook verification. A webhook consumer needs this and
    # nothing else, so it should not have to reach into haldir_watch.
    verify_webhook_signature,
    WebhookVerificationError,
    # RFC 6962 audit-tree verification. An auditor holding a proof can check
    # it offline — no network, and no trust in the server beyond the STH
    # signing key they already hold.
    verify_inclusion_proof,
    verify_consistency_proof,
    verify_sth,
    verify_rekor_receipt,
    STH_ALGORITHM_HMAC,
    STH_ALGORITHM_ED25519,
)

# The version, so `haldir.__version__` can answer the first question in any bug
# report. A literal rather than importlib.metadata, deliberately: CI imports
# this module from a source checkout where the distribution is not installed at
# all, and a developer venv may hold a stale one — this machine's reports 0.3.0
# while the checkout is 0.4.1. Reading metadata would raise in the first case
# and quietly return a wrong answer in the second.
#
# tests/test_version.py holds this equal to pyproject.toml, which is the same
# guard the other version literals in this tree are under.
__version__ = "0.4.1"

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
    "verify_rekor_receipt",
    "STH_ALGORITHM_HMAC",
    "STH_ALGORITHM_ED25519",
    "__version__",
]
