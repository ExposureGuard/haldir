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

__all__ = [
    "HaldirClient",
    "HaldirAsyncClient",
    "HaldirAPIError",
    "HaldirAuthError",
    "HaldirPermissionError",
    "HaldirNotFoundError",
]
