"""
Haldir Vault — Secrets management and payment authorization for agents.

Agents never see raw credentials. They request access through scoped sessions
and Vault injects secrets into API calls on their behalf.
"""

from .vault import Vault, SecretEntry

__all__ = ["Vault", "SecretEntry"]
