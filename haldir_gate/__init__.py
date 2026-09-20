"""
Haldir Gate — Agent identity, authentication, and permissions.

Every agent gets a session with scoped permissions. No session = no access.
"""

from .gate import (
    Gate,
    Session,
    Permission,
    DelegationError,
    MAX_DELEGATION_DEPTH,
    reserve_spend,
)

__all__ = [
    "Gate",
    "Session",
    "Permission",
    "DelegationError",
    "MAX_DELEGATION_DEPTH",
    "reserve_spend",
]
