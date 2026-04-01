"""
Haldir Gate — Agent identity, authentication, and permissions.

Every agent gets a session with scoped permissions. No session = no access.
"""

from .gate import Gate, Session, Permission

__all__ = ["Gate", "Session", "Permission"]
