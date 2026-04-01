"""
Haldir SDK — Unified interface for Gate, Vault, and Watch.
"""

from haldir_gate import Gate, Session, Permission
from haldir_vault import Vault
from haldir_watch import Watch


class Haldir:
    """
    Unified Haldir client.

    Usage:
        h = Haldir(api_key="your-key")
        session = h.gate.create_session("my-agent", scopes=["read", "spend:50"])
        secret = h.vault.get_secret("stripe_key", session=session)
        h.watch.log_action(session, tool="stripe", action="charge", cost_usd=29.99)
    """

    def __init__(self, api_key: str | None = None):
        self.gate = Gate(api_key=api_key)
        self.vault = Vault()
        self.watch = Watch()

    def create_agent(self, agent_id: str, scopes: list[str] | None = None,
                     max_spend: float = 0.0) -> Session:
        """Register an agent and create a session in one call."""
        self.gate.register_agent(agent_id, default_scopes=scopes, max_spend=max_spend)
        return self.gate.create_session(agent_id, scopes=scopes)

    def execute(self, session: Session, tool: str, action: str,
                cost_usd: float = 0.0, **details) -> dict:
        """
        Execute an action through the full Haldir pipeline:
        1. Check permission (Gate)
        2. Authorize spend if needed (Vault)
        3. Log the action (Watch)
        """
        # Gate check
        if not session.is_valid:
            return {"allowed": False, "reason": "Session invalid or expired"}

        if not session.has_permission("execute"):
            if not session.has_permission(action):
                return {"allowed": False, "reason": f"No '{action}' permission"}

        # Spend check
        if cost_usd > 0:
            if not session.authorize_spend(cost_usd):
                return {
                    "allowed": False,
                    "reason": f"Budget exceeded. Remaining: ${session.remaining_budget:.2f}",
                }
            session.record_spend(cost_usd)

        # Audit log
        entry = self.watch.log_action(
            session, tool=tool, action=action, cost_usd=cost_usd, details=details
        )

        return {
            "allowed": True,
            "audit_id": entry.entry_id,
            "flagged": entry.flagged,
            "remaining_budget": session.remaining_budget,
        }


__all__ = ["Haldir", "Gate", "Vault", "Watch", "Session", "Permission"]
