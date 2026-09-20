"""
Haldir Watch — Audit trail and cost tracking with persistent storage.

Audit entries are hash-chained: each entry contains a SHA-256 hash of its
contents plus the hash of the previous entry, creating a tamper-evident chain.
If any past entry is modified, all subsequent hashes break.
"""

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from haldir_tracing import traced_span


# How many times an append re-reads the chain tail after losing a race for a
# sequence number. Each retry means a concurrent writer beat us; a handful is
# generous for any realistic write rate, and the loop raises rather than
# spinning forever if the contention is genuinely pathological.
APPEND_ATTEMPTS = 8


def _is_unique_violation(exc: BaseException) -> bool:
    """True for a UNIQUE/PRIMARY KEY conflict on either backend.

    Matched by class name rather than by import: sqlite3 and psycopg2 are
    both optional depending on how Haldir is deployed, and importing either
    at module scope would make the other a hard dependency. sqlite3 raises
    IntegrityError, psycopg2 raises errors.UniqueViolation (a subclass of
    IntegrityError), and both appear in the MRO.
    """
    return any(k.__name__ in ("IntegrityError", "UniqueViolation")
               for k in type(exc).__mro__)


@dataclass
class AuditEntry:
    entry_id: str
    session_id: str
    agent_id: str
    action: str
    tool: str = ""
    details: dict = field(default_factory=dict)
    cost_usd: float = 0.0
    timestamp: float = field(default_factory=time.time)
    flagged: bool = False
    flag_reason: str = ""
    tenant_id: str = ""
    prev_hash: str = ""
    entry_hash: str = ""
    # Position in the tenant's chain. Deliberately NOT part of compute_hash:
    # the hash covers linkage, and adding a field would invalidate every
    # entry written before this column existed, breaking verification of
    # logs that are perfectly intact.
    seq: int = 0

    def compute_hash(self) -> str:
        """SHA-256 hash of entry contents + previous hash = tamper-evident chain.

        Uses normalized representations (2 decimal places for cost, integer seconds
        for timestamp) to avoid precision drift between Python float and Postgres
        REAL column storage.
        """
        ts_int = int(self.timestamp)
        payload = (
            f"{self.entry_id}|{self.session_id}|{self.agent_id}|{self.action}|"
            f"{self.tool}|{json.dumps(self.details, sort_keys=True)}|"
            f"{self.cost_usd:.2f}|{ts_int}|"
            f"{1 if self.flagged else 0}|{self.prev_hash}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class _AdminPrincipal:
    """The stand-in "session" for an admin action.

    log_action expects something with session_id and agent_id, and an audit
    entry has to carry both. An admin action belongs to no agent session, so
    session_id is empty and the agent_id names the acting key instead —
    which is also what makes admin entries findable in the trail.
    """
    session_id: str
    agent_id: str


class Watch:
    """Audit and compliance engine with persistent storage."""

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path
        self._anomaly_rules: list[dict] = []

        conn = self._get_db()
        if conn:
            rows = conn.execute("SELECT * FROM anomaly_rules").fetchall()
            conn.close()
            for r in rows:
                self._anomaly_rules.append({
                    "type": r["rule_type"],
                    "threshold": r["threshold"],
                    "reason": r["reason"],
                })

    def _get_db(self) -> Any:
        if not self._db_path:
            return None
        from haldir_db import get_db
        return get_db(self._db_path)

    @traced_span("haldir.watch.log_action")
    def log_action(self, session: Any, tool: str, action: str,
                   details: Optional[dict[str, Any]] = None, cost_usd: float = 0.0,
                   tenant_id: str = "") -> AuditEntry:
        """Append an entry to the tenant's chain.

        The tail is found by sequence number, and the insert carries the next
        one. Two writers that race therefore collide on the unique index
        rather than both chaining onto the same predecessor — the loser
        re-reads the tail and writes the entry that actually follows.

        This replaces a read of `ORDER BY timestamp DESC LIMIT 1`, which had
        no tiebreak and no constraint behind it. Eight concurrent appends
        produced eight rows of which one was reachable from the head; the
        other seven were on branches, and the log stopped being a chain.
        """
        conn = self._get_db()
        if not conn:
            # No database: build the entry and chain it in memory only.
            return self._build_entry(session, tool, action, details, cost_usd,
                                     tenant_id, prev_hash="", seq=0)

        try:
            for _attempt in range(APPEND_ATTEMPTS):
                row = conn.execute(
                    "SELECT entry_hash, seq FROM audit_log "
                    "WHERE tenant_id = ? ORDER BY seq DESC LIMIT 1",
                    (tenant_id,),
                ).fetchone()
                prev_hash = row["entry_hash"] if row else ""
                seq = (row["seq"] if row else 0) + 1

                entry = self._build_entry(session, tool, action, details,
                                          cost_usd, tenant_id, prev_hash, seq)
                try:
                    conn.execute(
                        "INSERT INTO audit_log (entry_id, tenant_id, session_id, agent_id, action, tool, details, cost_usd, timestamp, flagged, flag_reason, prev_hash, entry_hash, seq) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (entry.entry_id, tenant_id, entry.session_id, entry.agent_id,
                         entry.action, entry.tool, json.dumps(entry.details),
                         entry.cost_usd, entry.timestamp, int(entry.flagged),
                         entry.flag_reason, entry.prev_hash, entry.entry_hash, seq),
                    )
                    conn.commit()
                    return entry
                except Exception as e:  # noqa: BLE001 — re-raised unless it is
                    # the expected collision with a concurrent appender.
                    if not _is_unique_violation(e):
                        raise
                    conn.rollback()

            raise RuntimeError(
                f"could not append to the audit chain after {APPEND_ATTEMPTS} "
                f"attempts — sustained concurrent writes to tenant {tenant_id!r}"
            )
        finally:
            conn.close()

    def _build_entry(self, session: Any, tool: str, action: str,
                     details: Optional[dict[str, Any]], cost_usd: float,
                     tenant_id: str, prev_hash: str, seq: int) -> AuditEntry:
        """Construct and hash one entry. Anomaly rules run BEFORE hashing so
        that the flagged state is covered by the hash — deciding afterwards
        would let the flag be altered without breaking the chain."""
        entry = AuditEntry(
            entry_id=f"aud_{secrets.token_urlsafe(16)}",
            session_id=session.session_id,
            agent_id=session.agent_id,
            action=action,
            tool=tool,
            details=details or {},
            cost_usd=round(cost_usd, 2),
            timestamp=time.time(),  # sub-second precision; hash uses int()
            tenant_id=tenant_id,
            prev_hash=prev_hash,
            seq=seq,
        )

        for rule in self._anomaly_rules:
            if self._check_anomaly(entry, rule):
                entry.flagged = True
                entry.flag_reason = rule.get("reason", "Anomaly detected")
                break

        entry.entry_hash = entry.compute_hash()
        return entry

    def log_admin_action(self, actor: str, action: str,
                         details: Optional[dict[str, Any]] = None,
                         tenant_id: str = "") -> AuditEntry:
        """Record an administrative action in the same chain as agent actions.

        Haldir audits what agents do. Until now it did not audit what is done
        *to* it: creating and revoking API keys left no trace, so "who revoked
        production's key, and when?" had no answer — in a product whose claim
        is that every action is logged. For anyone reviewing whether the audit
        trail is complete, that is the first question, and a gap where the
        credential lifecycle should be is worse than no audit trail at all.

        `actor` is the API key prefix that performed the action: already shown
        in the dashboard, useless for authentication since only the hash is
        stored.

        Goes through log_action so these entries land in the same hash chain,
        carry the same prev_hash linkage, and are covered by the same Merkle
        tree and signed tree heads. An action recorded somewhere else would be
        exactly the kind of thing an attacker would edit.
        """
        return self.log_system_action(
            actor=actor,
            action=f"admin.{action}",
            tool="haldir",
            details=details,
            cost_usd=0.0,
            tenant_id=tenant_id,
            session_id="",
            stamp_actor=True,
            principal_prefix="admin:",
        )

    def log_system_action(self, actor: str, action: str, tool: str = "",
                          details: Optional[dict[str, Any]] = None,
                          cost_usd: float = 0.0, tenant_id: str = "",
                          session_id: str = "", stamp_actor: bool = False,
                          principal_prefix: str = "") -> AuditEntry:
        """Record an action that belongs to no agent session.

        The general form of log_admin_action: the system itself did something
        — settled an x402 payment, ran a retention prune — and it has to land
        in the chain like anything else.

        This exists because two call sites were writing to audit_log with a
        hand-built INSERT and a fabricated `entry_hash` such as
        `f"x402-hash-{entry_id}"`. Those rows never verified: the writer and
        the verifier disagreed about what a chain hash is, so a *legitimate*
        payment made verify_chain report tampering. Going through log_action
        means one implementation of the hash, and the entry is covered by the
        same Merkle tree and signed tree heads as everything else.

        `cost_usd` is real here — an x402 settlement moves money, and a
        system action that spends is exactly the kind of thing the trail is
        for.
        """
        # `principal_prefix` labels the agent_id without altering the actor
        # recorded in details — prefixing the actor itself and then stamping
        # it recorded "admin:hld_abc12345" as the actor, which is a different
        # key from the one that acted.
        principal = _AdminPrincipal(
            session_id=session_id,
            agent_id=f"{principal_prefix}{actor}" if actor else "system",
        )
        payload = dict(details or {})
        if stamp_actor:
            payload["actor"] = actor or "unknown"
        return self.log_action(
            principal,
            tool=tool,
            action=action,
            details=payload,
            cost_usd=cost_usd,
            tenant_id=tenant_id,
        )

    def get_audit_trail(self, session_id: str | None = None,
                        agent_id: str | None = None,
                        tool: str | None = None,
                        since: float | None = None,
                        flagged_only: bool = False,
                        limit: int = 100,
                        tenant_id: str = "") -> list[AuditEntry]:
        conn = self._get_db()
        if conn:
            query = "SELECT * FROM audit_log WHERE tenant_id = ?"
            params: list[Any] = [tenant_id]
            if session_id:
                query += " AND session_id = ?"
                params.append(session_id)
            if agent_id:
                query += " AND agent_id = ?"
                params.append(agent_id)
            if tool:
                query += " AND tool = ?"
                params.append(tool)
            if since:
                query += " AND timestamp >= ?"
                params.append(since)
            if flagged_only:
                query += " AND flagged = 1"
            # seq first: it is unique per tenant and follows write order.
            # timestamp is the tiebreak for a log that has not been numbered
            # yet (all seq = 0), so ordering degrades to the old behaviour
            # rather than to something arbitrary.
            query += " ORDER BY seq DESC, timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            conn.close()
            return [
                AuditEntry(
                    entry_id=r["entry_id"],
                    session_id=r["session_id"],
                    agent_id=r["agent_id"],
                    action=r["action"],
                    tool=r["tool"],
                    details=json.loads(r["details"]),
                    cost_usd=r["cost_usd"],
                    timestamp=r["timestamp"],
                    flagged=bool(r["flagged"]),
                    flag_reason=r["flag_reason"],
                    tenant_id=tenant_id,
                    prev_hash=r["prev_hash"] if "prev_hash" in r.keys() else "",
                    entry_hash=r["entry_hash"] if "entry_hash" in r.keys() else "",
                    seq=r["seq"] if "seq" in r.keys() else 0,
                )
                for r in rows
            ]
        return []

    def get_spend(self, session_id: str | None = None,
                  agent_id: str | None = None,
                  tenant_id: str = "") -> dict:
        conn = self._get_db()
        if conn:
            query = "SELECT tool, SUM(cost_usd) as total, COUNT(*) as cnt FROM audit_log WHERE tenant_id = ?"
            params = [tenant_id]
            if session_id:
                query += " AND session_id = ?"
                params.append(session_id)
            if agent_id:
                query += " AND agent_id = ?"
                params.append(agent_id)
            query += " GROUP BY tool"
            rows = conn.execute(query, params).fetchall()

            total_query = "SELECT SUM(cost_usd) as total, COUNT(*) as cnt FROM audit_log WHERE tenant_id = ?"
            total_params = [tenant_id]
            if session_id:
                total_query += " AND session_id = ?"
                total_params.append(session_id)
            elif agent_id:
                total_query += " AND agent_id = ?"
                total_params.append(agent_id)
            total_row = conn.execute(total_query, total_params).fetchone()
            conn.close()

            by_tool = {r["tool"]: round(r["total"], 4) for r in rows if r["tool"]}
            return {
                "total_usd": round(total_row["total"] or 0, 4),
                "action_count": total_row["cnt"] or 0,
                "by_tool": by_tool,
            }
        return {"total_usd": 0, "action_count": 0, "by_tool": {}}

    def add_anomaly_rule(self, rule_type: str, threshold: float, reason: str = "",
                         tenant_id: str = "") -> None:
        rule: dict[str, Any] = {
            "type": rule_type,
            "threshold": threshold,
            "reason": reason or f"{rule_type} exceeded {threshold}",
        }
        self._anomaly_rules.append(rule)

        conn = self._get_db()
        if conn:
            conn.execute(
                "INSERT INTO anomaly_rules (tenant_id, rule_type, threshold, reason, created_at) VALUES (?, ?, ?, ?, ?)",
                (tenant_id, rule_type, threshold, rule["reason"], time.time())
            )
            conn.commit()
            conn.close()

    def _check_anomaly(self, entry: AuditEntry, rule: dict[str, Any]) -> bool:
        if rule["type"] == "spend_per_action":
            return bool(entry.cost_usd > rule["threshold"])
        if rule["type"] == "actions_per_minute":
            conn = self._get_db()
            if conn:
                one_min_ago = time.time() - 60
                count = conn.execute(
                    "SELECT COUNT(*) FROM audit_log WHERE agent_id = ? AND tenant_id = ? AND timestamp >= ?",
                    (entry.agent_id, entry.tenant_id, one_min_ago)
                ).fetchone()[0]
                conn.close()
                return bool(count >= rule["threshold"])
        if rule["type"] == "tool_blocked":
            return entry.tool == str(rule["threshold"])
        return False

    def flag_anomaly(self, entry_id: str, reason: str, tenant_id: str = "") -> bool:
        conn = self._get_db()
        if conn:
            conn.execute(
                "UPDATE audit_log SET flagged = 1, flag_reason = ? WHERE entry_id = ? AND tenant_id = ?",
                (reason, entry_id, tenant_id))
            conn.commit()
            affected = conn.total_changes
            conn.close()
            return bool(affected > 0)
        return False

    def verify_chain(self, tenant_id: str = "", limit: int = 10000) -> dict:
        """Verify the hash chain integrity of the audit log.

        Walks the chain from oldest to newest, recomputing each hash.
        If any entry was tampered with, the chain breaks at that point.
        """
        conn = self._get_db()
        if not conn:
            return {"verified": False, "error": "No database"}

        rows = conn.execute(
            "SELECT * FROM audit_log WHERE tenant_id = ? "
            "ORDER BY seq ASC, timestamp ASC LIMIT ?",
            (tenant_id, limit)
        ).fetchall()
        conn.close()

        if not rows:
            return {"verified": True, "entries_checked": 0, "message": "Empty audit log"}

        # If retention has pruned this tenant's log, the oldest surviving entry
        # commits to a hash that is deliberately gone. Start from the recorded
        # boundary instead of from empty, or every pruned log would report as
        # broken — which would make pruning strictly worse than not pruning.
        #
        # This does not weaken the check: the boundary hash is the hash of the
        # newest removed entry, so the survivors still have to chain back to
        # something real, and the checkpoint carries the signed tree head that
        # commits to everything before it.
        prev_hash = ""
        pruned = None
        try:
            import haldir_retention
            ck = (haldir_retention.latest_checkpoint(self._db_path, tenant_id)
                  if self._db_path else None)
        except Exception:
            ck = None
        if ck:
            prev_hash = ck.get("last_pruned_entry_hash") or ""
            pruned = {
                "checkpoint_id":    ck.get("checkpoint_id"),
                "pruned_before":    ck.get("pruned_before"),
                "entries_deleted":  ck.get("entries_deleted"),
                "tree_size":        ck.get("tree_size"),
                "root_hash":        ck.get("root_hash"),
                "signed_at":        ck.get("signed_at"),
                "note": ("Entries older than pruned_before were removed under a "
                         "retention policy. The signed tree head above is the "
                         "commitment to them."),
            }

        for i, r in enumerate(rows):
            entry = AuditEntry(
                entry_id=r["entry_id"], session_id=r["session_id"],
                agent_id=r["agent_id"], action=r["action"], tool=r["tool"],
                details=json.loads(r["details"]), cost_usd=r["cost_usd"],
                timestamp=r["timestamp"], flagged=bool(r["flagged"]),
                prev_hash=r["prev_hash"],
                seq=r["seq"] if "seq" in r.keys() else 0,
            )
            expected_hash = entry.compute_hash()
            stored_hash = r["entry_hash"]

            if stored_hash and stored_hash != expected_hash:
                return {
                    "verified": False,
                    "entries_checked": i + 1,
                    "tampered_entry": r["entry_id"],
                    "error": "Entry hash mismatch — data was modified",
                }
            if entry.prev_hash and entry.prev_hash != prev_hash:
                return {
                    "verified": False,
                    "entries_checked": i + 1,
                    "broken_at": r["entry_id"],
                    "error": "Chain broken — previous entry was modified or deleted",
                }
            prev_hash = stored_hash or expected_hash

        result = {
            "verified": True,
            "entries_checked": len(rows),
            "message": "Audit chain integrity verified",
        }
        if pruned:
            # Surfaced rather than silent: "the log is shorter than it was"
            # is something an auditor should be told, not left to notice.
            result["pruned"] = pruned
        return result

    def export_log(self, format: str = "json", limit: int = 1000, tenant_id: str = "") -> str | list[dict]:
        entries = self.get_audit_trail(limit=limit, tenant_id=tenant_id)
        records = [
            {"id": e.entry_id, "session": e.session_id, "agent": e.agent_id,
             "action": e.action, "tool": e.tool, "cost_usd": e.cost_usd,
             "flagged": e.flagged, "flag_reason": e.flag_reason,
             "timestamp": e.timestamp, "details": e.details}
            for e in entries
        ]
        if format == "json":
            return json.dumps(records, indent=2)
        return records
