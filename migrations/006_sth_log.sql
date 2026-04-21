-- Haldir migration 006: self-published Signed Tree Head log.
--
-- Every STH the server signs (via haldir_audit_tree.get_tree_head)
-- gets persisted here. The (tenant_id, tree_size) primary key gives
-- idempotency — repeated requests for the same tree size never write
-- duplicates, but the FIRST observation of a new tree size is captured
-- forever.
--
-- Why this exists:
--
--   The Merkle tree we sign answers "is THIS entry in the log right
--   now?" The audit hash chain answers "has any individual entry been
--   mutated?" Neither answers the meta-question:
--
--     "Has Haldir-the-server shown different STHs to different
--      auditors at the same wall-clock time?"
--
--   That's the equivocation attack. Same primitive Certificate
--   Transparency monitors run distributed gossip to detect.
--
--   The SELF-PUBLISHED log is the first defence: any auditor can
--   demand the full STH history at any time (GET /v1/audit/sth-log).
--   If two auditors get back inconsistent histories, equivocation is
--   provable. If Haldir tries to rewrite an old STH to fit a current
--   narrative, the consistency check (GET /v1/audit/sth-log/verify)
--   catches it: the auditor's pinned STH from last month either
--   matches the row at that tree_size, or doesn't — there's nowhere
--   to hide.
--
-- Future: phase 2 mirrors this log to an external transparency
-- monitor (Sigstore / Rekor / on-chain via EAS) so even Haldir's
-- internal DB can't be quietly rewritten.
--
-- Storage cost: O(tenant tree growth). At ~one STH per 1000 entries
-- (cap below) this is rounding error vs. the audit log itself.

CREATE TABLE IF NOT EXISTS sth_log (
    tenant_id     TEXT    NOT NULL,
    tree_size     INTEGER NOT NULL,
    root_hash     TEXT    NOT NULL,
    algorithm     TEXT    NOT NULL,
    signature     TEXT    NOT NULL,
    signed_at     INTEGER NOT NULL,
    key_id        TEXT    NOT NULL DEFAULT '',
    public_key    TEXT    NOT NULL DEFAULT '',
    recorded_at   DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (tenant_id, tree_size)
);

CREATE INDEX IF NOT EXISTS idx_sth_log_tenant_size
    ON sth_log(tenant_id, tree_size);

CREATE INDEX IF NOT EXISTS idx_sth_log_signed_at
    ON sth_log(tenant_id, signed_at);
