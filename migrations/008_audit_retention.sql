-- Haldir migration 008: audit retention windows and prune checkpoints.
--
-- Two problems, one feature.
--
-- The compliance one: every security questionnaire asks how long audit data
-- is kept and whether it can be deleted. Until now the answer was "forever,
-- and no" — there was no policy and no way to act on one. For a tenant with
-- a data-deletion obligation that is not a missing feature, it is a
-- compliance failure.
--
-- The operational one: the audit log is append-only and unbounded. Nothing
-- pruned it, so it grew at whatever rate the tenant's agents worked.
--
-- ── Why this needs a checkpoint ────────────────────────────────────────
--
-- The audit log is a hash chain: each entry commits to the hash of the one
-- before it. Deleting the oldest entries naively leaves the new-oldest entry
-- pointing at a hash that no longer exists, and `verify_chain` — which starts
-- from an empty prev_hash — reports the surviving chain as broken. Retention
-- without this table would turn a working audit trail into a failing one.
--
-- So before deleting, we take a Signed Tree Head over the log as it stands
-- and record the hash of the last entry being removed. That hash is the link
-- across the boundary:
--
--   * verification starts from `last_pruned_entry_hash` instead of ""
--   * the STH is the cryptographic commitment to everything that was removed
--
-- The effect is that pruning is *provable* rather than silent. An auditor is
-- told "entries before this point were deleted under a retention policy, and
-- here is the signed Merkle root they produced at the time" — which is a far
-- better answer than a chain that either breaks or quietly gets shorter.
--
-- Same shape as Certificate Transparency log sharding: you cannot keep
-- everything forever, so you keep a signed commitment to what you dropped.

CREATE TABLE IF NOT EXISTS audit_retention (
    tenant_id     TEXT    PRIMARY KEY,
    -- Days to keep. 0 means keep forever, which is the default and the
    -- behaviour every existing tenant already has.
    retain_days   INTEGER NOT NULL DEFAULT 0,
    updated_at    DOUBLE PRECISION NOT NULL,
    updated_by    TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    checkpoint_id           TEXT    PRIMARY KEY,
    tenant_id               TEXT    NOT NULL,
    -- Entries with timestamp < pruned_before were removed.
    pruned_before           DOUBLE PRECISION NOT NULL,
    -- The chain link across the boundary: the entry_hash of the newest entry
    -- that was removed. Verification of the survivors starts here.
    last_pruned_entry_hash  TEXT    NOT NULL DEFAULT '',
    entries_deleted         INTEGER NOT NULL DEFAULT 0,
    -- Signed Tree Head over the log as it stood BEFORE the delete. This is
    -- the commitment to what was removed.
    tree_size               INTEGER NOT NULL DEFAULT 0,
    root_hash               TEXT    NOT NULL DEFAULT '',
    algorithm               TEXT    NOT NULL DEFAULT '',
    signature               TEXT    NOT NULL DEFAULT '',
    signed_at               DOUBLE PRECISION NOT NULL DEFAULT 0,
    key_id                  TEXT    NOT NULL DEFAULT '',
    public_key              TEXT    NOT NULL DEFAULT '',
    created_at              DOUBLE PRECISION NOT NULL,
    created_by              TEXT    NOT NULL DEFAULT ''
);

-- Checkpoints are read newest-first per tenant on every chain verification.
CREATE INDEX IF NOT EXISTS idx_checkpoints_tenant
    ON audit_checkpoints(tenant_id, created_at DESC);
