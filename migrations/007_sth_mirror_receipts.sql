-- Haldir migration 007: external transparency-mirror receipts.
--
-- Context: migration 006 (sth_log) gave Haldir a SELF-published record
-- of every STH it ever signed. The residual risk named in
-- THREAT_MODEL.md §10.3 is that a coordinated DB-write attacker could
-- rewrite both audit_log AND sth_log in a single transaction. No
-- in-process primitive defeats that.
--
-- The mirror layer closes that loop. Every STH is additionally pushed
-- to an EXTERNAL, append-only log (Sigstore Rekor, a file the
-- operator rotates, a webhook to a third-party archiver — backend is
-- pluggable). This table records the RECEIPT each external backend
-- returned. Two properties that matter:
--
--   1. Every row is a cryptographic witness created by code that
--      doesn't share a DB with Haldir.
--   2. The receipt_id + log_index let an auditor independently
--      reproduce the STH by querying the external log directly,
--      bypassing Haldir entirely.
--
-- Coordinated attacker would now have to compromise Haldir's DB +
-- every external mirror + every auditor's pinned receipt in the same
-- window. Not a complete defeat, but a multi-order-of-magnitude
-- escalation of the attack cost.
--
-- `backend` is an opaque string identifier (e.g. "rekor:v1",
-- "file:/var/log/haldir/sth.jsonl", "webhook:haldir-archiver"). The
-- schema doesn't know about specific backends — callers check
-- receipt_json for backend-specific fields.
--
-- `mirrored_at` is Haldir's wall-clock at publish time. `receipt_json`
-- is whatever the backend returned (could be {uuid, logIndex, ...}
-- for Rekor, {sha256, offset} for a file backend, etc.). Keeping it
-- as raw JSON means we never have to migrate the schema when we add
-- a new backend.
--
-- Multiple mirror attempts for the same (tenant, tree_size, backend)
-- are allowed — they represent retry history. Queries that want "the
-- most recent receipt" should ORDER BY mirrored_at DESC LIMIT 1.

CREATE TABLE IF NOT EXISTS sth_mirror_receipts (
    tenant_id      TEXT    NOT NULL,
    tree_size      INTEGER NOT NULL,
    backend        TEXT    NOT NULL,
    receipt_id     TEXT    NOT NULL DEFAULT '',
    log_index      BIGINT  NOT NULL DEFAULT 0,
    mirrored_at    DOUBLE PRECISION NOT NULL,
    success        INTEGER NOT NULL DEFAULT 1,
    receipt_json   TEXT    NOT NULL DEFAULT '{}',
    error_message  TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sth_mirror_tenant_tree
    ON sth_mirror_receipts(tenant_id, tree_size);

CREATE INDEX IF NOT EXISTS idx_sth_mirror_backend
    ON sth_mirror_receipts(backend, mirrored_at DESC);
