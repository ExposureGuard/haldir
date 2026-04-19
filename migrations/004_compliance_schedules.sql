-- Haldir migration 004: scheduled compliance-pack delivery.
--
-- A tenant can register N schedules. Each schedule says "every
-- <cadence>, generate a fresh compliance evidence pack covering the
-- prior <cadence> and fire it at <delivery>."
--
-- Cadences are coarse — daily / weekly / monthly / quarterly. SOC2
-- audits operate on quarterly cycles; CISOs want monthly heartbeats.
-- Anything finer-grained than daily is observability, not compliance.
--
-- Delivery currently supports `webhook:<webhook_id>` (re-uses the
-- production-grade delivery path with retries + dead-letter logging
-- already in place). Future deliveries: `email:<addr>`, `s3://bucket`,
-- `gcs://bucket` — each is a new delivery scheme parsed by the
-- worker.
--
-- last_run_at tracks the most recent successful generation; the
-- worker's "is this due" check is `now - last_run_at >= cadence_seconds`.
-- A schedule with last_run_at=0 is due immediately (the first run).

CREATE TABLE IF NOT EXISTS compliance_schedules (
    schedule_id     TEXT    PRIMARY KEY,
    tenant_id       TEXT    NOT NULL,
    name            TEXT    NOT NULL DEFAULT '',
    cadence         TEXT    NOT NULL,           -- 'daily' | 'weekly' | 'monthly' | 'quarterly'
    delivery        TEXT    NOT NULL,           -- 'webhook:<id>' (extensible)
    active          INTEGER NOT NULL DEFAULT 1,
    created_at      DOUBLE PRECISION NOT NULL,
    last_run_at     DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_status     TEXT    NOT NULL DEFAULT '',
    last_error      TEXT    NOT NULL DEFAULT '',
    run_count       INTEGER NOT NULL DEFAULT 0,
    fail_count      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_schedules_tenant   ON compliance_schedules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_schedules_due      ON compliance_schedules(active, last_run_at);
