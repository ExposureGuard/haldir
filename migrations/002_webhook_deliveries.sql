-- Haldir migration 002: webhook delivery log.
--
-- Every webhook fire records one or more delivery attempts here, so
-- operators can answer the question every enterprise buyer asks:
-- "did my webhook get through, and if not, why?"
--
-- Why a new table instead of denormalizing into `webhooks`:
--   - A single webhook endpoint fires thousands of events; one row
--     per webhook can't capture attempt-level detail.
--   - Delivery state (status_code, response excerpt, error message)
--     is per-attempt — retry 2 may succeed where retry 1 failed.
--   - Bounded retention is easier on a narrow table: future pruning
--     migration can `DELETE FROM webhook_deliveries WHERE created_at
--     < ?` without touching the webhooks registration table.
--
-- event_id     Stable identity of the business event (e.g. the audit
--              entry_id that triggered it). Consumers dedupe on this;
--              retry attempts share the same event_id.
-- delivery_id  Per-attempt UUID. Logged on the Haldir side; Haldir
--              sends the EVENT id in the X-Haldir-Webhook-Id header
--              so receivers dedupe on event, not attempt.
-- attempt      Starts at 1. Increments on retry.
-- status_code  HTTP response code; 0 if the request never completed
--              (network error, timeout).
-- response_excerpt  First 512 bytes of the receiver's response body,
--                   for operator debugging. Not the full response —
--                   receivers sometimes echo the payload back.

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    delivery_id      TEXT    PRIMARY KEY,
    event_id         TEXT    NOT NULL,
    tenant_id        TEXT    NOT NULL DEFAULT '',
    webhook_url      TEXT    NOT NULL,
    event_type       TEXT    NOT NULL,
    attempt          INTEGER NOT NULL DEFAULT 1,
    status_code      INTEGER NOT NULL DEFAULT 0,
    response_excerpt TEXT    NOT NULL DEFAULT '',
    error            TEXT    NOT NULL DEFAULT '',
    duration_ms      INTEGER NOT NULL DEFAULT 0,
    created_at       REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_deliveries_tenant   ON webhook_deliveries(tenant_id);
CREATE INDEX IF NOT EXISTS idx_deliveries_event    ON webhook_deliveries(event_id);
CREATE INDEX IF NOT EXISTS idx_deliveries_created  ON webhook_deliveries(created_at);
