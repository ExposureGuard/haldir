-- Haldir migration 009: OAuth clients and authorization codes.
--
-- Why this exists
-- ---------------
-- MCP clients — Claude's custom connectors among them — reach a remote server
-- by signing in with a browser. Haldir authenticates with an API key, so the
-- only ways in were a beta header field or installing Node to run a bridge.
-- This adds the authorization-code flow that turns one button press into an
-- ordinary `hld_` key.
--
-- ── Why this state is in the database ──────────────────────────────────
--
-- Both tables would be simpler as in-process dicts, and both would be wrong.
-- Production runs two gunicorn workers: a client registered on one is unknown
-- to the other, and a code minted on one cannot be redeemed on the other. The
-- browser makes two separate round trips through the load balancer, so the
-- failure would land on roughly half of all attempts and look like a broken
-- client rather than a broken deployment.
--
-- ── Why codes are stored hashed ────────────────────────────────────────
--
-- An authorization code is a bearer credential: whoever holds it, and can
-- produce the PKCE verifier, receives a key. `code_hash` stores a SHA-256 the
-- same way `api_keys.key_hash` does, so a database leak does not hand over
-- redeemable codes.
--
-- ── Why `used_at` rather than deleting spent codes ─────────────────────
--
-- A replayed code has to be *recognisably* replayed. If a spent code were
-- deleted, "never existed" and "already used" would be indistinguishable, and
-- that distinction is the only evidence an attack leaves behind.
--
-- ── Why the IP is recorded, hashed ─────────────────────────────────────
--
-- Anonymous tenant creation needs a ceiling somewhere: each new tenant carries
-- its own free allowance, so an uncapped mint is uncapped free capacity. The
-- cap is enforced by counting grants per IP per day, which needs an identifier
-- and nothing more — so it is a hash, not an address, and it cannot be read
-- back into one.

CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id     TEXT PRIMARY KEY,
    client_name   TEXT NOT NULL DEFAULT '',
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    source        TEXT NOT NULL DEFAULT 'dynamic',
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scope          TEXT NOT NULL DEFAULT '',
    tenant_id      TEXT NOT NULL DEFAULT '',
    ip_hash        TEXT NOT NULL DEFAULT '',
    created_at     REAL NOT NULL,
    used_at        REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_oauth_codes_client ON oauth_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_ip ON oauth_codes(ip_hash);
