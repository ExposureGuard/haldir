-- Haldir migration 010: capability cards — an agent made discoverable.
--
-- Why this exists
-- ---------------
-- The register answers "which agents do we run". A card answers "which of them
-- are we willing to be found by": an owner-published, capability-only listing,
-- surfaced at /.well-known/agents.json so that other agents and people can
-- discover it. It is the first piece of the registry that faces outward, and
-- it is opt-in per agent.
--
-- What a card deliberately does NOT contain
-- -----------------------------------------
-- Sessions, spend, actions, flags, the tenant id, or the agent's internal id.
-- A card is the operator's *claim* about what an agent does — never a summary
-- of what it did. The public projection lives in `haldir_cards.public_cards`,
-- and a test asserts that adding an operational field to the table cannot
-- reach it.
--
-- Why one row per agent
-- ---------------------
-- UNIQUE (tenant_id, agent_id): an agent has one card, and re-publishing
-- updates it rather than accumulating duplicates. Withdrawing consent means
-- deleting the row, which is why `unpublish` deletes rather than flagging —
-- the difference between "hidden" and "gone" matters to the operator's
-- promise that they can take it back.
--
-- Why the id is opaque
-- --------------------
-- The card id is the public address of the listing. Deriving it from the
-- tenant or the agent would make the internal identifier guessable from the
-- public one, which is the opposite of what an opt-in directory should do.
CREATE TABLE IF NOT EXISTS agent_cards (
    card_id       TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    display_name  TEXT NOT NULL DEFAULT '',
    description   TEXT NOT NULL DEFAULT '',
    capabilities  TEXT NOT NULL DEFAULT '[]',
    contact_url   TEXT NOT NULL DEFAULT '',
    published_at  REAL NOT NULL,
    updated_at    REAL NOT NULL,
    UNIQUE (tenant_id, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_cards_tenant ON agent_cards(tenant_id);
