-- Charon schema for OAuth pending link tokens.
-- Applied automatically by the migration runner at startup.

CREATE TABLE IF NOT EXISTS oauth_pending_links (
    token_hash  BYTEA        PRIMARY KEY,
    user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider    TEXT         NOT NULL,
    provider_id TEXT         NOT NULL,
    given_name  TEXT,
    family_name TEXT,
    picture     TEXT,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth_pending_links_expires ON oauth_pending_links (expires_at);
