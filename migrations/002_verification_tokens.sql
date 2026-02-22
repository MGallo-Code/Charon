-- Charon schema for verification tokens
-- Applied automatically by the migration runner at startup.

-- =~=~=~=~=~=~=~=~=~=~=~=~=
-- TOKENS
-- =~=~=~=~=~=~=~=~=~=~=~=~=
CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    token_type TEXT NOT NULL,
    token_hash BYTEA UNIQUE NOT NULL,
    used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),

    CHECK (
        token_type IN ('password_reset', 'email_verification')
    ),
    CONSTRAINT fk_tokens_user
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens (user_id);