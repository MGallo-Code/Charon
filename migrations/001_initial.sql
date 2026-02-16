-- Charon initial schema
-- Applied automatically by the migration runner at startup.


-- =~=~=~=~=~=~=~=~=~=~=~=~=
-- USERS
-- =~=~=~=~=~=~=~=~=~=~=~=~=
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE,
    email_confirmed_at TIMESTAMPTZ,
    phone TEXT UNIQUE,
    phone_confirmed_at TIMESTAMPTZ,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    password_hash TEXT,
    oauth_provider VARCHAR(30),
    oauth_provider_id TEXT,
    avatar_url TEXT,
    created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),
    -- Validate oauth_provider...
    CHECK (oauth_provider IS NULL OR oauth_provider IN ('google')),
    -- oauth_provider and oauth_provider_id must both be set or both be null...
    CHECK ((oauth_provider IS NULL) = (oauth_provider_id IS NULL)),
    -- No duplicate oauth users...
    UNIQUE (oauth_provider, oauth_provider_id),
    -- If user has email or phone, password is required...
    CHECK ((email IS NULL AND phone IS NULL) OR password_hash IS NOT NULL)
);


-- =~=~=~=~=~=~=~=~=~=~=~=~=
-- SESSIONS
-- =~=~=~=~=~=~=~=~=~=~=~=~=
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    token_hash BYTEA UNIQUE NOT NULL,
    csrf_token BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),

    CONSTRAINT fk_sessions_user
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);