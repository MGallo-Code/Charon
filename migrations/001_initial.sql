-- Charon initial schema
-- Applied automatically by the migration runner at startup.

-- Incl for uuid gen
CREATE EXTENSION IF NOT EXISTS pgcrypto;


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
    
);

-- Columns:
--   id            UUID primary key
--   user_id       UUID, foreign key -> users(id)
--   token_hash    BYTEA — raw SHA-256 bytes (32 bytes, fixed length)
--   expires_at    TIMESTAMPTZ — when this session becomes invalid
--   ip_address    INET — Postgres has a native type for IP addresses
--   user_agent    TEXT
--   created_at    TIMESTAMPTZ, default to now()
--
-- Think about:
--   What happens to sessions if the user row is deleted? (ON DELETE CASCADE)
--   Which column will you look up sessions by? (token_hash needs an index)
--   Which column will you use to delete all sessions for a user? (user_id needs an index)


-- =~=~=~=~=~=~=~=~=~=~=~=~=
-- SESSIONS
-- =~=~=~=~=~=~=~=~=~=~=~=~=
-- Create indexes for columns you query by:
--   users(email)           — login lookup
--   sessions(token_hash)   — session validation on every request
--   sessions(user_id)      — "log out everywhere" deletes all sessions for a user
--
-- Syntax: CREATE INDEX index_name ON table_name (column_name);
-- For unique columns, the UNIQUE constraint already creates an index.
