-- Charon schema for audit logs
-- Applied automatically by the migration runner at startup.

-- =~=~=~=~=~=~=~=~=~=~=~=~=
-- AUDIT_LOGS
-- =~=~=~=~=~=~=~=~=~=~=~=~=

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    user_id UUID,
    -- Event type as dot-namespaced string: user.registered, user.login, etc...
    action TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    -- If more information to note on event, store in metadata
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),

    CONSTRAINT fk_audit_logs_user
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at);