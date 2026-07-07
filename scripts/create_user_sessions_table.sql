-- PostgreSQL session storage for authprovider
-- Purpose: persist login sessions across process boundaries (multi-worker/pod safe)

BEGIN;

-- 1) Table
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id           TEXT PRIMARY KEY,
    user_id              INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ NOT NULL,
    ip_address           INET,
    user_agent           TEXT,
    invalidated_at       TIMESTAMPTZ,

    CONSTRAINT user_sessions_expires_after_created
        CHECK (expires_at > created_at)
);

-- 2) Indexes for common access paths
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id
    ON user_sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at
    ON user_sessions (expires_at);

CREATE INDEX IF NOT EXISTS idx_user_sessions_active_expires
    ON user_sessions (expires_at)
    WHERE invalidated_at IS NULL;

-- 3) Keep updated_at fresh on update
CREATE OR REPLACE FUNCTION set_user_sessions_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_set_user_sessions_updated_at ON user_sessions;
CREATE TRIGGER trg_set_user_sessions_updated_at
BEFORE UPDATE ON user_sessions
FOR EACH ROW
EXECUTE FUNCTION set_user_sessions_updated_at();

-- 4) Optional helper to remove expired/invalidated sessions
CREATE OR REPLACE FUNCTION cleanup_user_sessions()
RETURNS BIGINT AS $$
DECLARE
    deleted_count BIGINT;
BEGIN
    DELETE FROM user_sessions
    WHERE expires_at <= NOW()
       OR invalidated_at IS NOT NULL;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

COMMIT;
