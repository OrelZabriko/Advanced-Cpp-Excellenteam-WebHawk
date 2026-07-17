-- ============================================================
-- WebHawk Database Schema
-- Users Tables
-- ============================================================

-- users: one row per registered account. Passwords are never stored in
-- plain text - password_hash holds a bcrypt hash (see
-- services/users/utils/HashUtils.cc), which already includes its own salt,
-- so no separate salt column is needed here.
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    email         VARCHAR(255)  UNIQUE NOT NULL,   -- login identifier; UNIQUE also gives it a fast index for free
    password_hash VARCHAR(255)  NOT NULL,           -- bcrypt hash (always 60 chars), not the raw password
    created_at    TIMESTAMPTZ   DEFAULT NOW()
);

-- user_sessions: one row per active (or previously active) login. This is
-- what lets a JWT be revoked before it naturally expires - the token itself
-- can't be "un-issued" once handed out, but AuthController::logout can mark
-- the matching row here as 'revoked', and UserService::validateToken checks
-- this table (not just the JWT's own signature/expiry) on every request.
CREATE TABLE IF NOT EXISTS user_sessions (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,  -- if a user is deleted, their sessions go with them
    token_id   VARCHAR(255)  UNIQUE NOT NULL,       -- the actual JWT string issued at login
    ip         VARCHAR(45)   NOT NULL,               -- IPv4 or IPv6 (45 chars fits the longest possible IPv6 form)
    created_at TIMESTAMPTZ   DEFAULT NOW(),
    expires_at TIMESTAMPTZ   NOT NULL,                -- mirrors the JWT's own "exp" claim (see AuthConfig::JWT_EXPIRY_SECS)
    status     VARCHAR(10)   DEFAULT 'active' CHECK (status IN ('active', 'revoked'))
);