-- ============================================================
-- WebHawk Database Schema
-- Security Engine Tables
-- ============================================================

-- logs_security: audit trail of every request the security engine evaluates.
-- Every request (clean or malicious) gets a row here.
-- This table is also the source for the analytics dashboard (bonus).
CREATE TABLE IF NOT EXISTS security_logs (
    id          SERIAL PRIMARY KEY,
    endpoint    VARCHAR(255)  NOT NULL,
    method      VARCHAR(10)   NOT NULL,
    attack_type VARCHAR(50),              -- 'sqli' / 'xss' / 'rate_limit' / NULL if clean
    blocked     BOOLEAN       NOT NULL DEFAULT FALSE,
    ip          VARCHAR(45)   NOT NULL,
    timestamp   TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- limit_rate: running counter of request volume per IP per endpoint.
-- Rate-limit abuse can only be detected across multiple requests over time,
-- so we need state here (unlike SQLi/XSS which only look at a single request).
-- UNIQUE(ip, endpoint) ensures one row per IP+endpoint pair — we UPDATE it, not INSERT each time.
CREATE TABLE IF NOT EXISTS rate_limit (
    id             SERIAL PRIMARY KEY,
    endpoint       VARCHAR(255) NOT NULL,
    ip             VARCHAR(45)  NOT NULL,
    request_count  INTEGER      NOT NULL DEFAULT 1,
    window_start   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    blocked_status BOOLEAN      NOT NULL DEFAULT FALSE,
    UNIQUE (ip, endpoint)
);