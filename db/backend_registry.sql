-- ============================================================
-- WebHawk Database Schema
-- Backend Registry Table
-- ============================================================

-- backend_registration: the control plane for the product.
-- A developer who wants WebHawk to protect their app registers it here,
-- gets back a unique api_key, and the middleware uses that key to look up
-- which real backend (target_url) to forward an allowed request to.
CREATE TABLE IF NOT EXISTS backend_registration (
    id           SERIAL PRIMARY KEY,
    service_name VARCHAR(255)  NOT NULL,
    target_url   VARCHAR(500)  NOT NULL,
    api_key      VARCHAR(64)   UNIQUE NOT NULL,
    active       BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- No separate index needed on api_key for lookups - the UNIQUE constraint
-- above already creates one automatically in Postgres.