-- Hashes of refresh tokens that were replaced by rotation. Presenting one again (after a short grace period)
-- means the token was copied, so the whole session is revoked.
CREATE TABLE refresh_token_history (
    token_hash VARCHAR2(64)  NOT NULL,      -- SHA-256 hex of the old refresh token
    sid        VARCHAR2(100) NOT NULL,      -- session (authorization id) it belonged to
    rotated_at TIMESTAMP     NOT NULL,
    expires_at TIMESTAMP     NOT NULL,      -- when the old token would have expired anyway
    CONSTRAINT pk_refresh_token_hist PRIMARY KEY (token_hash)
);
CREATE INDEX idx_rth_expires ON refresh_token_history (expires_at);
CREATE INDEX idx_auth_session_expires ON auth_session (expires_at);
