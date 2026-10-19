-- Indexes for token lookups (introspection / refresh run equality searches on these columns).
-- Names are kept within 30 characters for older Oracle versions.
CREATE UNIQUE INDEX uq_oauth2_client_client_id ON oauth2_registered_client (client_id);
CREATE INDEX idx_oauth2_auth_access_token  ON oauth2_authorization (access_token_value);
CREATE INDEX idx_oauth2_auth_refresh_token ON oauth2_authorization (refresh_token_value);
CREATE INDEX idx_oauth2_auth_code          ON oauth2_authorization (authorization_code_value);
CREATE INDEX idx_oauth2_auth_state         ON oauth2_authorization (state);
CREATE INDEX idx_oauth2_auth_principal     ON oauth2_authorization (registered_client_id, principal_name);

-- How the auth server validates users for each registered application (used from Milestone 2).
-- Booleans are NUMBER(1) (1/0) because only Oracle 23ai has a BOOLEAN type.
CREATE TABLE client_directory_config (
    client_id       VARCHAR2(100) NOT NULL,           -- oauth2_registered_client.client_id
    directory_type  VARCHAR2(20)  NOT NULL,
    verify_url      VARCHAR2(500),                    -- REMOTE: app's user-verify service
    status_url      VARCHAR2(500),                    -- REMOTE: user status/roles lookup (refresh-time check)
    jdbc_url        VARCHAR2(500),                    -- JDBC: app database
    jdbc_username   VARCHAR2(200),
    jdbc_secret_ref VARCHAR2(200),                    -- reference to the secret (Vault path etc.), never the secret
    auth_query      CLOB,                             -- JDBC: query returning user id, hash, status, roles
    claims_mapping  CLOB,                             -- JSON: app roles/attributes -> token claims
    enabled         NUMBER(1)     DEFAULT 1 NOT NULL,
    created_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT pk_client_directory_config PRIMARY KEY (client_id),
    CONSTRAINT ck_client_directory_type CHECK (directory_type IN ('REMOTE', 'JDBC')),
    CONSTRAINT ck_client_directory_enabled CHECK (enabled IN (0, 1))
);

-- Application APIs that validate tokens through introspection (used from Milestone 4).
CREATE TABLE resource_server (
    id                      VARCHAR2(100) NOT NULL,
    audience                VARCHAR2(200) NOT NULL,   -- value placed in the token's "aud"
    name                    VARCHAR2(200) NOT NULL,
    introspection_client_id VARCHAR2(100) NOT NULL,   -- client the API authenticates as
    enabled                 NUMBER(1)     DEFAULT 1 NOT NULL,
    created_at              TIMESTAMP     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT pk_resource_server PRIMARY KEY (id),
    CONSTRAINT uq_resource_server_audience UNIQUE (audience),
    CONSTRAINT ck_resource_server_enabled CHECK (enabled IN (0, 1))
);

-- SSO / login sessions owned by the auth server (used from Milestone 3).
CREATE TABLE auth_session (
    sid              VARCHAR2(100) NOT NULL,
    subject          VARCHAR2(300) NOT NULL,          -- namespaced, e.g. appA:12345
    client_id        VARCHAR2(100) NOT NULL,
    authenticated_at TIMESTAMP     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_seen_at     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at       TIMESTAMP     NOT NULL,
    revoked_at       TIMESTAMP,
    ip_address       VARCHAR2(64),
    CONSTRAINT pk_auth_session PRIMARY KEY (sid)
);
CREATE INDEX idx_auth_session_subject ON auth_session (subject);

CREATE TABLE audit_event (
    id         NUMBER GENERATED ALWAYS AS IDENTITY,   -- needs Oracle 12c or later
    event_time TIMESTAMP     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    event_type VARCHAR2(50)  NOT NULL,                -- LOGIN, LOGIN_FAILED, TOKEN_ISSUED, REFRESH, REVOKE, INTROSPECT...
    client_id  VARCHAR2(100),
    subject    VARCHAR2(300),
    outcome    VARCHAR2(20)  NOT NULL,
    ip_address VARCHAR2(64),
    detail     CLOB,                                  -- never store passwords or tokens here
    CONSTRAINT pk_audit_event PRIMARY KEY (id)
);
CREATE INDEX idx_audit_event_time    ON audit_event (event_time);
CREATE INDEX idx_audit_event_subject ON audit_event (subject);

-- Signing key metadata for rotation (key material stays in the keystore / Vault).
CREATE TABLE signing_key (
    kid          VARCHAR2(100) NOT NULL,
    algorithm    VARCHAR2(20)  NOT NULL,
    public_jwk   CLOB          NOT NULL,
    key_ref      VARCHAR2(300) NOT NULL,
    active       NUMBER(1)     DEFAULT 0 NOT NULL,
    created_at   TIMESTAMP     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    retire_after TIMESTAMP,
    CONSTRAINT pk_signing_key PRIMARY KEY (kid),
    CONSTRAINT ck_signing_key_active CHECK (active IN (0, 1))
);
