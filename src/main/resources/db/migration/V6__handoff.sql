-- Hand-off: an application sends a signed-in user to another application without a second login.
-- A hand-off is allowed only when BOTH sides agree: the source lists the target, and the target accepts the source.

-- Declared on the SOURCE application ("handoffTargets"): where it may send its users.
CREATE TABLE client_handoff_target (
    source_client_id VARCHAR2(100) NOT NULL,
    target_client_id VARCHAR2(100) NOT NULL,
    CONSTRAINT pk_client_handoff_target PRIMARY KEY (source_client_id, target_client_id)
);

-- Declared on the TARGET application ("acceptsHandoffFrom"): whose users it accepts.
CREATE TABLE client_handoff_accept (
    target_client_id VARCHAR2(100) NOT NULL,
    source_client_id VARCHAR2(100) NOT NULL,
    CONSTRAINT pk_client_handoff_accept PRIMARY KEY (target_client_id, source_client_id)
);

-- One-time hand-off codes. Only the SHA-256 of the code is stored. The context (opaque text from the source application,
-- for example encrypted proposal and quote numbers) is cleared as soon as the code is redeemed.
CREATE TABLE handoff_code (
    code_hash        VARCHAR2(64)   NOT NULL,      -- SHA-256 hex of the code
    source_client_id VARCHAR2(100)  NOT NULL,
    target_client_id VARCHAR2(100)  NOT NULL,
    subject          VARCHAR2(300)  NOT NULL,      -- "<clientId>:<userId>" of the signed-in user
    roles            VARCHAR2(1000),               -- the user's roles at the source, comma separated
    context_value    VARCHAR2(2048),               -- opaque; cleared on redeem
    created_at       TIMESTAMP      NOT NULL,
    expires_at       TIMESTAMP      NOT NULL,
    used_at          TIMESTAMP,
    CONSTRAINT pk_handoff_code PRIMARY KEY (code_hash)
);
CREATE INDEX idx_handoff_code_expires ON handoff_code (expires_at);
