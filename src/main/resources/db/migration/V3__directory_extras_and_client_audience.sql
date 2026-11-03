-- Milestone 2: extra settings for user-directory providers, and which audience(s) a client's tokens are for.

ALTER TABLE client_directory_config ADD (
    verify_secret_ref  VARCHAR2(200),                          -- REMOTE: reference to the key sent to the app's verify service
    password_hash_type VARCHAR2(30) DEFAULT 'BCRYPT' NOT NULL, -- JDBC: how passwords are hashed in the app DB (BCRYPT | DELEGATING)
    load_query         CLOB                                    -- JDBC: query by :userId returning the same columns as auth_query (used on refresh)
);

-- Audience ("aud") placed in access tokens issued to a client. Applications check this value.
CREATE TABLE client_audience (
    client_id VARCHAR2(100) NOT NULL,
    audience  VARCHAR2(200) NOT NULL,
    CONSTRAINT pk_client_audience PRIMARY KEY (client_id, audience)
);
