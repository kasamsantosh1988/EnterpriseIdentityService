-- Spring Authorization Server tables (columns/names from Spring Security 7.1.1), adapted for Oracle.
--
-- Oracle notes:
--  * The *_value token columns are VARCHAR2, not BLOB: the framework looks tokens up with
--    "access_token_value = ?" and Oracle cannot compare LOB columns with "=".
--    The framework reads each column's real JDBC type, so VARCHAR2 and CLOB both work.
--    Opaque tokens are ~50-130 chars. If you switch to JWT access tokens and they exceed 4000 bytes,
--    enable MAX_STRING_SIZE=EXTENDED and widen these columns.
--  * *_metadata and attributes hold JSON that can be large, so they are CLOB.
--  * Oracle stores '' as NULL, so "scopes" must be nullable (a client with no scopes saves '').
--  * Run the JVM in UTC (set in AuthServerApplication) so TIMESTAMP values are consistent.

CREATE TABLE oauth2_registered_client (
    id                            VARCHAR2(100)  NOT NULL,
    client_id                     VARCHAR2(100)  NOT NULL,
    client_id_issued_at           TIMESTAMP      DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                 VARCHAR2(200),
    client_secret_expires_at      TIMESTAMP,
    client_name                   VARCHAR2(200)  NOT NULL,
    client_authentication_methods VARCHAR2(1000) NOT NULL,
    authorization_grant_types     VARCHAR2(1000) NOT NULL,
    redirect_uris                 VARCHAR2(1000),
    post_logout_redirect_uris     VARCHAR2(1000),
    scopes                        VARCHAR2(1000),
    client_settings               VARCHAR2(4000) NOT NULL,
    token_settings                VARCHAR2(4000) NOT NULL,
    CONSTRAINT pk_oauth2_registered_client PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization (
    id                            VARCHAR2(100)  NOT NULL,
    registered_client_id          VARCHAR2(100)  NOT NULL,
    principal_name                VARCHAR2(200)  NOT NULL,
    authorization_grant_type      VARCHAR2(100)  NOT NULL,
    authorized_scopes             VARCHAR2(1000),
    attributes                    CLOB,
    state                         VARCHAR2(500),
    authorization_code_value      VARCHAR2(4000),
    authorization_code_issued_at  TIMESTAMP,
    authorization_code_expires_at TIMESTAMP,
    authorization_code_metadata   CLOB,
    access_token_value            VARCHAR2(4000),
    access_token_issued_at        TIMESTAMP,
    access_token_expires_at       TIMESTAMP,
    access_token_metadata         CLOB,
    access_token_type             VARCHAR2(100),
    access_token_scopes           VARCHAR2(1000),
    oidc_id_token_value           VARCHAR2(4000),
    oidc_id_token_issued_at       TIMESTAMP,
    oidc_id_token_expires_at      TIMESTAMP,
    oidc_id_token_metadata        CLOB,
    refresh_token_value           VARCHAR2(4000),
    refresh_token_issued_at       TIMESTAMP,
    refresh_token_expires_at      TIMESTAMP,
    refresh_token_metadata        CLOB,
    user_code_value               VARCHAR2(4000),
    user_code_issued_at           TIMESTAMP,
    user_code_expires_at          TIMESTAMP,
    user_code_metadata            CLOB,
    device_code_value             VARCHAR2(4000),
    device_code_issued_at         TIMESTAMP,
    device_code_expires_at        TIMESTAMP,
    device_code_metadata          CLOB,
    CONSTRAINT pk_oauth2_authorization PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization_consent (
    registered_client_id VARCHAR2(100)  NOT NULL,
    principal_name       VARCHAR2(200)  NOT NULL,
    authorities          VARCHAR2(1000) NOT NULL,
    CONSTRAINT pk_oauth2_authorization_consent PRIMARY KEY (registered_client_id, principal_name)
);
