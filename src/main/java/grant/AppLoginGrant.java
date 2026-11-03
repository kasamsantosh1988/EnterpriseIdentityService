package com.example.authserver.grant;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

/** Constants of the app_login grant: an application backend exchanges a user's username and password for tokens. */
public final class AppLoginGrant {

    /** The {@code grant_type} value. Register it on a client's authorization grant types. */
    public static final AuthorizationGrantType TYPE = new AuthorizationGrantType("app_login");

    /** Scopes starting with this prefix are administrative (for example auth.revoke) and are never given to users. */
    public static final String ADMIN_SCOPE_PREFIX = "auth.";

    /** Error code returned when too many failed sign-ins were made (HTTP 429). */
    public static final String ERROR_TOO_MANY_ATTEMPTS = "too_many_attempts";

    private AppLoginGrant() {
    }
}
