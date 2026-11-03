package com.example.authserver.grant;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Constants of the handoff grant: the target application of a hand-off exchanges the one-time code for its own access
 * token for the user that the source application vouched for.
 */
public final class HandoffGrant {

    /** The {@code grant_type} value. Register it on the client that RECEIVES users from other applications. */
    public static final AuthorizationGrantType TYPE = new AuthorizationGrantType("handoff");

    private HandoffGrant() {
    }
}
