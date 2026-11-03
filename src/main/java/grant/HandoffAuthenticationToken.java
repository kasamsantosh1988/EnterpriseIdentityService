package com.example.authserver.grant;

import java.io.Serial;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

/** A request to exchange a one-time hand-off code for an access token, made by an authenticated (confidential) client. */
public final class HandoffAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String code;

    private final Set<String> scopes;

    public HandoffAuthenticationToken(Authentication clientPrincipal, String code, Set<String> scopes) {
        super(HandoffGrant.TYPE, clientPrincipal, null);
        this.code = code;
        this.scopes = Set.copyOf(scopes);
    }

    /** The one-time code. Keep it out of logs and exceptions. */
    public String getCode() {
        return this.code;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}
