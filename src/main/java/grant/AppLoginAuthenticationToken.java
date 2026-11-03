package com.example.authserver.grant;

import java.io.Serial;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

/** A request to exchange a username and password for tokens, made by an authenticated (confidential) client. */
public final class AppLoginAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String username;

    private final String password;

    private final Set<String> scopes;

    public AppLoginAuthenticationToken(Authentication clientPrincipal, String username, String password,
            Set<String> scopes) {
        super(AppLoginGrant.TYPE, clientPrincipal, null);
        this.username = username;
        this.password = password;
        this.scopes = Set.copyOf(scopes);
    }

    public String getUsername() {
        return this.username;
    }

    /** The user's password. Keep it out of logs and exceptions. */
    public String getPassword() {
        return this.password;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}
