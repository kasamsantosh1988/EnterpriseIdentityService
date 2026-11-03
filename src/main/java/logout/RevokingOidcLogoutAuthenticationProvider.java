package com.example.authserver.logout;

import com.example.authserver.session.SessionRevocationService;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;

/**
 * OIDC RP-initiated logout (/connect/logout). The framework validates the id_token_hint and ends the browser session of
 * the central login page; this wrapper additionally revokes the tokens of the session the id token belongs to, so the
 * application's access token stops working at once.
 */
public class RevokingOidcLogoutAuthenticationProvider implements AuthenticationProvider {

    private static final OAuth2TokenType ID_TOKEN = new OAuth2TokenType("id_token");

    private final AuthenticationProvider delegate;

    private final OAuth2AuthorizationService authorizationService;

    private final SessionRevocationService revocation;

    public RevokingOidcLogoutAuthenticationProvider(AuthenticationProvider delegate,
            OAuth2AuthorizationService authorizationService, SessionRevocationService revocation) {
        this.delegate = delegate;
        this.authorizationService = authorizationService;
        this.revocation = revocation;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Authentication result = this.delegate.authenticate(authentication);      // throws if the hint is not valid
        if (authentication instanceof OidcLogoutAuthenticationToken logout && logout.getIdTokenHint() != null) {
            OAuth2Authorization authorization = this.authorizationService.findByToken(logout.getIdTokenHint(),
                    ID_TOKEN);
            if (authorization != null) {
                this.revocation.revoke(authorization, "oidc logout");
            }
        }
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return this.delegate.supports(authentication);
    }
}
