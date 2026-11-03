package com.example.authserver.admin;

import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;

/**
 * Checks bearer tokens for the /admin endpoints directly against this server's own authorization store (no HTTP call to
 * itself). Only active access tokens obtained with the client_credentials grant are accepted, so a token that belongs
 * to a user can never call an admin endpoint.
 */
@Component
public class LocalOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final OAuth2AuthorizationService authorizationService;

    private final RegisteredClientRepository clients;

    public LocalOpaqueTokenIntrospector(OAuth2AuthorizationService authorizationService,
            RegisteredClientRepository clients) {
        this.authorizationService = authorizationService;
        this.clients = clients;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2Authorization authorization = this.authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null) {
            throw new BadOpaqueTokenException("Unknown token");
        }
        OAuth2Authorization.Token<OAuth2AccessToken> access = authorization.getAccessToken();
        if (access == null || !access.isActive()) {
            throw new BadOpaqueTokenException("Inactive token");
        }
        if (!AuthorizationGrantType.CLIENT_CREDENTIALS.equals(authorization.getAuthorizationGrantType())) {
            throw new BadOpaqueTokenException("Not a client credentials token");
        }
        RegisteredClient client = this.clients.findById(authorization.getRegisteredClientId());
        if (client == null) {
            throw new BadOpaqueTokenException("Unknown client");
        }
        List<GrantedAuthority> authorities = authorization.getAuthorizedScopes()
            .stream()
            .<GrantedAuthority>map((scope) -> new SimpleGrantedAuthority("SCOPE_" + scope))
            .toList();
        return new DefaultOAuth2AuthenticatedPrincipal(client.getClientId(),
                Map.of("client_id", client.getClientId()), authorities);
    }
}
