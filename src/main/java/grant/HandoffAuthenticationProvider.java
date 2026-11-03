package com.example.authserver.grant;

import java.security.Principal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.example.authserver.audit.AuditService;
import com.example.authserver.handoff.HandoffRepository;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.ClaimAccessor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Exchanges a one-time hand-off code for an access token. The code was issued to a SOURCE application for one of its
 * signed-in users and names this client as the target. The user is NOT looked up in the target's directory: the source
 * application vouched for them, and the server re-checks that the source and the target still agree to hand off.
 *
 * The token is for the target's audience, carries the source application's user as subject ("source:userId"), has no
 * refresh token (the target has no directory to re-check the user in), and the response also returns the opaque context
 * the source attached, once.
 */
public class HandoffAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final OAuth2AuthorizationService authorizationService;

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    private final HandoffRepository handoffs;

    private final AuditService audit;

    public HandoffAuthenticationProvider(OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, HandoffRepository handoffs, AuditService audit) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.handoffs = handoffs;
        this.audit = audit;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        HandoffAuthenticationToken request = (HandoffAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal = authenticatedClient(request);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        if (!registeredClient.getAuthorizationGrantTypes().contains(HandoffGrant.TYPE)) {
            throw error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, "This client may not use the handoff grant");
        }
        if (ClientAuthenticationMethod.NONE.equals(clientPrincipal.getClientAuthenticationMethod())) {
            throw error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, "handoff requires a client secret");
        }
        String targetClientId = registeredClient.getClientId();
        Set<String> scopes = authorizedScopes(registeredClient, request.getScopes());

        // The code works once, only for this client, and only before it expires.
        HandoffRepository.Redeemed redeemed = this.handoffs.consume(request.getCode(), targetClientId, Instant.now())
            .orElse(null);
        if (redeemed == null) {
            this.audit.record("HANDOFF_REDEEM_FAILED", targetClientId, null, "FAILURE", null, "invalid or used code");
            throw error(OAuth2ErrorCodes.INVALID_GRANT, "The hand-off code is invalid or has expired");
        }
        // The two sides may have changed their minds in the minute since the code was issued.
        if (!this.handoffs.isAllowed(redeemed.sourceClientId(), targetClientId)) {
            this.audit.record("HANDOFF_REDEEM_FAILED", targetClientId, redeemed.subject(), "FAILURE", null,
                    "link no longer allowed from " + redeemed.sourceClientId());
            throw error(OAuth2ErrorCodes.INVALID_GRANT, "The hand-off code is invalid or has expired");
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String role : redeemed.roles()) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        // Standard Spring Security types only: they are stored with the authorization.
        User principal = new User(redeemed.subject(), "", authorities);
        UsernamePasswordAuthenticationToken user = UsernamePasswordAuthenticationToken.authenticated(principal, null,
                authorities);

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(user)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(scopes)
            .authorizationGrantType(HandoffGrant.TYPE)
            .authorizationGrant(request);

        OAuth2TokenContext accessTokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(accessTokenContext);
        if (generatedAccessToken == null) {
            throw error(OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the access token.");
        }

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(redeemed.subject())
            .authorizationGrantType(HandoffGrant.TYPE)
            .authorizedScopes(scopes)
            .attribute(Principal.class.getName(), user);
        OAuth2AccessToken accessToken = accessToken(authorizationBuilder, generatedAccessToken, accessTokenContext);
        this.authorizationService.save(authorizationBuilder.build());

        this.audit.record("HANDOFF_REDEEMED", targetClientId, redeemed.subject(), "SUCCESS", null,
                "from " + redeemed.sourceClientId());

        // Extra fields in the token response: who the user is, where they came from, and the source's context (once).
        Map<String, Object> additional = new LinkedHashMap<>();
        additional.put("sub", redeemed.subject());
        additional.put("src", redeemed.sourceClientId());
        additional.put("roles", String.join(" ", redeemed.roles()));
        if (StringUtils.hasText(redeemed.context())) {
            additional.put("context", redeemed.context());
        }
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, null,
                additional);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return HandoffAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /** Requested scopes must be registered for the client; openid and administrative scopes are never given to users. */
    private static Set<String> authorizedScopes(RegisteredClient client, Set<String> requested) {
        Set<String> authorized = new LinkedHashSet<>();
        for (String scope : requested) {
            if (!client.getScopes().contains(scope) || OidcScopes.OPENID.equals(scope)
                    || scope.startsWith(AppLoginGrant.ADMIN_SCOPE_PREFIX)) {
                throw error(OAuth2ErrorCodes.INVALID_SCOPE, "Scope not allowed: " + printable(scope));
            }
            authorized.add(scope);
        }
        return authorized;
    }

    private static OAuth2ClientAuthenticationToken authenticatedClient(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof OAuth2ClientAuthenticationToken client && client.isAuthenticated()) {
            return client;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    // Same as the framework's (package-private) helper: records the access token and its claims on the authorization.
    private static OAuth2AccessToken accessToken(OAuth2Authorization.Builder builder, OAuth2Token token,
            OAuth2TokenContext context) {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                token.getTokenValue(), token.getIssuedAt(), token.getExpiresAt(), context.getAuthorizedScopes());
        OAuth2TokenFormat format = context.getRegisteredClient().getTokenSettings().getAccessTokenFormat();
        builder.token(accessToken, (metadata) -> {
            if (token instanceof ClaimAccessor claimAccessor && !CollectionUtils.isEmpty(claimAccessor.getClaims())) {
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims());
            }
            metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
            metadata.put(OAuth2TokenFormat.class.getName(), format.getValue());
        });
        return accessToken;
    }

    private static OAuth2AuthenticationException error(String code, String description) {
        return new OAuth2AuthenticationException(new OAuth2Error(code, description, ERROR_URI));
    }

    private static String printable(String value) {
        String clean = value.replaceAll("[^\\x21\\x23-\\x5B\\x5D-\\x7E]", "?");
        return clean.length() > 40 ? clean.substring(0, 40) : clean;
    }
}
