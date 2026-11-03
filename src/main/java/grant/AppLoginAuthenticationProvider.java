package com.example.authserver.grant;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Set;

import com.example.authserver.login.DirectoryLoginService;
import com.example.authserver.ratelimit.TooManyAttemptsException;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
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
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.CollectionUtils;

/**
 * Exchanges a username and password for tokens. Modelled on the framework's client credentials provider, with the user
 * checked against the calling application's directory by {@link DirectoryLoginService}.
 *
 * Only confidential clients (those that authenticate with a secret) may use it, because the secret is what stops
 * anyone who knows a client id from guessing passwords through this endpoint.
 */
public class AppLoginAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final OAuth2AuthorizationService authorizationService;

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    private final DirectoryLoginService loginService;

    public AppLoginAuthenticationProvider(OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, DirectoryLoginService loginService) {
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.loginService = loginService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AppLoginAuthenticationToken request = (AppLoginAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal = authenticatedClient(request);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        if (!registeredClient.getAuthorizationGrantTypes().contains(AppLoginGrant.TYPE)) {
            throw error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, "This client may not use the app_login grant", null);
        }
        if (ClientAuthenticationMethod.NONE.equals(clientPrincipal.getClientAuthenticationMethod())) {
            throw error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, "app_login requires a client secret", null);
        }
        Set<String> scopes = authorizedScopes(registeredClient, request.getScopes());

        UsernamePasswordAuthenticationToken user = signIn(registeredClient, request);

        // ----- Access token -----
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(user)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(scopes)
            .authorizationGrantType(AppLoginGrant.TYPE)
            .authorizationGrant(request);

        OAuth2TokenContext accessTokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(accessTokenContext);
        if (generatedAccessToken == null) {
            throw error(OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the access token.",
                    null);
        }

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(user.getName())
            .authorizationGrantType(AppLoginGrant.TYPE)
            .authorizedScopes(scopes)
            .attribute(Principal.class.getName(), user);

        OAuth2AccessToken accessToken = accessToken(authorizationBuilder, generatedAccessToken, accessTokenContext);

        // ----- Refresh token -----
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            OAuth2TokenContext refreshTokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(refreshTokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                throw error(OAuth2ErrorCodes.SERVER_ERROR, "The token generator failed to generate the refresh token.",
                        null);
            }
            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.refreshToken(refreshToken);
        }

        this.authorizationService.save(authorizationBuilder.build());

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AppLoginAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private UsernamePasswordAuthenticationToken signIn(RegisteredClient client, AppLoginAuthenticationToken request) {
        String ip = request.getDetails() instanceof WebAuthenticationDetails details ? details.getRemoteAddress()
                : null;
        try {
            return this.loginService.authenticate(client.getClientId(), request.getUsername(), request.getPassword(),
                    ip, "app_login");
        }
        catch (TooManyAttemptsException ex) {
            throw error(AppLoginGrant.ERROR_TOO_MANY_ATTEMPTS,
                    "Too many failed attempts. Try again in " + ex.getRetryAfterSeconds() + " seconds.", ex);
        }
        catch (LockedException ex) {
            throw error(OAuth2ErrorCodes.INVALID_GRANT, "account_locked", ex);
        }
        catch (DisabledException ex) {
            throw error(OAuth2ErrorCodes.INVALID_GRANT, "account_disabled", ex);
        }
        catch (CredentialsExpiredException ex) {
            throw error(OAuth2ErrorCodes.INVALID_GRANT, "password_expired", ex);
        }
        catch (BadCredentialsException ex) {
            throw error(OAuth2ErrorCodes.INVALID_GRANT, "Invalid username or password.", ex);
        }
        catch (AuthenticationServiceException ex) {
            throw error(OAuth2ErrorCodes.TEMPORARILY_UNAVAILABLE, "directory_unavailable", ex);
        }
        catch (AuthenticationException ex) {
            throw error(OAuth2ErrorCodes.INVALID_GRANT, "Invalid username or password.", ex);
        }
    }

    /** Requested scopes must be registered for the client; openid and administrative scopes are never given to users. */
    private static Set<String> authorizedScopes(RegisteredClient client, Set<String> requested) {
        Set<String> authorized = new LinkedHashSet<>();
        for (String scope : requested) {
            if (!client.getScopes().contains(scope) || OidcScopes.OPENID.equals(scope)
                    || scope.startsWith(AppLoginGrant.ADMIN_SCOPE_PREFIX)) {
                throw error(OAuth2ErrorCodes.INVALID_SCOPE, "Scope not allowed: " + printable(scope), null);
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

    private static OAuth2AuthenticationException error(String code, String description, Throwable cause) {
        OAuth2Error error = new OAuth2Error(code, description, ERROR_URI);
        return cause == null ? new OAuth2AuthenticationException(error)
                : new OAuth2AuthenticationException(error, cause);
    }

    private static String printable(String value) {
        String clean = value.replaceAll("[^\\x21\\x23-\\x5B\\x5D-\\x7E]", "?");
        return clean.length() > 40 ? clean.substring(0, 40) : clean;
    }
}
