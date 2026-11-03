package com.example.authserver.refresh;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import com.example.authserver.audit.AuditService;
import com.example.authserver.config.AuthServerProperties;
import com.example.authserver.directory.DirectoryProviderRegistry;
import com.example.authserver.directory.UserDirectoryProvider;
import com.example.authserver.directory.UserInfo;
import com.example.authserver.session.SessionRepository;
import com.example.authserver.session.SessionRevocationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Wraps the framework's refresh token provider with the rules of this platform:
 *  1. a refresh token that was already rotated is refused; outside the grace period it is treated as theft and the
 *     whole session is revoked,
 *  2. the session may not live longer than authserver.session.absolute,
 *  3. the user is looked up again in the application's directory: if the user is gone or disabled the session is
 *     revoked; if the directory cannot be reached the request fails with temporarily_unavailable and the refresh token
 *     is NOT consumed, so the app can simply retry,
 *  4. the new access token carries the roles read just now.
 * Everything else (client authentication, scope rules, rotation) is left to the framework provider.
 */
public class DirectoryRefreshTokenAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(DirectoryRefreshTokenAuthenticationProvider.class);

    private final AuthenticationProvider delegate;

    private final OAuth2AuthorizationService authorizationService;

    private final DirectoryProviderRegistry registry;

    private final SessionRepository sessions;

    private final SessionRevocationService revocation;

    private final AuditService audit;

    private final AuthServerProperties.Session settings;

    public DirectoryRefreshTokenAuthenticationProvider(AuthenticationProvider delegate,
            OAuth2AuthorizationService authorizationService, DirectoryProviderRegistry registry,
            SessionRepository sessions, SessionRevocationService revocation, AuditService audit,
            AuthServerProperties.Session settings) {
        this.delegate = delegate;
        this.authorizationService = authorizationService;
        this.registry = registry;
        this.sessions = sessions;
        this.revocation = revocation;
        this.audit = audit;
        this.settings = settings;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2RefreshTokenAuthenticationToken request = (OAuth2RefreshTokenAuthenticationToken) authentication;
        if (!(request.getPrincipal() instanceof OAuth2ClientAuthenticationToken clientPrincipal)
                || !clientPrincipal.isAuthenticated() || clientPrincipal.getRegisteredClient() == null) {
            return this.delegate.authenticate(authentication);      // the framework rejects it with invalid_client
        }
        RegisteredClient client = clientPrincipal.getRegisteredClient();
        String tokenValue = request.getRefreshToken();

        OAuth2Authorization authorization = this.authorizationService.findByToken(tokenValue,
                OAuth2TokenType.REFRESH_TOKEN);
        if (authorization == null) {
            checkForReuse(tokenValue, client);
            return this.delegate.authenticate(authentication);      // invalid_grant
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refresh = authorization.getRefreshToken();
        if (!client.getId().equals(authorization.getRegisteredClientId()) || refresh == null || !refresh.isActive()) {
            return this.delegate.authenticate(authentication);      // invalid_grant
        }

        String expectedPrefix = client.getClientId() + ":";
        String subject = authorization.getPrincipalName();
        if (subject == null || !subject.startsWith(expectedPrefix) || subject.length() == expectedPrefix.length()) {
            return this.delegate.authenticate(authentication);
        }
        String userId = subject.substring(expectedPrefix.length());
        Instant now = Instant.now();

        // 2. absolute session lifetime
        SessionRepository.SessionRow session = this.sessions.find(authorization.getId()).orElse(null);
        if (session != null && (session.isRevoked() || session.isExpired(now))) {
            if (!session.isRevoked()) {
                this.revocation.revoke(authorization, "absolute session lifetime reached");
            }
            this.audit.record("REFRESH_DENIED", client.getClientId(), subject, "FAILURE", null,
                    session.isRevoked() ? "session revoked" : "absolute lifetime reached");
            throw invalidGrant();
        }

        // 3. the user must still exist and be active in the application's directory
        UserInfo user = loadUser(client.getClientId(), userId, subject);
        if (user == null || !user.active()) {
            this.revocation.revoke(authorization, "user missing or disabled in directory");
            this.audit.record("REFRESH_DENIED", client.getClientId(), subject, "FAILURE", null,
                    (user == null) ? "user not found" : "user disabled");
            throw invalidGrant();
        }

        // 4. fresh roles for the new access token
        FreshUserHolder.set(user);
        try {
            Authentication result = this.delegate.authenticate(authentication);
            this.audit.record("REFRESH", client.getClientId(), subject, "SUCCESS", null, null);
            return result;
        }
        finally {
            FreshUserHolder.clear();
        }
    }

    /** Returns null when the user does not exist. Throws temporarily_unavailable if the directory cannot answer. */
    private UserInfo loadUser(String clientId, String userId, String subject) {
        try {
            Optional<UserDirectoryProvider> provider = this.registry.find(clientId);
            if (provider.isEmpty()) {
                return null;
            }
            return provider.get().loadById(userId).orElse(null);
        }
        catch (RuntimeException ex) {
            log.warn("Directory of client {} unavailable during refresh: {}", clientId, ex.toString());
            this.audit.record("REFRESH_DENIED", clientId, subject, "FAILURE", null, "directory unavailable");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.TEMPORARILY_UNAVAILABLE, "directory_unavailable", null), ex);
        }
    }

    /** A token we no longer know may be one that was rotated away. Using it again after the grace period = theft. */
    private void checkForReuse(String tokenValue, RegisteredClient client) {
        try {
            SessionRepository.RotationRow rotation = this.sessions.findRotation(SessionRepository.hash(tokenValue))
                .orElse(null);
            if (rotation == null) {
                return;
            }
            SessionRepository.SessionRow session = this.sessions.find(rotation.sid()).orElse(null);
            if (session == null || !client.getClientId().equals(session.clientId())) {
                return;
            }
            Duration age = Duration.between(rotation.rotatedAt(), Instant.now());
            if (age.compareTo(this.settings.reuseGrace()) <= 0) {
                return;     // a retry of the same request just after rotation: refuse quietly
            }
            this.revocation.revokeById(rotation.sid(), "refresh token reuse");
            this.audit.record("REFRESH_REUSE", client.getClientId(), session.subject(), "FAILURE", null,
                    "rotated refresh token presented again; session revoked");
        }
        catch (RuntimeException ex) {
            log.error("Reuse check failed", ex);
        }
    }

    private static OAuth2AuthenticationException invalidGrant() {
        return new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return this.delegate.supports(authentication);
    }
}
