package com.example.authserver.session;

import java.security.Principal;
import java.time.Instant;

import com.example.authserver.config.AuthServerProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Wraps the JDBC authorization service and keeps the session bookkeeping up to date whenever an authorization with a
 * refresh token is saved:
 *  - creates the session (with its absolute expiry) the first time,
 *  - remembers the hash of each refresh token that gets replaced, so reuse of an old token can be recognised,
 *  - marks the session revoked when its refresh token is revoked.
 *
 * Bookkeeping errors are logged but never fail the token request: a session without a row is created again on the next
 * refresh, and the worst case of missing history is that token reuse is not detected for that rotation.
 */
public class SessionTrackingAuthorizationService implements OAuth2AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(SessionTrackingAuthorizationService.class);

    private final OAuth2AuthorizationService delegate;

    private final SessionRepository sessions;

    private final RegisteredClientRepository clients;

    private final AuthServerProperties.Session settings;

    public SessionTrackingAuthorizationService(OAuth2AuthorizationService delegate, SessionRepository sessions,
            RegisteredClientRepository clients, AuthServerProperties.Session settings) {
        this.delegate = delegate;
        this.sessions = sessions;
        this.clients = clients;
        this.settings = settings;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        authorization = withoutLoginDetails(authorization);
        OAuth2Authorization.Token<OAuth2RefreshToken> refresh = authorization.getRefreshToken();
        OAuth2Authorization previous = (refresh != null) ? this.delegate.findById(authorization.getId()) : null;

        this.delegate.save(authorization);

        if (refresh != null) {
            try {
                track(authorization, refresh, previous);
            }
            catch (RuntimeException ex) {
                log.error("Could not update session bookkeeping for authorization {}", authorization.getId(), ex);
            }
        }
    }

    /**
     * The login's request details (client id, IP) are only needed while authenticating. The authorization stores the
     * signed-in user as JSON, and the JSON reader refuses types that are not on its allowlist, so a stored
     * LoginDetails makes every later read of the authorization (for example the code exchange) fail. Store the user
     * without details.
     */
    private static OAuth2Authorization withoutLoginDetails(OAuth2Authorization authorization) {
        Object principal = authorization.getAttribute(Principal.class.getName());
        if (principal instanceof UsernamePasswordAuthenticationToken token && token.getDetails() != null) {
            UsernamePasswordAuthenticationToken clean = UsernamePasswordAuthenticationToken
                .authenticated(token.getPrincipal(), null, token.getAuthorities());
            return OAuth2Authorization.from(authorization).attribute(Principal.class.getName(), clean).build();
        }
        return authorization;
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        this.delegate.remove(authorization);
        try {
            this.sessions.markRevoked(authorization.getId(), Instant.now());
        }
        catch (RuntimeException ex) {
            log.error("Could not mark session {} revoked", authorization.getId(), ex);
        }
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return this.delegate.findById(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        return this.delegate.findByToken(token, tokenType);
    }

    private void track(OAuth2Authorization authorization, OAuth2Authorization.Token<OAuth2RefreshToken> refresh,
            OAuth2Authorization previous) {
        Instant now = Instant.now();
        String sid = authorization.getId();

        if (refresh.isInvalidated()) {
            this.sessions.markRevoked(sid, now);
            return;
        }

        if (this.sessions.touch(sid, now) == 0) {
            RegisteredClient client = this.clients.findById(authorization.getRegisteredClientId());
            String clientId = (client != null) ? client.getClientId() : authorization.getRegisteredClientId();
            this.sessions.ensure(sid, authorization.getPrincipalName(), clientId, now,
                    now.plus(this.settings.absolute()));
        }

        if (previous != null && previous.getRefreshToken() != null) {
            OAuth2RefreshToken old = previous.getRefreshToken().getToken();
            if (!old.getTokenValue().equals(refresh.getToken().getTokenValue())) {
                Instant oldExpiry = (old.getExpiresAt() != null) ? old.getExpiresAt() : now.plus(this.settings.idle());
                this.sessions.recordRotation(SessionRepository.hash(old.getTokenValue()), sid, now, oldExpiry);
            }
        }
    }
}
