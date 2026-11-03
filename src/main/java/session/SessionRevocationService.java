package com.example.authserver.session;

import java.time.Instant;
import java.util.List;

import com.example.authserver.audit.AuditService;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

/**
 * Ends sessions: invalidates every token of an authorization (so introspection answers "inactive" and the refresh
 * token can no longer be used) and marks the session revoked.
 */
@Service
public class SessionRevocationService {

    private final OAuth2AuthorizationService authorizationService;

    private final RegisteredClientRepository clients;

    private final SessionRepository sessions;

    private final AuditService audit;

    private final JdbcClient jdbc;

    public SessionRevocationService(OAuth2AuthorizationService authorizationService,
            RegisteredClientRepository clients, SessionRepository sessions, AuditService audit, JdbcClient jdbc) {
        this.authorizationService = authorizationService;
        this.clients = clients;
        this.sessions = sessions;
        this.audit = audit;
        this.jdbc = jdbc;
    }

    /** Revokes one authorization (one login session). */
    public void revoke(OAuth2Authorization authorization, String reason) {
        OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);
        if (authorization.getRefreshToken() != null) {
            builder.invalidate(authorization.getRefreshToken().getToken());     // also invalidates the access token
        }
        if (authorization.getAccessToken() != null) {
            builder.invalidate(authorization.getAccessToken().getToken());
        }
        OAuth2Authorization.Token<OidcIdToken> idToken = authorization.getToken(OidcIdToken.class);
        if (idToken != null) {
            builder.invalidate(idToken.getToken());
        }
        this.authorizationService.save(builder.build());
        this.sessions.markRevoked(authorization.getId(), Instant.now());

        RegisteredClient client = this.clients.findById(authorization.getRegisteredClientId());
        this.audit.record("REVOKE", (client != null) ? client.getClientId() : null, authorization.getPrincipalName(),
                "SUCCESS", null, reason);
    }

    /** Revokes by authorization id. Returns the subject that was signed out, or null if it no longer exists. */
    public String revokeById(String authorizationId, String reason) {
        OAuth2Authorization authorization = this.authorizationService.findById(authorizationId);
        if (authorization == null) {
            this.sessions.markRevoked(authorizationId, Instant.now());
            return null;
        }
        revoke(authorization, reason);
        return authorization.getPrincipalName();
    }

    /** Revokes every session of one user of one application. Returns how many sessions were revoked. */
    public int revokeAllFor(String clientId, String userId, String reason) {
        RegisteredClient client = this.clients.findByClientId(clientId);
        if (client == null) {
            return 0;
        }
        String subject = clientId + ":" + userId;
        // By subject only (not by client): the subject names the user's directory, and it also finds the tokens other
        // applications received for this user through a hand-off.
        List<String> ids = this.jdbc
            .sql("SELECT id FROM oauth2_authorization WHERE principal_name = :subject")
            .param("subject", subject)
            .query(String.class)
            .list();
        int revoked = 0;
        for (String id : ids) {
            OAuth2Authorization authorization = this.authorizationService.findById(id);
            if (authorization != null) {
                revoke(authorization, reason);
                revoked++;
            }
        }
        this.audit.record("REVOKE_ALL", clientId, subject, "SUCCESS", null, reason + " (" + revoked + " sessions)");
        return revoked;
    }
}
