package com.example.authserver.handoff;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.example.authserver.audit.AuditService;
import com.example.authserver.grant.AppLoginGrant;
import com.example.authserver.grant.HandoffGrant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Issues one-time hand-off codes. A source application backend proves who it is (client secret) and presents the access
 * token of a user it signed in itself; the server checks that source and target agreed to hand off, stores the opaque
 * context the source wants to carry, and returns a short-lived single-use code.
 */
@Service
public class HandoffService {

    /** What the caller gets back. */
    public record Issued(String code, long expiresIn) {
    }

    /** A refusal with the HTTP status and OAuth-style error to answer with. */
    public static class HandoffException extends RuntimeException {

        private final HttpStatus status;

        private final String error;

        public HandoffException(HttpStatus status, String error, String description) {
            super(description);
            this.status = status;
            this.error = error;
        }

        public HttpStatus status() {
            return this.status;
        }

        public String error() {
            return this.error;
        }
    }

    private static final Pattern CLIENT_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{1,98}");

    /** Printable ASCII only: the context is opaque text such as Base64 of encrypted values. */
    private static final Pattern CONTEXT = Pattern.compile("[\\x20-\\x7E]*");

    private static final String NOT_ALLOWED = "This hand-off is not allowed";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final OAuth2AuthorizationService authorizations;

    private final RegisteredClientRepository clients;

    private final HandoffRepository handoffs;

    private final AuditService audit;

    private final Duration codeTtl;

    private final int maxContextLength;

    public HandoffService(OAuth2AuthorizationService authorizations, RegisteredClientRepository clients,
            HandoffRepository handoffs, AuditService audit,
            @Value("${authserver.handoff.code-ttl:60s}") Duration codeTtl,
            @Value("${authserver.handoff.max-context-length:2048}") int maxContextLength) {
        this.authorizations = authorizations;
        this.clients = clients;
        this.handoffs = handoffs;
        this.audit = audit;
        this.codeTtl = codeTtl;
        this.maxContextLength = Math.min(maxContextLength, 2048);          // the column holds 2048
    }

    public Issued issue(RegisteredClient source, String subjectToken, String targetClientId, String context, String ip) {
        if (!StringUtils.hasText(subjectToken)) {
            throw new HandoffException(HttpStatus.BAD_REQUEST, "invalid_request", "subjectToken is required");
        }
        if (targetClientId == null || !CLIENT_ID.matcher(targetClientId).matches()) {
            throw new HandoffException(HttpStatus.BAD_REQUEST, "invalid_request", "targetClientId is invalid");
        }
        if (context != null && (context.length() > this.maxContextLength || !CONTEXT.matcher(context).matches())) {
            throw new HandoffException(HttpStatus.BAD_REQUEST, "invalid_request",
                    "context must be printable text of at most " + this.maxContextLength + " characters");
        }

        // 1. The user's pass: active, issued to the caller itself, for a user the caller signed in.
        OAuth2Authorization authorization = this.authorizations.findByToken(subjectToken, OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null) {
            return deny(source, null, targetClientId, HttpStatus.UNAUTHORIZED, "invalid_token",
                    "The subject token is not valid", "unknown token");
        }
        OAuth2Authorization.Token<OAuth2AccessToken> access = authorization.getAccessToken();
        if (access == null || !access.isActive()) {
            return deny(source, authorization.getPrincipalName(), targetClientId, HttpStatus.UNAUTHORIZED,
                    "invalid_token", "The subject token is not valid", "inactive token");
        }
        if (!source.getId().equals(authorization.getRegisteredClientId())) {
            return deny(source, authorization.getPrincipalName(), targetClientId, HttpStatus.FORBIDDEN, "access_denied",
                    "The subject token was not issued to this client", "token of another client");
        }
        AuthorizationGrantType grant = authorization.getAuthorizationGrantType();
        String subject = authorization.getPrincipalName();
        boolean signedInUser = (AuthorizationGrantType.AUTHORIZATION_CODE.equals(grant)
                || AppLoginGrant.TYPE.equals(grant))
                && subject != null && subject.startsWith(source.getClientId() + ":");
        if (!signedInUser) {
            // client_credentials tokens have no user; a token that came from a hand-off is not handed on again.
            return deny(source, subject, targetClientId, HttpStatus.FORBIDDEN, "access_denied",
                    "Only the token of a user signed in at this client can be handed off", "not a user token");
        }

        // 2. Both sides agreed. One answer for every reason, so the endpoint does not reveal which applications exist.
        RegisteredClient target = this.clients.findByClientId(targetClientId);
        boolean allowed = target != null && target.getAuthorizationGrantTypes().contains(HandoffGrant.TYPE)
                && this.handoffs.isAllowed(source.getClientId(), targetClientId);
        if (!allowed) {
            return deny(source, subject, targetClientId, HttpStatus.FORBIDDEN, "access_denied", NOT_ALLOWED,
                    "no agreed link");
        }

        // 3. Store the context and return the code.
        String code = newCode();
        Instant now = Instant.now();
        this.handoffs.insertCode(code, source.getClientId(), targetClientId, subject, rolesOf(access), context, now,
                now.plus(this.codeTtl));
        this.audit.record("HANDOFF_ISSUED", source.getClientId(), subject, "SUCCESS", ip, "to " + targetClientId);
        return new Issued(code, this.codeTtl.toSeconds());
    }

    private Issued deny(RegisteredClient source, String subject, String target, HttpStatus status, String error,
            String description, String reason) {
        this.audit.record("HANDOFF_DENIED", source.getClientId(), subject, "FAILURE", null,
                "to " + target + ": " + reason);
        throw new HandoffException(status, error, description);
    }

    /** The roles the source put in the user's token (they are the source directory's roles). */
    private static Collection<String> rolesOf(OAuth2Authorization.Token<OAuth2AccessToken> access) {
        List<String> roles = new ArrayList<>();
        Map<String, Object> claims = access.getClaims();
        if (claims != null && claims.get("roles") instanceof Collection<?> values) {
            for (Object value : values) {
                if (value != null) {
                    roles.add(value.toString());
                }
            }
        }
        return roles;
    }

    private static String newCode() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
