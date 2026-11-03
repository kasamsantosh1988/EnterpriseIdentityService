package com.example.authserver.admin;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import com.example.authserver.audit.AuditService;
import com.example.authserver.config.AuthServerProperties;
import com.example.authserver.grant.AppLoginGrant;
import com.example.authserver.grant.HandoffGrant;
import com.example.authserver.handoff.HandoffRepository;
import com.example.authserver.introspection.ResourceServerRepository;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * Registers applications and APIs. Secrets are generated here, stored hashed, and returned exactly once.
 * Secrets for user directories (the key sent to an app's verify service, an app database password) are never accepted
 * here: only a reference name, resolved from the environment/Vault when needed.
 */
@Service
public class OnboardingService {

    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{1,98}");     // no ':' (subject = clientId:userId)

    private static final Set<String> ALLOWED_GRANTS = Set.of("authorization_code", "app_login", "refresh_token",
            "client_credentials", "handoff");

    private static final int MAX_LINKS = 50;

    private static final SecureRandom RANDOM = new SecureRandom();

    public record DirectorySpec(String type, String verifyUrl, String statusUrl, String verifySecretRef,
            String jdbcUrl, String jdbcUsername, String jdbcSecretRef, String authQuery, String loadQuery,
            String passwordHashType) {
    }

    public record AppSpec(String clientId, String name, List<String> redirectUris, List<String> scopes,
            List<String> grants, List<String> audiences, DirectorySpec directory, List<String> handoffTargets,
            List<String> acceptsHandoffFrom) {
    }

    public record HandoffLinks(String clientId, List<String> handoffTargets, List<String> acceptsHandoffFrom) {
    }

    public record Created(String clientId, String clientSecret) {
    }

    public static class InvalidSpecException extends RuntimeException {

        public InvalidSpecException(String message) {
            super(message);
        }
    }

    public static class ConflictException extends RuntimeException {

        public ConflictException(String message) {
            super(message);
        }
    }

    private final RegisteredClientRepository clients;

    private final PasswordEncoder passwordEncoder;

    private final JdbcClient jdbc;

    private final ResourceServerRepository resourceServers;

    private final AuditService audit;

    private final AuthServerProperties.Session session;

    private final HandoffRepository handoffs;

    public OnboardingService(RegisteredClientRepository clients, PasswordEncoder passwordEncoder, JdbcClient jdbc,
            ResourceServerRepository resourceServers, AuditService audit, AuthServerProperties props,
            HandoffRepository handoffs) {
        this.handoffs = handoffs;
        this.clients = clients;
        this.passwordEncoder = passwordEncoder;
        this.jdbc = jdbc;
        this.resourceServers = resourceServers;
        this.audit = audit;
        this.session = props.session();
    }

    @Transactional
    public Created registerApp(AppSpec spec, String adminClient) {
        validateApp(spec);
        if (this.clients.findByClientId(spec.clientId()) != null) {
            throw new ConflictException("Client '" + spec.clientId() + "' already exists");
        }
        String secret = newSecret();
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(spec.clientId())
            .clientName(StringUtils.hasText(spec.name()) ? spec.name() : spec.clientId())
            .clientSecret(this.passwordEncoder.encode(secret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)      // secret in the form body is accepted too
            .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
            .tokenSettings(TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .refreshTokenTimeToLive(this.session.idle())
                .reuseRefreshTokens(false)
                .build());
        for (String grant : spec.grants()) {
            builder.authorizationGrantType("app_login".equals(grant) ? AppLoginGrant.TYPE
                    : "handoff".equals(grant) ? HandoffGrant.TYPE
                    : new AuthorizationGrantType(grant));
        }
        if (spec.redirectUris() != null) {
            spec.redirectUris().forEach(builder::redirectUri);
        }
        if (spec.scopes() != null) {
            spec.scopes().forEach(builder::scope);
        }
        this.clients.save(builder.build());

        if (spec.audiences() != null) {
            for (String audience : spec.audiences()) {
                this.jdbc.sql("INSERT INTO client_audience (client_id, audience) VALUES (:c, :a)")
                    .param("c", spec.clientId())
                    .param("a", audience)
                    .update();
            }
        }
        if (spec.directory() != null) {
            insertDirectory(spec.clientId(), spec.directory());
        }
        if (spec.handoffTargets() != null && !spec.handoffTargets().isEmpty()) {
            this.handoffs.replaceTargets(spec.clientId(), spec.handoffTargets());
        }
        if (spec.acceptsHandoffFrom() != null && !spec.acceptsHandoffFrom().isEmpty()) {
            this.handoffs.replaceAccepts(spec.clientId(), spec.acceptsHandoffFrom());
        }
        this.audit.record("CLIENT_REGISTERED", spec.clientId(), null, "SUCCESS", null, "by " + adminClient);
        return new Created(spec.clientId(), secret);
    }

    /**
     * Changes an application's hand-off links. null = leave that side unchanged, empty list = clear it. A hand-off works
     * only when the source lists the target AND the target lists the source.
     */
    @Transactional
    public HandoffLinks setHandoffLinks(String clientId, List<String> targets, List<String> accepts,
            String adminClient) {
        RegisteredClient client = this.clients.findByClientId(clientId);
        if (client == null) {
            throw new InvalidSpecException("Unknown client");
        }
        if (targets != null) {
            validateLinkIds(clientId, targets, "handoffTargets");
            this.handoffs.replaceTargets(clientId, targets);
        }
        if (accepts != null) {
            validateLinkIds(clientId, accepts, "acceptsHandoffFrom");
            if (!accepts.isEmpty() && !client.getAuthorizationGrantTypes().contains(HandoffGrant.TYPE)) {
                throw new InvalidSpecException("acceptsHandoffFrom requires the 'handoff' grant");
            }
            this.handoffs.replaceAccepts(clientId, accepts);
        }
        this.audit.record("HANDOFF_LINKS_CHANGED", clientId, null, "SUCCESS", null, "by " + adminClient);
        return handoffLinks(clientId);
    }

    public HandoffLinks handoffLinks(String clientId) {
        if (this.clients.findByClientId(clientId) == null) {
            throw new InvalidSpecException("Unknown client");
        }
        return new HandoffLinks(clientId, this.handoffs.targetsOf(clientId), this.handoffs.acceptsOf(clientId));
    }

    private static void validateLinkIds(String self, List<String> ids, String field) {
        if (ids.size() > MAX_LINKS) {
            throw new InvalidSpecException(field + " may list at most " + MAX_LINKS + " applications");
        }
        for (String id : ids) {
            requireId(id, field + " entry");
            if (id.equals(self)) {
                throw new InvalidSpecException(field + " must not contain the application itself");
            }
        }
    }

    /** Registers an API: an introspection-only client plus the resource_server row that defines its audience. */
    @Transactional
    public Created registerResourceServer(String id, String audience, String name, String adminClient) {
        requireId(id, "id");
        if (!StringUtils.hasText(audience) || audience.length() > 200) {
            throw new InvalidSpecException("audience is required (max 200 chars)");
        }
        String clientId = id;
        if (this.clients.findByClientId(clientId) != null || this.resourceServers.exists(id)) {
            throw new ConflictException("'" + id + "' already exists");
        }
        String secret = newSecret();
        this.clients.save(RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientName(StringUtils.hasText(name) ? name : id)
            .clientSecret(this.passwordEncoder.encode(secret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)      // secret in the form body is accepted too
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)        // needed by the client model; no scopes
            .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
            .build());
        try {
            this.resourceServers.insert(new ResourceServerRepository.ResourceServer(id, audience,
                    StringUtils.hasText(name) ? name : id, clientId, true));
        }
        catch (DuplicateKeyException ex) {
            throw new ConflictException("Audience '" + audience + "' is already used by another API");
        }
        this.audit.record("RESOURCE_SERVER_REGISTERED", clientId, null, "SUCCESS", null,
                "audience " + audience + " by " + adminClient);
        return new Created(clientId, secret);
    }

    /** New secret for an existing client; the old one stops working at once. */
    public Created rotateSecret(String clientId, String adminClient) {
        RegisteredClient existing = this.clients.findByClientId(clientId);
        if (existing == null) {
            throw new InvalidSpecException("Unknown client");
        }
        String secret = newSecret();
        this.clients.save(RegisteredClient.from(existing)
            .clientSecret(this.passwordEncoder.encode(secret))
            .clientSecretExpiresAt(null)
            .build());
        this.audit.record("CLIENT_SECRET_ROTATED", clientId, null, "SUCCESS", null, "by " + adminClient);
        return new Created(clientId, secret);
    }

    /** Switches an application's user directory on or off. Off = nobody of that app can log in or refresh. */
    public void setDirectoryEnabled(String clientId, boolean enabled, String adminClient) {
        int updated = this.jdbc.sql("""
                UPDATE client_directory_config SET enabled = :e, updated_at = :now WHERE client_id = :c
                """)
            .param("e", enabled ? 1 : 0)
            .param("now", java.sql.Timestamp.from(java.time.Instant.now()))
            .param("c", clientId)
            .update();
        if (updated == 0) {
            throw new InvalidSpecException("No directory configured for that client");
        }
        this.audit.record(enabled ? "DIRECTORY_ENABLED" : "DIRECTORY_DISABLED", clientId, null, "SUCCESS", null,
                "by " + adminClient);
    }

    public void setResourceServerEnabled(String id, boolean enabled, String adminClient) {
        if (this.resourceServers.setEnabled(id, enabled) == 0) {
            throw new InvalidSpecException("Unknown resource server");
        }
        this.audit.record(enabled ? "RESOURCE_SERVER_ENABLED" : "RESOURCE_SERVER_DISABLED", id, null, "SUCCESS", null,
                "by " + adminClient);
    }

    public List<ResourceServerRepository.ResourceServer> listResourceServers() {
        return this.resourceServers.findAll();
    }

    private void validateApp(AppSpec spec) {
        if (spec == null) {
            throw new InvalidSpecException("Body is required");
        }
        requireId(spec.clientId(), "clientId");
        if (spec.grants() == null || spec.grants().isEmpty()) {
            throw new InvalidSpecException("grants is required");
        }
        for (String grant : spec.grants()) {
            if (!ALLOWED_GRANTS.contains(grant)) {
                throw new InvalidSpecException("Unsupported grant '" + grant + "'");
            }
        }
        if (spec.grants().contains("authorization_code") && (spec.redirectUris() == null || spec.redirectUris().isEmpty())) {
            throw new InvalidSpecException("redirectUris is required for authorization_code");
        }
        if (spec.scopes() != null && spec.scopes().stream().anyMatch((s) -> s.startsWith("auth.") && !s.equals("auth.revoke"))) {
            throw new InvalidSpecException("Scopes starting with 'auth.' are reserved for platform administration (only 'auth.revoke' may be given to an application)");
        }
        if (spec.directory() == null && (spec.grants().contains("app_login") || spec.grants().contains("authorization_code"))) {
            throw new InvalidSpecException("directory is required for user login grants");
        }
        if (spec.handoffTargets() != null) {
            validateLinkIds(spec.clientId(), spec.handoffTargets(), "handoffTargets");
        }
        if (spec.acceptsHandoffFrom() != null) {
            validateLinkIds(spec.clientId(), spec.acceptsHandoffFrom(), "acceptsHandoffFrom");
            if (!spec.acceptsHandoffFrom().isEmpty() && !spec.grants().contains("handoff")) {
                throw new InvalidSpecException("acceptsHandoffFrom requires the 'handoff' grant");
            }
        }
    }

    private void insertDirectory(String clientId, DirectorySpec d) {
        String type = (d.type() == null) ? "" : d.type().toUpperCase();
        if (type.equals("REMOTE")) {
            requireText(d.verifyUrl(), "directory.verifyUrl");
            requireText(d.verifySecretRef(), "directory.verifySecretRef");
        }
        else if (type.equals("JDBC")) {
            requireText(d.jdbcUrl(), "directory.jdbcUrl");
            requireText(d.jdbcUsername(), "directory.jdbcUsername");
            requireText(d.jdbcSecretRef(), "directory.jdbcSecretRef");
            requireText(d.authQuery(), "directory.authQuery");
            requireText(d.loadQuery(), "directory.loadQuery");
        }
        else {
            throw new InvalidSpecException("directory.type must be REMOTE or JDBC");
        }
        this.jdbc.sql("""
                INSERT INTO client_directory_config
                    (client_id, directory_type, verify_url, status_url, verify_secret_ref, jdbc_url, jdbc_username,
                     jdbc_secret_ref, auth_query, load_query, password_hash_type)
                VALUES (:c, :type, :verify, :status, :vref, :jurl, :juser, :jref, :aq, :lq, :hash)
                """)
            .param("c", clientId)
            .param("type", type)
            .param("verify", nz(d.verifyUrl()))
            .param("status", nz(d.statusUrl()))
            .param("vref", nz(d.verifySecretRef()))
            .param("jurl", nz(d.jdbcUrl()))
            .param("juser", nz(d.jdbcUsername()))
            .param("jref", nz(d.jdbcSecretRef()))
            .param("aq", nz(d.authQuery()))
            .param("lq", nz(d.loadQuery()))
            .param("hash", StringUtils.hasText(d.passwordHashType()) ? d.passwordHashType() : "BCRYPT")
            .update();
    }

    private static void requireId(String value, String field) {
        if (value == null || !ID.matcher(value).matches()) {
            throw new InvalidSpecException(field + " must be 2-99 chars of letters, digits, '.', '_' or '-'");
        }
    }

    private static void requireText(String value, String field) {
        if (!StringUtils.hasText(value)) {
            throw new InvalidSpecException(field + " is required");
        }
    }

    /** Oracle stores '' as NULL; bind null explicitly for blank values. */
    private static String nz(String value) {
        return StringUtils.hasText(value) ? value : null;
    }

    private static String newSecret() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
