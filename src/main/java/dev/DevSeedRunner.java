package com.example.authserver.dev;

import java.time.Duration;
import java.util.UUID;

import com.example.authserver.config.AuthServerProperties;
import com.example.authserver.grant.AppLoginGrant;
import com.example.authserver.grant.HandoffGrant;
import com.example.authserver.handoff.HandoffRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

/**
 * DEV ONLY. Registers a demo application "demo-ui" (confidential client with secret "demo-ui-secret": authorization code + PKCE,
 * app_login, refresh tokens, client credentials),
 * points it at the built-in demo directory, and sets its token audience to "demo-api".
 * In real environments an application is registered with the SQL in docs/directory-contracts.md.
 */
@Component
@Profile("dev")
class DevSeedRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DevSeedRunner.class);

    private static final String CLIENT_ID = "demo-ui";

    private final RegisteredClientRepository clients;

    private final JdbcClient jdbc;

    private static final String CLIENT_SECRET = "demo-ui-secret";

    private final PasswordEncoder passwordEncoder;

    private final AuthServerProperties.Session sessionSettings;

    private final int port;

    private final HandoffRepository handoffs;

    DevSeedRunner(RegisteredClientRepository clients, JdbcClient jdbc, PasswordEncoder passwordEncoder,
            AuthServerProperties props, @Value("${local.server.port:${server.port:9000}}") int port,
            HandoffRepository handoffs) {
        this.handoffs = handoffs;
        this.clients = clients;
        this.jdbc = jdbc;
        this.passwordEncoder = passwordEncoder;
        this.sessionSettings = props.session();
        this.port = port;
    }

    @Override
    public void run(ApplicationArguments args) {
        // Confidential client: refresh and revoke calls must be authenticated, so a backend (or curl, in dev) holds the
        // secret. PKCE stays on for the browser flow. An existing demo-ui from Milestone 2 is updated in place.
        RegisteredClient existing = this.clients.findByClientId(CLIENT_ID);
        this.clients.save(RegisteredClient.withId(existing != null ? existing.getId() : UUID.randomUUID().toString())
            .clientId(CLIENT_ID)
            .clientName("Demo Application")
            .clientSecret(this.passwordEncoder.encode(CLIENT_SECRET))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)      // secret in the form body is accepted too
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AppLoginGrant.TYPE)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .redirectUri("http://127.0.0.1:8080/callback")
            .scope(OidcScopes.OPENID)
            .scope("app")
            .scope("auth.revoke")
            .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
            .tokenSettings(TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .refreshTokenTimeToLive(this.sessionSettings.idle())      // idle timeout
                .reuseRefreshTokens(false)
                .build())
            .build());
        log.info("Dev client '{}' {} (secret '{}')", CLIENT_ID, existing == null ? "created" : "updated", CLIENT_SECRET);

        if (count("SELECT COUNT(*) FROM client_directory_config WHERE client_id = :c", CLIENT_ID) == 0) {
            String base = "http://localhost:" + this.port + "/dev/demo-directory";
            this.jdbc.sql("""
                    INSERT INTO client_directory_config
                        (client_id, directory_type, verify_url, status_url, verify_secret_ref)
                    VALUES (:c, 'REMOTE', :verify, :status, 'demo-dir')
                    """)
                .param("c", CLIENT_ID)
                .param("verify", base + "/verify")
                .param("status", base + "/status")
                .update();
            log.info("Dev directory config for '{}' created", CLIENT_ID);
        }

        // demo-api (the introspection client from application-dev.yml) is registered as the API for audience "demo-api"
        if (count("SELECT COUNT(*) FROM resource_server WHERE id = :c", "demo-api") == 0) {
            this.jdbc.sql("""
                    INSERT INTO resource_server (id, audience, name, introspection_client_id, enabled)
                    VALUES ('demo-api', 'demo-api', 'Demo API', 'demo-api', 1)
                    """).update();
        }
        // demo-service's client_credentials tokens are meant for demo-api as well
        if (count("SELECT COUNT(*) FROM client_audience WHERE client_id = :c", "demo-service") == 0) {
            this.jdbc.sql("INSERT INTO client_audience (client_id, audience) VALUES ('demo-service', 'demo-api')").update();
        }

        if (count("SELECT COUNT(*) FROM client_audience WHERE client_id = :c", CLIENT_ID) == 0) {
            this.jdbc.sql("INSERT INTO client_audience (client_id, audience) VALUES (:c, 'demo-api')")
                .param("c", CLIENT_ID)
                .update();
        }

        seedGateway();
        seedApp2();
    }

    /**
     * A second application with no users of its own: it only receives users handed off from demo-ui. Its gateway
     * redeems the hand-off code with this client id and secret. The link is approved on both sides.
     */
    private void seedApp2() {
        String id = "demo-app2";
        String secret = "demo-app2-secret";
        RegisteredClient existing = this.clients.findByClientId(id);
        this.clients.save(RegisteredClient.withId(existing != null ? existing.getId() : UUID.randomUUID().toString())
            .clientId(id)
            .clientName("Demo Application 2 (hand-off target)")
            .clientSecret(this.passwordEncoder.encode(secret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(HandoffGrant.TYPE)
            .scope("app2.ui")
            .clientSettings(ClientSettings.builder().requireProofKey(false).requireAuthorizationConsent(false).build())
            .tokenSettings(TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .build())
            .build());
        log.info("Dev client '{}' {} (secret '{}')", id, existing == null ? "created" : "updated", secret);

        if (count("SELECT COUNT(*) FROM client_audience WHERE client_id = :c", id) == 0) {
            this.jdbc.sql("INSERT INTO client_audience (client_id, audience) VALUES (:c, 'demo-api')")
                .param("c", id)
                .update();
        }
        this.handoffs.replaceTargets(CLIENT_ID, java.util.List.of(id));
        this.handoffs.replaceAccepts(id, java.util.List.of(CLIENT_ID));
        log.info("Dev hand-off link {} -> {} approved on both sides", CLIENT_ID, id);
    }

    /**
     * The demo gateway (project auth-gateway): the confidential client that does the central login for browsers, keeps the
     * tokens in its own session and relays them to the APIs. Its redirect URI is the gateway's callback.
     */
    private void seedGateway() {
        String id = "demo-gateway";
        String secret = "demo-gateway-secret";
        RegisteredClient existing = this.clients.findByClientId(id);
        this.clients.save(RegisteredClient.withId(existing != null ? existing.getId() : UUID.randomUUID().toString())
            .clientId(id)
            .clientName("Demo Gateway")
            .clientSecret(this.passwordEncoder.encode(secret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)      // secret in the form body is accepted too
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://localhost:8090/login/oauth2/code/auth")
            .scope(OidcScopes.OPENID)
            .scope("app")
            .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
            .tokenSettings(TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .refreshTokenTimeToLive(this.sessionSettings.idle())
                .reuseRefreshTokens(false)
                .build())
            .build());
        log.info("Dev client '{}' {} (secret '{}')", id, existing == null ? "created" : "updated", secret);

        if (count("SELECT COUNT(*) FROM client_directory_config WHERE client_id = :c", id) == 0) {
            String base = "http://localhost:" + this.port + "/dev/demo-directory";
            this.jdbc.sql("""
                    INSERT INTO client_directory_config
                        (client_id, directory_type, verify_url, status_url, verify_secret_ref)
                    VALUES (:c, 'REMOTE', :verify, :status, 'demo-dir')
                    """)
                .param("c", id)
                .param("verify", base + "/verify")
                .param("status", base + "/status")
                .update();
        }
        if (count("SELECT COUNT(*) FROM client_audience WHERE client_id = :c", id) == 0) {
            this.jdbc.sql("INSERT INTO client_audience (client_id, audience) VALUES (:c, 'demo-api')")
                .param("c", id)
                .update();
        }
    }

    private int count(String sql, String clientId) {
        Integer value = this.jdbc.sql(sql).param("c", clientId).query(Integer.class).single();
        return value == null ? 0 : value;
    }
}
