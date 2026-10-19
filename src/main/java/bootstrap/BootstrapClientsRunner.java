package com.vam.eis.bootstrap;

import java.time.Duration;
import java.util.UUID;

import com.vam.eis.config.AuthServerProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

/**
 * Seeds client_credentials clients listed under authserver.bootstrap.clients if they do not exist.
 * Secrets are hashed before they are stored. Disabled unless authserver.bootstrap.enabled=true.
 * Later milestones replace this with an admin API for onboarding applications.
 */
@Component
@ConditionalOnProperty(prefix = "authserver.bootstrap", name = "enabled", havingValue = "true")
class BootstrapClientsRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapClientsRunner.class);

    private final AuthServerProperties props;
    private final RegisteredClientRepository clients;
    private final PasswordEncoder passwordEncoder;

    BootstrapClientsRunner(AuthServerProperties props, RegisteredClientRepository clients,
            PasswordEncoder passwordEncoder) {
        this.props = props;
        this.clients = clients;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(ApplicationArguments args) {
        for (AuthServerProperties.MachineClient c : props.bootstrap().clients()) {
            if (clients.findByClientId(c.clientId()) != null) {
                log.info("Bootstrap client '{}' already exists, skipping", c.clientId());
                continue;
            }
            RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(c.clientId())
                .clientName(c.clientId())
                .clientSecret(passwordEncoder.encode(c.secret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes((scopes) -> scopes.addAll(c.scopes()))
                .tokenSettings(TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.REFERENCE)      // opaque tokens, validated by introspection
                    .accessTokenTimeToLive(Duration.ofMinutes(30))
                    .build())
                .build();
            clients.save(client);
            log.info("Bootstrap client '{}' created", c.clientId());
        }
    }
}
