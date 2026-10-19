package com.vam.eis.config;

import java.util.List;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings under the "authserver" prefix (see application.yml).
 */
@ConfigurationProperties(prefix = "authserver")
public record AuthServerProperties(String issuer, Signing signing, Bootstrap bootstrap) {

    public AuthServerProperties {
        if (signing == null) {
            signing = new Signing(null, null, "auth-signing", false);
        }
        if (bootstrap == null) {
            bootstrap = new Bootstrap(false, List.of());
        }
    }

    /** RSA signing key source. Leave keystoreLocation blank only together with allowEphemeral=true (dev). */
    public record Signing(String keystoreLocation, String keystorePassword, String keyAlias, boolean allowEphemeral) {
    }

    /** Optional seeding of machine clients at startup (dev / first install). */
    public record Bootstrap(boolean enabled, List<MachineClient> clients) {

        public Bootstrap {
            clients = clients == null ? List.of() : clients;
        }
    }

    /** A client that authenticates with a secret and uses the client_credentials grant. */
    public record MachineClient(String clientId, String secret, Set<String> scopes) {

        public MachineClient {
            scopes = scopes == null ? Set.of() : scopes;
        }
    }
}
