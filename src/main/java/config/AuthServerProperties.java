package com.example.authserver.config;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings under the "authserver" prefix (see application.yml).
 */
@ConfigurationProperties(prefix = "authserver")
public record AuthServerProperties(String issuer, Signing signing, Bootstrap bootstrap, Directory directory,
        Session session, Limits limits, Cleanup cleanup) {

    public AuthServerProperties {
        if (signing == null) {
            signing = new Signing(null, null, "auth-signing", false, null);
        }
        if (bootstrap == null) {
            bootstrap = new Bootstrap(false, List.of());
        }
        if (directory == null) {
            directory = new Directory(null, null, 0, null);
        }
        if (session == null) {
            session = new Session(null, null, null);
        }
        if (limits == null) {
            limits = new Limits(0, 0, 0, null, null);
        }
        if (cleanup == null) {
            cleanup = new Cleanup(null, null);
        }
    }

    /** RSA signing key source. Leave keystoreLocation blank only together with allowEphemeral=true (dev). */
    public record Signing(String keystoreLocation, String keystorePassword, String keyAlias, boolean allowEphemeral,
            List<String> publishedKeyAliases) {

        public Signing {
            publishedKeyAliases = (publishedKeyAliases == null) ? List.of() : List.copyOf(publishedKeyAliases);
        }
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

    /** How the auth server talks to each application's user directory. */
    public record Directory(Duration connectTimeout, Duration readTimeout, int jdbcPoolSize, Duration configRefresh) {

        public Directory {
            connectTimeout = connectTimeout == null ? Duration.ofSeconds(3) : connectTimeout;
            readTimeout = readTimeout == null ? Duration.ofSeconds(5) : readTimeout;
            jdbcPoolSize = jdbcPoolSize <= 0 ? 3 : jdbcPoolSize;
            configRefresh = configRefresh == null ? Duration.ofSeconds(60) : configRefresh;
        }
    }

    /**
     * Session limits for refresh tokens.
     * {@code idle}: lifetime of each refresh token (a user away longer than this must sign in again). It is applied to
     * clients registered by the dev seed / bootstrap; clients registered by SQL carry their own token settings.
     * {@code absolute}: hard cap on a session's age, however often it is refreshed.
     * {@code reuseGrace}: a just-rotated refresh token presented again within this time (a lost response and a retry)
     * is refused without revoking the session; after it, reuse is treated as theft and the session is revoked.
     */
    public record Session(Duration idle, Duration absolute, Duration reuseGrace) {

        public Session {
            idle = idle == null ? Duration.ofHours(1) : idle;
            absolute = absolute == null ? Duration.ofHours(10) : absolute;
            reuseGrace = reuseGrace == null ? Duration.ofSeconds(10) : reuseGrace;
        }
    }

    /** Failed-login limits. Counters are kept in memory on each node (so the effective limit is per node). */
    public record Limits(int ipFailures, int userFailures, int clientFailures, Duration shortWindow,
            Duration userWindow) {

        public Limits {
            ipFailures = ipFailures <= 0 ? 30 : ipFailures;
            userFailures = userFailures <= 0 ? 5 : userFailures;
            clientFailures = clientFailures <= 0 ? 300 : clientFailures;
            shortWindow = shortWindow == null ? Duration.ofMinutes(10) : shortWindow;
            userWindow = userWindow == null ? Duration.ofMinutes(15) : userWindow;
        }
    }

    /** Housekeeping of expired authorizations, sessions and rotated-token history. */
    public record Cleanup(Duration interval, Duration retention) {

        public Cleanup {
            interval = interval == null ? Duration.ofHours(1) : interval;
            retention = retention == null ? Duration.ofDays(1) : retention;
        }
    }
}
