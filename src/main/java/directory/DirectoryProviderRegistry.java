package com.example.authserver.directory;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import com.example.authserver.config.AuthServerProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Finds the user directory for a registered client. Providers (and their connection pools) are created once
 * and reused. The configuration row is re-read every authserver.directory.config-refresh; if it changed,
 * the provider is rebuilt, and if the row was disabled or deleted, the provider is closed.
 */
@Component
public class DirectoryProviderRegistry implements DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(DirectoryProviderRegistry.class);

    private record Holder(DirectoryConfig config, UserDirectoryProvider provider, long checkedAtNanos) {
    }

    private final DirectoryConfigRepository repository;

    private final SecretResolver secrets;

    private final AuthServerProperties.Directory settings;

    private final ConcurrentHashMap<String, Holder> holders = new ConcurrentHashMap<>();

    public DirectoryProviderRegistry(DirectoryConfigRepository repository, SecretResolver secrets,
            AuthServerProperties props) {
        this.repository = repository;
        this.secrets = secrets;
        this.settings = props.directory();
    }

    /** Empty if the client has no enabled directory. Throws if a directory is configured but cannot be built. */
    public Optional<UserDirectoryProvider> find(String clientId) {
        if (!StringUtils.hasText(clientId)) {
            return Optional.empty();
        }
        Holder holder = this.holders.get(clientId);
        if (holder != null && fresh(holder)) {
            return Optional.of(holder.provider());
        }
        return reload(clientId);
    }

    private synchronized Optional<UserDirectoryProvider> reload(String clientId) {
        Holder current = this.holders.get(clientId);
        if (current != null && fresh(current)) {
            return Optional.of(current.provider());
        }
        long now = System.nanoTime();
        Optional<DirectoryConfig> loaded = this.repository.findByClientId(clientId);

        if (loaded.isEmpty() || !loaded.get().enabled()) {
            if (current != null) {
                this.holders.remove(clientId);
                closeQuietly(current.provider());
            }
            return Optional.empty();
        }
        DirectoryConfig config = loaded.get();
        if (current != null && current.config().equals(config)) {
            this.holders.put(clientId, new Holder(config, current.provider(), now));
            return Optional.of(current.provider());
        }

        UserDirectoryProvider provider = build(config);     // may throw: the old provider (if any) stays in place
        this.holders.put(clientId, new Holder(config, provider, now));
        if (current != null) {
            closeQuietly(current.provider());
        }
        log.info("Directory provider for client '{}' loaded (type {})", clientId, config.type());
        return Optional.of(provider);
    }

    private UserDirectoryProvider build(DirectoryConfig config) {
        return switch (config.type()) {
            case REMOTE -> new RemoteVerifyProvider(config, this.secrets.resolve(config.verifySecretRef()), this.settings);
            case JDBC -> new JdbcDirectoryProvider(config, this.secrets.resolve(config.jdbcSecretRef()), this.settings);
        };
    }

    private boolean fresh(Holder holder) {
        return System.nanoTime() - holder.checkedAtNanos() < this.settings.configRefresh().toNanos();
    }

    private static void closeQuietly(UserDirectoryProvider provider) {
        try {
            provider.close();
        }
        catch (Exception ex) {
            log.warn("Error closing directory provider", ex);
        }
    }

    @Override
    public void destroy() {
        this.holders.values().forEach((holder) -> closeQuietly(holder.provider()));
        this.holders.clear();
    }
}
