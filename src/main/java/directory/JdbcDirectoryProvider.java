package com.example.authserver.directory;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.example.authserver.config.AuthServerProperties;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * Validates users by querying the application's own database, read-only.
 *
 * The two queries come from client_directory_config and must return these columns:
 * user_id, password_hash, display_name, status, roles   (see docs/directory-contracts.md).
 * authQuery takes :username, loadQuery takes :userId. Only named parameters are used - never string concatenation.
 */
public class JdbcDirectoryProvider implements UserDirectoryProvider {

    private record Row(String userId, String passwordHash, String displayName, String status, Set<String> roles) {
    }

    private final HikariDataSource dataSource;

    private final NamedParameterJdbcTemplate jdbc;

    private final String authQuery;

    private final String loadQuery;

    private final PasswordVerifier passwordVerifier;

    public JdbcDirectoryProvider(DirectoryConfig config, String dbPassword, AuthServerProperties.Directory settings) {
        this.authQuery = requireSelect(config.authQuery(), "auth_query");
        this.loadQuery = requireSelect(config.loadQuery(), "load_query");
        this.passwordVerifier = PasswordVerifiers.forType(config.passwordHashType());

        if (config.jdbcUrl() == null || config.jdbcUrl().isBlank()) {
            throw new IllegalStateException("jdbc_url is required for JDBC directories");
        }
        HikariConfig hikari = new HikariConfig();
        hikari.setPoolName("directory-" + config.clientId());
        hikari.setJdbcUrl(config.jdbcUrl());
        hikari.setUsername(config.jdbcUsername());
        hikari.setPassword(dbPassword);
        hikari.setReadOnly(true);
        hikari.setMaximumPoolSize(settings.jdbcPoolSize());
        hikari.setMinimumIdle(0);
        hikari.setConnectionTimeout(settings.connectTimeout().toMillis());
        hikari.setInitializationFailTimeout(-1);          // do not fail at startup if the app DB is down; fail per request instead
        this.dataSource = new HikariDataSource(hikari);

        this.jdbc = new NamedParameterJdbcTemplate(this.dataSource);
        this.jdbc.getJdbcTemplate().setQueryTimeout((int) Math.max(1, settings.readTimeout().toSeconds()));
    }

    @Override
    public AuthResult authenticate(String username, char[] password, AuthContext context) {
        Optional<Row> found = query(this.authQuery, Map.of("username", username));
        if (found.isEmpty()) {
            PasswordVerifiers.burnTime(new String(password));      // keep unknown-user timing close to wrong-password timing
            return AuthResult.failure(AuthStatus.INVALID_CREDENTIALS);
        }
        Row row = found.get();
        if (!passwordMatches(password, row.passwordHash())) {
            return AuthResult.failure(AuthStatus.INVALID_CREDENTIALS);   // never reveal account state without a correct password
        }
        AuthStatus status = mapStatus(row.status());
        if (status != AuthStatus.SUCCESS) {
            return AuthResult.failure(status);
        }
        return AuthResult.success(new UserInfo(row.userId(), row.displayName(), row.roles(), true));
    }

    @Override
    public Optional<UserInfo> loadById(String userId) {
        return query(this.loadQuery, Map.of("userId", userId))
            .map((row) -> new UserInfo(row.userId(), row.displayName(), row.roles(),
                    mapStatus(row.status()) == AuthStatus.SUCCESS));
    }

    @Override
    public void close() {
        this.dataSource.close();
    }

    private Optional<Row> query(String sql, Map<String, Object> params) {
        List<Row> rows;
        try {
            rows = this.jdbc.query(sql, params, (rs, rowNum) -> new Row(
                    rs.getString("user_id"),
                    rs.getString("password_hash"),
                    rs.getString("display_name"),
                    rs.getString("status"),
                    splitRoles(rs.getString("roles"))));
        }
        catch (DataAccessException ex) {
            throw new DirectoryUnavailableException("Directory query failed: " + ex.getClass().getSimpleName(), ex);
        }
        if (rows.size() > 1) {
            // Ambiguous match (for example two users differing only by case): refuse rather than guess.
            throw new DirectoryUnavailableException("Directory query returned more than one user", null);
        }
        return rows.stream().findFirst().filter((row) -> row.userId() != null && !row.userId().isBlank());
    }

    private boolean passwordMatches(char[] password, String storedHash) {
        if (storedHash == null || storedHash.isBlank()) {
            return false;
        }
        try {
            return this.passwordVerifier.matches(new String(password), storedHash);
        }
        catch (IllegalArgumentException ex) {
            return false;                                  // malformed hash or over-long input: treat as no match
        }
    }

    private static AuthStatus mapStatus(String status) {
        if (status == null) {
            return AuthStatus.DISABLED;                    // missing status: fail closed
        }
        return switch (status.trim().toUpperCase(Locale.ROOT)) {
            case "ACTIVE", "ENABLED", "OK" -> AuthStatus.SUCCESS;
            case "LOCKED" -> AuthStatus.LOCKED;
            case "EXPIRED" -> AuthStatus.EXPIRED;
            case "MUST_CHANGE_PASSWORD" -> AuthStatus.MUST_CHANGE_PASSWORD;
            default -> AuthStatus.DISABLED;
        };
    }

    private static Set<String> splitRoles(String roles) {
        Set<String> result = new LinkedHashSet<>();
        if (roles != null) {
            for (String part : roles.split(",")) {
                if (!part.isBlank()) {
                    result.add(part.trim());
                }
            }
        }
        return result;
    }

    /** The queries are admin-configured SQL run with a read-only account; this is a sanity guard, not a sandbox. */
    private static String requireSelect(String sql, String field) {
        if (sql == null || sql.isBlank()) {
            throw new IllegalStateException(field + " is required for JDBC directories");
        }
        String trimmed = sql.trim();
        if (!trimmed.regionMatches(true, 0, "select", 0, 6) || trimmed.contains(";")) {
            throw new IllegalStateException(field + " must be a single SELECT statement without ';'");
        }
        return trimmed;
    }
}
