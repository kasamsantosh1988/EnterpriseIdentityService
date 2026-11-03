package com.example.authserver.directory;

import java.sql.Timestamp;
import java.util.Optional;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class DirectoryConfigRepository {

    private static final RowMapper<DirectoryConfig> MAPPER = (rs, rowNum) -> {
        Timestamp updated = rs.getTimestamp("updated_at");
        return new DirectoryConfig(
                rs.getString("client_id"),
                DirectoryType.valueOf(rs.getString("directory_type")),
                rs.getString("verify_url"),
                rs.getString("status_url"),
                rs.getString("verify_secret_ref"),
                rs.getString("jdbc_url"),
                rs.getString("jdbc_username"),
                rs.getString("jdbc_secret_ref"),
                rs.getString("auth_query"),
                rs.getString("load_query"),
                rs.getString("password_hash_type"),
                rs.getInt("enabled") == 1,
                updated == null ? null : updated.toInstant());
    };

    private final JdbcClient jdbc;

    public DirectoryConfigRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<DirectoryConfig> findByClientId(String clientId) {
        return this.jdbc.sql("""
                SELECT client_id, directory_type, verify_url, status_url, verify_secret_ref,
                       jdbc_url, jdbc_username, jdbc_secret_ref, auth_query, load_query,
                       password_hash_type, enabled, updated_at
                FROM client_directory_config
                WHERE client_id = :clientId
                """)
                .param("clientId", clientId)
                .query(MAPPER)
                .optional();
    }
}
