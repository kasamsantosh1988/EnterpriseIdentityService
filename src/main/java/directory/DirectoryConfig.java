package com.example.authserver.directory;

import java.time.Instant;

/** One row of client_directory_config. Secrets are never stored here, only references to them. */
public record DirectoryConfig(
        String clientId,
        DirectoryType type,
        String verifyUrl,
        String statusUrl,
        String verifySecretRef,
        String jdbcUrl,
        String jdbcUsername,
        String jdbcSecretRef,
        String authQuery,
        String loadQuery,
        String passwordHashType,
        boolean enabled,
        Instant updatedAt) {
}
