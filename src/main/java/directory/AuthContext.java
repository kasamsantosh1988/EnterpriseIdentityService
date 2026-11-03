package com.example.authserver.directory;

/** Who is asking: the registered client the login belongs to and the caller's address (for the app's own audit/lockout). */
public record AuthContext(String clientId, String ipAddress) {
}
