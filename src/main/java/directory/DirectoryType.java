package com.example.authserver.directory;

public enum DirectoryType {
    /** The auth server calls the application's own verify service over HTTP(S). */
    REMOTE,
    /** The auth server queries the application's database directly (read-only). */
    JDBC
}
