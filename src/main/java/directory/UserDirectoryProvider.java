package com.example.authserver.directory;

import java.util.Optional;

/**
 * One application's user directory, as seen by the auth server. The application keeps owning its users
 * and credentials; implementations only ask it questions.
 */
public interface UserDirectoryProvider extends AutoCloseable {

    /** Validates credentials. Never throws for "wrong password"; return a failure status instead. */
    AuthResult authenticate(String username, char[] password, AuthContext context);

    /**
     * Looks a user up by the app's own id (used to re-check status and roles on refresh).
     * Empty means "no such user". Throws {@link DirectoryUnavailableException} if the directory cannot answer.
     */
    Optional<UserInfo> loadById(String userId);

    @Override
    default void close() {
    }
}
