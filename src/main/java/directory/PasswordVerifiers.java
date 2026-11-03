package com.example.authserver.directory;

import java.util.Locale;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Password hash formats the JDBC provider understands. Applications with older or custom formats
 * (salted SHA, MD5, ...) need a new entry here - keep each one small and well tested.
 */
public final class PasswordVerifiers {

    private static final PasswordEncoder DUMMY_ENCODER = new BCryptPasswordEncoder();

    private static final String DUMMY_HASH = DUMMY_ENCODER.encode("not-a-real-password");

    private PasswordVerifiers() {
    }

    public static PasswordVerifier forType(String type) {
        String normalized = type == null ? "BCRYPT" : type.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "BCRYPT" -> {
                PasswordEncoder bcrypt = new BCryptPasswordEncoder();
                yield bcrypt::matches;
            }
            case "DELEGATING" -> {
                // Hashes stored as {bcrypt}..., {argon2}..., {pbkdf2}... etc.
                PasswordEncoder delegating = PasswordEncoderFactories.createDelegatingPasswordEncoder();
                yield delegating::matches;
            }
            default -> throw new IllegalArgumentException("Unsupported password_hash_type '" + type
                    + "'. Add a PasswordVerifier for that format in PasswordVerifiers.");
        };
    }

    /** Spends about as long as a real check, so "unknown user" and "wrong password" take similar time. */
    public static void burnTime(CharSequence rawPassword) {
        DUMMY_ENCODER.matches(rawPassword, DUMMY_HASH);
    }
}
