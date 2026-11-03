package com.example.authserver.directory;

/** Checks a typed password against the hash stored in an application's database. */
public interface PasswordVerifier {

    boolean matches(CharSequence rawPassword, String storedHash);
}
