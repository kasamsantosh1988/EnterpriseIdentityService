package com.example.authserver.directory;

import java.util.Locale;

/** Outcome of asking an application's directory to validate a user. Only SUCCESS lets the login continue. */
public enum AuthStatus {

    SUCCESS,
    INVALID_CREDENTIALS,
    LOCKED,
    EXPIRED,
    MUST_CHANGE_PASSWORD,
    DISABLED,
    ERROR;

    /** Parses a status sent by an application's verify service; anything unknown is treated as ERROR (fail closed). */
    public static AuthStatus parse(String value) {
        if (value == null) {
            return ERROR;
        }
        try {
            return valueOf(value.trim().toUpperCase(Locale.ROOT));
        }
        catch (IllegalArgumentException ex) {
            return ERROR;
        }
    }
}
