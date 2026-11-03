package com.example.authserver.ratelimit;

import org.springframework.security.core.AuthenticationException;

/** Too many failed sign-ins for this address, user or application. The caller should wait before trying again. */
public class TooManyAttemptsException extends AuthenticationException {

    private final long retryAfterSeconds;

    public TooManyAttemptsException(long retryAfterSeconds) {
        super("Too many failed attempts");
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long getRetryAfterSeconds() {
        return this.retryAfterSeconds;
    }
}
