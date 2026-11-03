package com.example.authserver.login;

/** Extra data captured at login time. Used only while authenticating; it is not stored in the session's token. */
public record LoginDetails(String clientId, String ipAddress) implements java.io.Serializable {
}
