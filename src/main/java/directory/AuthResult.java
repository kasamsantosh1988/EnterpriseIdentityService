package com.example.authserver.directory;

public record AuthResult(AuthStatus status, UserInfo user) {

    public static AuthResult success(UserInfo user) {
        return new AuthResult(AuthStatus.SUCCESS, user);
    }

    public static AuthResult failure(AuthStatus status) {
        return new AuthResult(status, null);
    }

    public boolean isSuccess() {
        return status == AuthStatus.SUCCESS && user != null;
    }
}
