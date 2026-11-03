package com.example.authserver.login;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

/** Tells the authentication provider which application's directory this login belongs to. */
@Component
public class LoginDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, LoginDetails> {

    @Override
    public LoginDetails buildDetails(HttpServletRequest request) {
        return new LoginDetails(LoginSupport.clientIdFrom(request), request.getRemoteAddr());
    }
}
