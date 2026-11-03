package com.example.authserver.login;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.example.authserver.ratelimit.TooManyAttemptsException;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

/** Sends the user back to the login page with a short reason code. The saved authorize request stays in the session. */
@Component
public class LoginFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException {
        String code;
        if (exception instanceof TooManyAttemptsException) {
            code = "throttled";
        }
        else if (exception instanceof LockedException) {
            code = "locked";
        }
        else if (exception instanceof DisabledException) {
            code = "disabled";
        }
        else if (exception instanceof CredentialsExpiredException) {
            code = "expired";
        }
        else if (exception instanceof AuthenticationServiceException) {
            code = "unavailable";
        }
        else {
            code = "invalid";
        }
        response.sendRedirect(request.getContextPath() + "/login?error=" + code);
    }
}
