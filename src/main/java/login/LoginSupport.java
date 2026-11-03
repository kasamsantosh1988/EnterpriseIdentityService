package com.example.authserver.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.web.savedrequest.SavedRequest;

final class LoginSupport {

    // Same value as HttpSessionRequestCache's session attribute (the constant itself is package-private).
    private static final String SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";

    private LoginSupport() {
    }

    /**
     * The login form does not know which application the user came from. The original /oauth2/authorize
     * request was saved in the session before the redirect to /login, so the client_id is read from there.
     */
    static String clientIdFrom(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object saved = session.getAttribute(SAVED_REQUEST);
        if (saved instanceof SavedRequest savedRequest) {
            String[] values = savedRequest.getParameterValues("client_id");
            if (values != null && values.length == 1 && !values[0].isBlank()) {
                return values[0];
            }
        }
        return null;
    }
}
