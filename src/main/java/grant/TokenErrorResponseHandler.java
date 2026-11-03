package com.example.authserver.grant;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import com.example.authserver.ratelimit.TooManyAttemptsException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

/**
 * Error responses of the token endpoint. Same JSON body as the framework's, but with the status codes callers need to
 * react correctly: 429 when throttled, 503 when a user directory is unavailable (retry later), 500 for server errors.
 */
@Component
public class TokenErrorResponseHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException {
        OAuth2Error error = exception instanceof OAuth2AuthenticationException oauth2 ? oauth2.getError()
                : new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR);
        String code = error.getErrorCode();

        int status;
        switch (code) {
            case OAuth2ErrorCodes.INVALID_CLIENT -> status = HttpServletResponse.SC_UNAUTHORIZED;
            case OAuth2ErrorCodes.SERVER_ERROR -> status = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
            case OAuth2ErrorCodes.TEMPORARILY_UNAVAILABLE -> status = HttpServletResponse.SC_SERVICE_UNAVAILABLE;
            case AppLoginGrant.ERROR_TOO_MANY_ATTEMPTS -> status = 429;
            default -> status = HttpServletResponse.SC_BAD_REQUEST;
        }

        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        if (status == HttpServletResponse.SC_UNAUTHORIZED) {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"auth-server\"");
        }
        if (exception.getCause() instanceof TooManyAttemptsException tooMany) {
            response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(tooMany.getRetryAfterSeconds()));
        }
        else if (status == HttpServletResponse.SC_SERVICE_UNAVAILABLE) {
            response.setHeader(HttpHeaders.RETRY_AFTER, "5");
        }

        StringBuilder body = new StringBuilder("{\"error\":\"").append(escape(code)).append('"');
        if (error.getDescription() != null) {
            body.append(",\"error_description\":\"").append(escape(error.getDescription())).append('"');
        }
        body.append('}');
        response.getWriter().write(body.toString());
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }
}
