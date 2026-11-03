package com.example.authserver.grant;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Reads an app_login request from the token endpoint. Strict on purpose: the request carries a password, so it must be
 * a POST body (never the URL), every parameter must appear once, and unknown parameters are refused.
 */
/**
 * Deliberately NOT a Spring bean: Spring Security 7 picks up any AuthenticationConverter bean for its bearer-token filter,
 * which would then run the app_login exchange before the token endpoint and end in a 403. It is created in
 * AuthorizationServerConfig and given only to the token endpoint.
 */
public class AppLoginAuthenticationConverter implements AuthenticationConverter {

    private static final Set<String> ALLOWED = Set.of(OAuth2ParameterNames.GRANT_TYPE, "username", "password",
            OAuth2ParameterNames.SCOPE, OAuth2ParameterNames.CLIENT_ID, OAuth2ParameterNames.CLIENT_SECRET);

    private static final int MAX_SCOPES = 20;

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!AppLoginGrant.TYPE.getValue().equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
            return null;                                    // some other grant: let the other converters try
        }
        if (request.getQueryString() != null) {
            throw invalid("Send the parameters in the request body, not the URL");
        }
        Map<String, String[]> parameters = request.getParameterMap();
        for (String name : parameters.keySet()) {
            if (!ALLOWED.contains(name)) {
                throw invalid("Unsupported parameter: " + sanitize(name));
            }
        }

        String username = single(parameters, "username", true);
        String password = single(parameters, "password", true);
        String scope = single(parameters, OAuth2ParameterNames.SCOPE, false);

        Set<String> scopes = new LinkedHashSet<>();
        if (StringUtils.hasText(scope)) {
            for (String part : scope.trim().split("\\s+")) {
                scopes.add(part);
            }
            if (scopes.size() > MAX_SCOPES) {
                throw invalid("Too many scopes");
            }
        }

        // The client has been authenticated (client_secret_basic) by the filter that runs before the token endpoint.
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        if (clientPrincipal == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        return new AppLoginAuthenticationToken(clientPrincipal, username, password, scopes);
    }

    private static String single(Map<String, String[]> parameters, String name, boolean required) {
        String[] values = parameters.get(name);
        if (values == null || values.length == 0) {
            if (required) {
                throw invalid("Missing parameter: " + name);
            }
            return null;
        }
        if (values.length > 1) {
            throw invalid("Parameter must appear once: " + name);
        }
        if (required && !StringUtils.hasText(values[0])) {
            throw invalid("Missing parameter: " + name);
        }
        return values[0];
    }

    private static OAuth2AuthenticationException invalid(String description) {
        return new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, description, null));
    }

    /** Parameter names come from the caller: keep only harmless characters before echoing one back. */
    private static String sanitize(String value) {
        String clean = value.replaceAll("[^A-Za-z0-9_.-]", "?");
        return clean.length() > 40 ? clean.substring(0, 40) : clean;
    }
}
