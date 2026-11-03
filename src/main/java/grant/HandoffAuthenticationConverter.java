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
 * Reads a handoff request from the token endpoint: grant_type=handoff, code, and optionally scope. Strict like the
 * app_login converter: POST body only, every parameter once, unknown parameters refused.
 *
 * Like AppLoginAuthenticationConverter this is deliberately NOT a Spring bean (the bearer-token filter would pick it up);
 * it is created in AuthorizationServerConfig and given only to the token endpoint.
 */
public class HandoffAuthenticationConverter implements AuthenticationConverter {

    private static final Set<String> ALLOWED = Set.of(OAuth2ParameterNames.GRANT_TYPE, OAuth2ParameterNames.CODE,
            OAuth2ParameterNames.SCOPE, OAuth2ParameterNames.CLIENT_ID, OAuth2ParameterNames.CLIENT_SECRET);

    private static final int MAX_SCOPES = 20;

    private static final int MAX_CODE_LENGTH = 200;

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!HandoffGrant.TYPE.getValue().equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
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
        String code = single(parameters, OAuth2ParameterNames.CODE, true);
        if (code.length() > MAX_CODE_LENGTH) {
            throw invalid("Invalid code");
        }
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
        // The client has been authenticated by the filter that runs before the token endpoint.
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        if (clientPrincipal == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        return new HandoffAuthenticationToken(clientPrincipal, code, scopes);
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

    private static String sanitize(String value) {
        String clean = value.replaceAll("[^A-Za-z0-9_.-]", "?");
        return clean.length() > 40 ? clean.substring(0, 40) : clean;
    }
}
