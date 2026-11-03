package com.example.authserver.directory;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.example.authserver.config.AuthServerProperties;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Validates users by calling the application's own verify service (see docs/directory-contracts.md).
 * The application keeps owning its users, hashing and lockout rules; this class only asks it.
 *
 * Contract: the service answers HTTP 200 with a JSON "status" for every outcome, including bad credentials.
 * Any other HTTP status, a timeout or an unreadable body means "directory unavailable" - never "wrong password".
 */
public class RemoteVerifyProvider implements UserDirectoryProvider {

    private static final ParameterizedTypeReference<Map<String, Object>> JSON_MAP = new ParameterizedTypeReference<>() {
    };

    private final RestClient client;

    private final String verifyUrl;

    private final String statusUrl;

    private final String sharedKey;

    public RemoteVerifyProvider(DirectoryConfig config, String sharedKey, AuthServerProperties.Directory settings) {
        this.verifyUrl = requireSecureUrl(config.verifyUrl(), "verify_url");
        this.statusUrl = config.statusUrl() == null || config.statusUrl().isBlank() ? null
                : requireSecureUrl(config.statusUrl(), "status_url");
        this.sharedKey = sharedKey;

        HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(settings.connectTimeout())
            .followRedirects(HttpClient.Redirect.NEVER)     // never forward credentials to a redirect target
            .build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(settings.readTimeout());
        this.client = RestClient.builder().requestFactory(requestFactory).build();
    }

    @Override
    public AuthResult authenticate(String username, char[] password, AuthContext context) {
        Map<String, Object> request = Map.of(
                "username", username,
                "password", new String(password),
                "clientId", context.clientId() == null ? "" : context.clientId(),
                "ipAddress", context.ipAddress() == null ? "" : context.ipAddress());

        Map<String, Object> body = post(this.verifyUrl, request);
        AuthStatus status = AuthStatus.parse(asString(body.get("status")));
        if (status != AuthStatus.SUCCESS) {
            return AuthResult.failure(status);
        }
        String userId = asString(body.get("userId"));
        if (userId == null || userId.isBlank() || Boolean.FALSE.equals(body.get("active"))) {
            return AuthResult.failure(AuthStatus.ERROR);   // SUCCESS without a usable user is a broken contract: fail closed
        }
        return AuthResult.success(new UserInfo(userId, asString(body.get("displayName")), roles(body.get("roles")), true));
    }

    @Override
    public Optional<UserInfo> loadById(String userId) {
        if (this.statusUrl == null) {
            throw new IllegalStateException("status_url is not configured for this client");
        }
        Map<String, Object> body;
        try {
            body = post(this.statusUrl, Map.of("userId", userId));
        }
        catch (DirectoryUnavailableException ex) {
            if (ex.getCause() instanceof HttpClientErrorException.NotFound) {
                return Optional.empty();
            }
            throw ex;
        }
        String id = asString(body.get("userId"));
        if (id == null || id.isBlank()) {
            return Optional.empty();
        }
        boolean active = AuthStatus.parse(asString(body.get("status"))) == AuthStatus.SUCCESS
                && !Boolean.FALSE.equals(body.get("active"));
        return Optional.of(new UserInfo(id, asString(body.get("displayName")), roles(body.get("roles")), active));
    }

    private Map<String, Object> post(String url, Map<String, Object> payload) {
        try {
            Map<String, Object> body = this.client.post()
                .uri(url)
                .contentType(MediaType.APPLICATION_JSON)
                .headers((headers) -> {
                    if (this.sharedKey != null) {
                        headers.set("X-Auth-Server-Key", this.sharedKey);
                    }
                })
                .body(payload)
                .retrieve()
                .body(JSON_MAP);
            if (body == null) {
                throw new DirectoryUnavailableException("Empty response from directory service", null);
            }
            return body;
        }
        catch (RestClientException ex) {
            // Do not include the request (it holds the password) in the message or the log.
            throw new DirectoryUnavailableException("Directory service call failed: " + ex.getClass().getSimpleName(), ex);
        }
    }

    private static String requireSecureUrl(String url, String field) {
        if (url == null || url.isBlank()) {
            throw new IllegalStateException(field + " is required for REMOTE directories");
        }
        URI uri = URI.create(url);
        String host = uri.getHost();
        boolean local = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host);
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !local) {
            throw new IllegalStateException(field + " must use https (plain http is only allowed for localhost)");
        }
        return url;
    }

    private static String asString(Object value) {
        return value == null ? null : value.toString();
    }

    private static Set<String> roles(Object value) {
        Set<String> roles = new LinkedHashSet<>();
        if (value instanceof List<?> list) {
            list.forEach((item) -> addRole(roles, item));
        }
        else if (value instanceof String text) {
            for (String part : text.split(",")) {
                addRole(roles, part);
            }
        }
        return roles;
    }

    private static void addRole(Set<String> roles, Object item) {
        if (item != null && !item.toString().isBlank()) {
            roles.add(item.toString().trim());
        }
    }
}
