package com.example.authserver.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.oracle.OracleContainer;

/**
 * End-to-end flows against a real Oracle (Docker required) and the built-in demo directory of the dev profile.
 * Run with:  mvn -Dtest=FlowsIT test
 */
@Testcontainers
@ActiveProfiles("dev")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = { "authserver.session.reuse-grace=0s", "authserver.bootstrap.enabled=true" })
class FlowsIT {

    @Container
    @ServiceConnection
    static final OracleContainer ORACLE = new OracleContainer("gvenzl/oracle-free:slim-faststart");

    @Value("${local.server.port}")
    int port;

    private final HttpClient http = HttpClient.newHttpClient();

    // ---- tests -------------------------------------------------------------------------------------------------

    @Test
    void clientCredentialsTokenIsOnlyVisibleToItsOwnApi() throws Exception {
        Reply token = post("/oauth2/token", "demo-service", "demo-service-secret",
                Map.of("grant_type", "client_credentials", "scope", "demo.read"));
        assertThat(token.status()).isEqualTo(200);
        String access = field(token.body(), "access_token");

        assertThat(introspect("demo-api", "demo-api-secret", access).body()).contains("\"active\":true");
        // demo-service is not a registered resource server, so it learns nothing about the token
        assertThat(introspect("demo-service", "demo-service-secret", access).body()).contains("\"active\":false");
    }

    @Test
    void appLoginRefreshReuseAndLogout() throws Exception {
        Reply login = appLogin("alice", "alice-pass");
        assertThat(login.status()).isEqualTo(200);
        String access = field(login.body(), "access_token");
        String refresh = field(login.body(), "refresh_token");

        String info = introspect("demo-api", "demo-api-secret", access).body();
        assertThat(info).contains("\"active\":true").contains("demo-ui:1001").contains("\"roles\"");

        Reply refreshed = post("/oauth2/token", "demo-ui", "demo-ui-secret",
                Map.of("grant_type", "refresh_token", "refresh_token", refresh));
        assertThat(refreshed.status()).isEqualTo(200);
        String newRefresh = field(refreshed.body(), "refresh_token");
        assertThat(newRefresh).isNotEqualTo(refresh);

        // the old refresh token is no longer valid, and with grace=0 its reuse kills the whole session
        Reply reuse = post("/oauth2/token", "demo-ui", "demo-ui-secret",
                Map.of("grant_type", "refresh_token", "refresh_token", refresh));
        assertThat(reuse.status()).isEqualTo(400);
        Reply afterReuse = post("/oauth2/token", "demo-ui", "demo-ui-secret",
                Map.of("grant_type", "refresh_token", "refresh_token", newRefresh));
        assertThat(afterReuse.status()).isEqualTo(400);
    }

    @Test
    void logoutRevokesTheAccessToken() throws Exception {
        Reply login = appLogin("alice", "alice-pass");
        String access = field(login.body(), "access_token");
        String refresh = field(login.body(), "refresh_token");

        Reply revoke = post("/oauth2/revoke", "demo-ui", "demo-ui-secret",
                Map.of("token", refresh, "token_type_hint", "refresh_token"));
        assertThat(revoke.status()).isEqualTo(200);
        assertThat(introspect("demo-api", "demo-api-secret", access).body()).contains("\"active\":false");
    }

    @Test
    void wrongPasswordAndLockedAccountAreRefused() throws Exception {
        Reply wrong = appLogin("alice", "nope");
        assertThat(wrong.status()).isEqualTo(400);
        assertThat(wrong.body()).contains("invalid_grant");
        Reply locked = appLogin("carol", "carol-pass");
        assertThat(locked.status()).isEqualTo(400);
    }

    @Test
    void adminRevokeAllEndsEverySessionOfTheUser() throws Exception {
        Reply login = appLogin("bob", "bob-pass");
        String refresh = field(login.body(), "refresh_token");

        Reply adminToken = post("/oauth2/token", "demo-ui", "demo-ui-secret",
                Map.of("grant_type", "client_credentials", "scope", "auth.revoke"));
        assertThat(adminToken.status()).isEqualTo(200);
        Reply revoked = postJson("/admin/sessions/revoke", field(adminToken.body(), "access_token"),
                "{\"userId\":\"1002\"}");
        assertThat(revoked.status()).isEqualTo(200);

        Reply refreshAfter = post("/oauth2/token", "demo-ui", "demo-ui-secret",
                Map.of("grant_type", "refresh_token", "refresh_token", refresh));
        assertThat(refreshAfter.status()).isEqualTo(400);
    }

    @Test
    void onboardingRegistersAnApiThatCanIntrospect() throws Exception {
        Reply adminToken = post("/oauth2/token", "platform-admin", "platform-admin-secret",
                Map.of("grant_type", "client_credentials", "scope", "auth.admin"));
        assertThat(adminToken.status()).isEqualTo(200);
        String bearer = field(adminToken.body(), "access_token");

        Reply created = postJson("/admin/resource-servers", bearer,
                "{\"id\":\"orders-api\",\"audience\":\"orders-api\",\"name\":\"Orders API\"}");
        assertThat(created.status()).isEqualTo(201);
        assertThat(field(created.body(), "clientSecret")).isNotBlank();

        // a user (non-admin) token cannot call the admin API
        Reply userToken = appLogin("alice", "alice-pass");
        Reply denied = postJson("/admin/resource-servers", field(userToken.body(), "access_token"), "{}");
        assertThat(denied.status()).isIn(401, 403);
    }

    // ---- helpers -----------------------------------------------------------------------------------------------

    private record Reply(int status, String body) {
    }

    private Reply appLogin(String user, String password) throws Exception {
        return post("/oauth2/token", "demo-ui", "demo-ui-secret",
                Map.of("grant_type", "app_login", "username", user, "password", password, "scope", "app"));
    }

    private Reply introspect(String client, String secret, String token) throws Exception {
        return post("/oauth2/introspect", client, secret, Map.of("token", token));
    }

    private Reply post(String path, String client, String secret, Map<String, String> form) throws Exception {
        String body = form.entrySet()
            .stream()
            .map((e) -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                    + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + this.port + path))
            .header("Authorization", "Basic " + Base64.getEncoder().encodeToString((client + ":" + secret).getBytes(StandardCharsets.UTF_8)))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        HttpResponse<String> response = this.http.send(request, HttpResponse.BodyHandlers.ofString());
        return new Reply(response.statusCode(), response.body());
    }

    private Reply postJson(String path, String bearer, String json) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + this.port + path))
            .header("Authorization", "Bearer " + bearer)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();
        HttpResponse<String> response = this.http.send(request, HttpResponse.BodyHandlers.ofString());
        return new Reply(response.statusCode(), response.body());
    }

    private static String field(String json, String name) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        assertThat(matcher.find()).as("field %s in %s", name, json).isTrue();
        return matcher.group(1);
    }
}
