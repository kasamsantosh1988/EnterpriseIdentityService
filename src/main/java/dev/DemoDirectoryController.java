package com.example.authserver.dev;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * DEV ONLY. A stand-in for an application's own verify service so the REMOTE directory flow can be tried
 * without a real application. It shows the contract in docs/directory-contracts.md.
 *
 * Users: alice / alice-pass (USER), bob / bob-pass (ADMIN, USER), carol / carol-pass (account locked).
 */
@RestController
@Profile("dev")
@RequestMapping("/dev/demo-directory")
class DemoDirectoryController {

    private record DemoUser(String id, String password, String name, List<String> roles, String status) {
    }

    private static final Map<String, DemoUser> USERS = Map.of(
            "alice", new DemoUser("1001", "alice-pass", "Alice Example", List.of("USER"), "SUCCESS"),
            "bob", new DemoUser("1002", "bob-pass", "Bob Example", List.of("ADMIN", "USER"), "SUCCESS"),
            "carol", new DemoUser("1003", "carol-pass", "Carol Example", List.of("USER"), "LOCKED"));

    private final String expectedKey;

    DemoDirectoryController(@Value("${authserver.secrets.demo-dir}") String expectedKey) {
        this.expectedKey = expectedKey;
    }

    @PostMapping("/verify")
    ResponseEntity<Map<String, Object>> verify(@RequestHeader(name = "X-Auth-Server-Key", required = false) String key,
            @RequestBody Map<String, Object> body) {
        if (!keyOk(key)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        DemoUser user = USERS.get(String.valueOf(body.get("username")));
        if (user == null || !user.password().equals(String.valueOf(body.get("password")))) {
            return ResponseEntity.ok(Map.of("status", "INVALID_CREDENTIALS"));
        }
        return ResponseEntity.ok(describe(user));
    }

    @PostMapping("/status")
    ResponseEntity<Map<String, Object>> status(@RequestHeader(name = "X-Auth-Server-Key", required = false) String key,
            @RequestBody Map<String, Object> body) {
        if (!keyOk(key)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String userId = String.valueOf(body.get("userId"));
        return USERS.values().stream()
            .filter((user) -> user.id().equals(userId))
            .findFirst()
            .map((user) -> ResponseEntity.ok(describe(user)))
            .orElseGet(() -> ResponseEntity.notFound().build());
    }

    private static Map<String, Object> describe(DemoUser user) {
        return Map.of("status", user.status(), "userId", user.id(), "displayName", user.name(),
                "roles", user.roles(), "active", "SUCCESS".equals(user.status()));
    }

    private boolean keyOk(String key) {
        return key != null && MessageDigest.isEqual(key.getBytes(StandardCharsets.UTF_8),
                this.expectedKey.getBytes(StandardCharsets.UTF_8));
    }
}
