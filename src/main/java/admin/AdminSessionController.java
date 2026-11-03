package com.example.authserver.admin;

import java.util.Map;

import com.example.authserver.session.SessionRevocationService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Admin call for an application backend: sign a user out of every session at once (password changed, account
 * disabled, ...). The caller is authenticated by a client_credentials token with scope "auth.revoke" and can only
 * act on its own users.
 */
@RestController
public class AdminSessionController {

    public record RevokeRequest(String userId, String clientId) {
    }

    private final SessionRevocationService revocation;

    public AdminSessionController(SessionRevocationService revocation) {
        this.revocation = revocation;
    }

    @PostMapping("/admin/sessions/revoke")
    ResponseEntity<Map<String, Object>> revokeAll(@RequestBody RevokeRequest request, Authentication caller) {
        if (request == null || !StringUtils.hasText(request.userId())) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_request", "error_description",
                    "userId is required"));
        }
        String callerClient = caller.getName();
        if (StringUtils.hasText(request.clientId()) && !request.clientId().equals(callerClient)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "access_denied", "error_description",
                        "A client can only revoke sessions of its own users"));
        }
        int revoked = this.revocation.revokeAllFor(callerClient, request.userId(), "admin revoke-all");
        return ResponseEntity.ok(Map.of("revoked", revoked));
    }
}
