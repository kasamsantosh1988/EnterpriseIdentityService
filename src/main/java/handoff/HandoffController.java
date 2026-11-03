package com.example.authserver.handoff;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import com.example.authserver.audit.AuditService;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * POST /oauth2/handoff: the source application's BACKEND asks for a one-time hand-off code for one of its signed-in users.
 *
 * Authentication: the caller's client id and secret (HTTP Basic). The user is identified by the user's access token in the
 * body ("subjectToken"), so the user's token never travels in the URL or the Authorization header. Secrets are 256-bit
 * random values, so there is no guessing to rate limit here; failures are audited.
 *
 * Request:  { "targetClientId": "app2", "subjectToken": "<user's access token>", "context": "<opaque text, optional>" }
 * Response: { "code": "...", "expires_in": 60 }   (Cache-Control: no-store)
 */
@RestController
public class HandoffController {

    public record IssueRequest(String targetClientId, String subjectToken, String context) {
    }

    private final HandoffService service;

    private final RegisteredClientRepository clients;

    private final PasswordEncoder passwordEncoder;

    private final AuditService audit;

    public HandoffController(HandoffService service, RegisteredClientRepository clients,
            PasswordEncoder passwordEncoder, AuditService audit) {
        this.service = service;
        this.clients = clients;
        this.passwordEncoder = passwordEncoder;
        this.audit = audit;
    }

    @PostMapping("/oauth2/handoff")
    ResponseEntity<Map<String, Object>> issue(@RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestBody(required = false) IssueRequest request, HttpServletRequest http) {
        RegisteredClient caller = authenticate(authorization);
        if (caller == null) {
            this.audit.record("HANDOFF_DENIED", null, null, "FAILURE", http.getRemoteAddr(),
                    "client authentication failed");
            return body(HttpStatus.UNAUTHORIZED, Map.of("error", "invalid_client", "error_description",
                    "Client authentication failed"));
        }
        if (request == null) {
            return body(HttpStatus.BAD_REQUEST, Map.of("error", "invalid_request", "error_description",
                    "A JSON body is required"));
        }
        HandoffService.Issued issued = this.service.issue(caller, request.subjectToken(), request.targetClientId(),
                request.context(), http.getRemoteAddr());
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("code", issued.code());
        response.put("expires_in", issued.expiresIn());
        return body(HttpStatus.OK, response);
    }

    @ExceptionHandler(HandoffService.HandoffException.class)
    ResponseEntity<Map<String, Object>> refused(HandoffService.HandoffException ex) {
        return body(ex.status(), Map.of("error", ex.error(), "error_description", ex.getMessage()));
    }

    /** client_secret_basic: the id and secret are form-encoded, then Base64 (RFC 6749 section 2.3.1). */
    private RegisteredClient authenticate(String header) {
        if (header == null || header.length() < 7 || !header.regionMatches(true, 0, "Basic ", 0, 6)) {
            return null;
        }
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(header.substring(6).trim()), StandardCharsets.UTF_8);
        }
        catch (IllegalArgumentException ex) {
            return null;
        }
        int colon = decoded.indexOf(':');
        if (colon <= 0) {
            return null;
        }
        String clientId = URLDecoder.decode(decoded.substring(0, colon), StandardCharsets.UTF_8);
        String secret = URLDecoder.decode(decoded.substring(colon + 1), StandardCharsets.UTF_8);
        RegisteredClient client = this.clients.findByClientId(clientId);
        if (client == null || client.getClientSecret() == null
                || !this.passwordEncoder.matches(secret, client.getClientSecret())) {
            return null;
        }
        return client;
    }

    private static ResponseEntity<Map<String, Object>> body(HttpStatus status, Map<String, Object> body) {
        return ResponseEntity.status(status).header("Cache-Control", "no-store").header("Pragma", "no-cache").body(body);
    }
}
