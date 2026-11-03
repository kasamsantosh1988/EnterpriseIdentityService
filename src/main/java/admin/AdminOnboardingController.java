package com.example.authserver.admin;

import java.util.List;
import java.util.Map;

import com.example.authserver.introspection.ResourceServerRepository;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Platform administration: register applications and APIs. Requires a client_credentials token with scope
 * "auth.admin" (see the /admin security chain). Responses that contain a new secret are the only time it is shown.
 */
@RestController
public class AdminOnboardingController {

    public record ResourceServerRequest(String id, String audience, String name) {
    }

    private final OnboardingService onboarding;

    public AdminOnboardingController(OnboardingService onboarding) {
        this.onboarding = onboarding;
    }

    @PostMapping("/admin/apps")
    ResponseEntity<OnboardingService.Created> registerApp(@RequestBody OnboardingService.AppSpec spec,
            Authentication admin) {
        return created(this.onboarding.registerApp(spec, admin.getName()));
    }

    @PostMapping("/admin/apps/{clientId}/rotate-secret")
    OnboardingService.Created rotate(@PathVariable String clientId, Authentication admin) {
        return this.onboarding.rotateSecret(clientId, admin.getName());
    }

    @PostMapping("/admin/apps/{clientId}/directory/enable")
    Map<String, Object> enableDirectory(@PathVariable String clientId, Authentication admin) {
        this.onboarding.setDirectoryEnabled(clientId, true, admin.getName());
        return Map.of("clientId", clientId, "directoryEnabled", true);
    }

    @PostMapping("/admin/apps/{clientId}/directory/disable")
    Map<String, Object> disableDirectory(@PathVariable String clientId, Authentication admin) {
        this.onboarding.setDirectoryEnabled(clientId, false, admin.getName());
        return Map.of("clientId", clientId, "directoryEnabled", false);
    }

    @GetMapping("/admin/apps/{clientId}/handoff-links")
    OnboardingService.HandoffLinks handoffLinks(@PathVariable String clientId) {
        return this.onboarding.handoffLinks(clientId);
    }

    /** Body: { "handoffTargets": [...], "acceptsHandoffFrom": [...] }. A missing field is left unchanged; [] clears it. */
    @PostMapping("/admin/apps/{clientId}/handoff-links")
    OnboardingService.HandoffLinks setHandoffLinks(@PathVariable String clientId,
            @RequestBody OnboardingService.HandoffLinks body, Authentication admin) {
        return this.onboarding.setHandoffLinks(clientId, body.handoffTargets(), body.acceptsHandoffFrom(),
                admin.getName());
    }

    @PostMapping("/admin/resource-servers")
    ResponseEntity<OnboardingService.Created> registerResourceServer(@RequestBody ResourceServerRequest request,
            Authentication admin) {
        return created(this.onboarding.registerResourceServer(request.id(), request.audience(), request.name(),
                admin.getName()));
    }

    @GetMapping("/admin/resource-servers")
    List<ResourceServerRepository.ResourceServer> listResourceServers() {
        return this.onboarding.listResourceServers();
    }

    @PostMapping("/admin/resource-servers/{id}/enable")
    Map<String, Object> enableResourceServer(@PathVariable String id, Authentication admin) {
        this.onboarding.setResourceServerEnabled(id, true, admin.getName());
        return Map.of("id", id, "enabled", true);
    }

    @PostMapping("/admin/resource-servers/{id}/disable")
    Map<String, Object> disableResourceServer(@PathVariable String id, Authentication admin) {
        this.onboarding.setResourceServerEnabled(id, false, admin.getName());
        return Map.of("id", id, "enabled", false);
    }

    private static ResponseEntity<OnboardingService.Created> created(OnboardingService.Created body) {
        return ResponseEntity.status(HttpStatus.CREATED).header("Cache-Control", "no-store").body(body);
    }
}
