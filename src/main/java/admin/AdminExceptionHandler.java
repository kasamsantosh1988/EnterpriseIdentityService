package com.example.authserver.admin;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Turns onboarding validation problems into plain 400/409 JSON answers. */
@RestControllerAdvice(basePackageClasses = AdminExceptionHandler.class)
class AdminExceptionHandler {

    @ExceptionHandler(OnboardingService.InvalidSpecException.class)
    ResponseEntity<Map<String, String>> invalid(OnboardingService.InvalidSpecException ex) {
        return ResponseEntity.badRequest().body(Map.of("error", "invalid_request", "error_description", ex.getMessage()));
    }

    @ExceptionHandler(OnboardingService.ConflictException.class)
    ResponseEntity<Map<String, String>> conflict(OnboardingService.ConflictException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
            .body(Map.of("error", "conflict", "error_description", ex.getMessage()));
    }
}
