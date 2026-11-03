package com.example.authserver.login;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
class LoginController {

    private final RegisteredClientRepository clients;

    LoginController(RegisteredClientRepository clients) {
        this.clients = clients;
    }

    @GetMapping("/login")
    String login(HttpServletRequest request, @RequestParam(name = "error", required = false) String error,
            Model model) {
        String appName = null;
        String clientId = LoginSupport.clientIdFrom(request);
        if (clientId != null) {
            RegisteredClient client = this.clients.findByClientId(clientId);
            if (client != null) {
                appName = client.getClientName();
            }
        }
        model.addAttribute("appName", appName);
        model.addAttribute("message", messageFor(error));
        return "login";
    }

    // Fixed messages chosen by code, so nothing from the request is ever echoed into the page.
    private static String messageFor(String code) {
        if (code == null) {
            return null;
        }
        return switch (code) {
            case "throttled" -> "Too many failed attempts. Please wait a few minutes and try again.";
            case "locked" -> "This account is locked. Please contact your administrator.";
            case "disabled" -> "This account is not active. Please contact your administrator.";
            case "expired" -> "Your password has expired. Change it in the application, then sign in again.";
            case "unavailable" -> "Sign-in is temporarily unavailable. Please try again shortly.";
            default -> "Invalid username or password.";
        };
    }
}
