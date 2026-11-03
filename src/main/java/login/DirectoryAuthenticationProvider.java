package com.example.authserver.login;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

/**
 * Authenticates a login-form user against the directory of the application the login belongs to.
 * The actual checks live in {@link DirectoryLoginService}, which the app_login grant shares.
 */
@Component
public class DirectoryAuthenticationProvider implements AuthenticationProvider {

    private final DirectoryLoginService loginService;

    public DirectoryAuthenticationProvider(DirectoryLoginService loginService) {
        this.loginService = loginService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LoginDetails details = authentication.getDetails() instanceof LoginDetails d ? d : null;
        String clientId = details == null ? null : details.clientId();
        String ip = details == null ? null : details.ipAddress();

        if (!(authentication.getCredentials() instanceof String password)) {
            throw new BadCredentialsException("Bad credentials");
        }
        return this.loginService.authenticate(clientId, authentication.getName(), password, ip, "form");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
