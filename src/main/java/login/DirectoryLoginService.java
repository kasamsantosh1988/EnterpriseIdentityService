package com.example.authserver.login;

import java.util.Arrays;
import java.util.List;

import com.example.authserver.audit.AuditService;
import com.example.authserver.directory.AuthContext;
import com.example.authserver.directory.AuthResult;
import com.example.authserver.directory.AuthStatus;
import com.example.authserver.directory.DirectoryProviderRegistry;
import com.example.authserver.directory.DirectoryUnavailableException;
import com.example.authserver.directory.UserDirectoryProvider;
import com.example.authserver.directory.UserInfo;
import com.example.authserver.ratelimit.AttemptLimiter;
import com.example.authserver.ratelimit.TooManyAttemptsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

/**
 * The single place where a username and password are checked against an application's directory.
 * Used by the central login form and by the app_login grant, so limits, auditing and status handling are identical.
 *
 * The resulting principal's name is "<clientId>:<userId>". The prefix keeps users of different applications apart
 * (two applications can both have a user "1001").
 */
@Service
public class DirectoryLoginService {

    private static final Logger log = LoggerFactory.getLogger(DirectoryLoginService.class);

    static final int MAX_USERNAME_LENGTH = 200;

    static final int MAX_PASSWORD_LENGTH = 256;

    private final DirectoryProviderRegistry registry;

    private final AuditService audit;

    private final AttemptLimiter limiter;

    public DirectoryLoginService(DirectoryProviderRegistry registry, AuditService audit, AttemptLimiter limiter) {
        this.registry = registry;
        this.audit = audit;
        this.limiter = limiter;
    }

    /**
     * @param channel "form" or "app_login", recorded in the audit trail
     * @throws TooManyAttemptsException a limit was reached
     * @throws BadCredentialsException wrong credentials or unknown user/application
     * @throws LockedException, DisabledException, CredentialsExpiredException the password was correct but the account cannot sign in
     * @throws AuthenticationServiceException the directory could not answer
     */
    public UsernamePasswordAuthenticationToken authenticate(String clientId, String username, String password,
            String ip, String channel) throws AuthenticationException {

        if (clientId == null || clientId.isBlank() || clientId.contains(":")) {
            this.audit.record("LOGIN_FAILED", clientId, username, "FAILURE", ip, channel + ": no application context");
            throw new BadCredentialsException("Bad credentials");
        }
        if (username == null || username.isBlank() || username.length() > MAX_USERNAME_LENGTH || password == null
                || password.isEmpty() || password.length() > MAX_PASSWORD_LENGTH) {
            this.audit.record("LOGIN_FAILED", clientId, username, "FAILURE", ip, channel + ": invalid input");
            throw new BadCredentialsException("Bad credentials");
        }

        try {
            this.limiter.check(clientId, username, ip);
        }
        catch (TooManyAttemptsException ex) {
            this.audit.record("LOGIN_FAILED", clientId, username, "FAILURE", ip, channel + ": throttled");
            throw ex;
        }

        UserDirectoryProvider provider;
        try {
            provider = this.registry.find(clientId).orElse(null);
        }
        catch (RuntimeException ex) {
            log.error("Directory for client '{}' could not be loaded", clientId, ex);
            this.audit.record("LOGIN_FAILED", clientId, username, "ERROR", ip, channel + ": directory could not be loaded");
            throw new AuthenticationServiceException("Directory unavailable", ex);
        }
        if (provider == null) {
            this.audit.record("LOGIN_FAILED", clientId, username, "FAILURE", ip, channel + ": no directory configured");
            throw new BadCredentialsException("Bad credentials");
        }

        char[] passwordChars = password.toCharArray();
        AuthResult result;
        try {
            result = provider.authenticate(username, passwordChars, new AuthContext(clientId, ip));
        }
        catch (DirectoryUnavailableException ex) {
            log.error("Directory for client '{}' unavailable: {}", clientId, ex.getMessage());
            this.audit.record("LOGIN_FAILED", clientId, username, "ERROR", ip, channel + ": directory unavailable");
            throw new AuthenticationServiceException("Directory unavailable", ex);
        }
        finally {
            Arrays.fill(passwordChars, '\0');
        }

        AuthStatus status = result.status();
        if (status == AuthStatus.INVALID_CREDENTIALS) {
            this.limiter.recordFailure(clientId, username, ip);
            this.audit.record("LOGIN_FAILED", clientId, username, "FAILURE", ip, channel + ": invalid credentials");
            throw new BadCredentialsException("Bad credentials");
        }
        if (status == AuthStatus.LOCKED) {
            this.audit.record("LOGIN_FAILED", clientId, username, "FAILURE", ip, channel + ": account locked");
            throw new LockedException("Account locked");
        }
        if (status == AuthStatus.DISABLED) {
            this.audit.record("LOGIN_FAILED", clientId, username, "FAILURE", ip, channel + ": account disabled");
            throw new DisabledException("Account disabled");
        }
        if (status == AuthStatus.EXPIRED || status == AuthStatus.MUST_CHANGE_PASSWORD) {
            this.audit.record("LOGIN_FAILED", clientId, username, "FAILURE", ip, channel + ": password " + status);
            throw new CredentialsExpiredException("Password expired");
        }
        if (status != AuthStatus.SUCCESS || !result.isSuccess()) {
            this.audit.record("LOGIN_FAILED", clientId, username, "ERROR", ip, channel + ": directory error");
            throw new AuthenticationServiceException("Directory error");
        }

        this.limiter.recordSuccess(clientId, username);
        UserInfo user = result.user();
        String subject = clientId + ":" + user.userId();
        List<GrantedAuthority> authorities = user.roles().stream()
            .<GrantedAuthority>map(SimpleGrantedAuthority::new)
            .toList();

        // Only standard Spring Security types go into the token: they are stored with the authorization and must
        // be readable again on refresh. Do not attach custom classes here.
        User principal = new User(subject, "", authorities);
        this.audit.record("LOGIN", clientId, subject, "SUCCESS", ip, channel);

        // Spring Security 7 records HOW and WHEN a user signed in as a "factor" authority. The authorization server
        // reads the time from it to fill "auth_time" in the ID token (without it: "authenticationTime cannot be null").
        // The factor authority is only on the authentication, not on the user, and the roles claim leaves it out.
        List<GrantedAuthority> withFactor = new java.util.ArrayList<>(authorities);
        withFactor.add(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
            .issuedAt(java.time.Instant.now())
            .build());
        return UsernamePasswordAuthenticationToken.authenticated(principal, null, withFactor);
    }
}
