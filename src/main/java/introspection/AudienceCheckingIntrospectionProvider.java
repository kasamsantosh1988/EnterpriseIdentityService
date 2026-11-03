package com.example.authserver.introspection;

import java.util.List;
import java.util.Optional;

import com.example.authserver.audit.AuditService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;

/**
 * Wraps the framework's introspection provider with the audience rule: a caller only sees a token as active if the
 * caller is a registered, enabled resource server and the token's "aud" contains that server's audience.
 * Otherwise the answer is the same as for an unknown token ({"active": false}), so a caller learns nothing about tokens
 * meant for other APIs. Refresh tokens carry no audience, so they always read as inactive here.
 */
public class AudienceCheckingIntrospectionProvider implements AuthenticationProvider {

    private final AuthenticationProvider delegate;

    private final ResourceServerRepository resourceServers;

    private final AuditService audit;

    private final MeterRegistry meters;

    public AudienceCheckingIntrospectionProvider(AuthenticationProvider delegate,
            ResourceServerRepository resourceServers, AuditService audit, MeterRegistry meters) {
        this.delegate = delegate;
        this.resourceServers = resourceServers;
        this.audit = audit;
        this.meters = meters;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Timer.Sample sample = Timer.start(this.meters);
        String outcome = "error";
        try {
            Authentication result = this.delegate.authenticate(authentication);
            if (!(result instanceof OAuth2TokenIntrospectionAuthenticationToken answer)
                    || !(answer.getPrincipal() instanceof OAuth2ClientAuthenticationToken caller)) {
                outcome = "unknown";
                return result;
            }
            OAuth2TokenIntrospection claims = answer.getTokenClaims();
            if (claims == null || !claims.isActive()) {
                outcome = "inactive";
                return result;
            }
            String callerId = caller.getRegisteredClient().getClientId();
            Optional<String> audience = this.resourceServers.audienceForClient(callerId);
            List<String> tokenAudience = claims.getAudience();
            if (audience.isPresent() && tokenAudience != null && tokenAudience.contains(audience.get())) {
                outcome = "active";
                return result;
            }
            outcome = "denied";
            this.audit.record("INTROSPECT_DENIED", callerId, claims.getSubject(), "FAILURE", null,
                    audience.isPresent() ? "token audience does not include " + audience.get()
                            : "caller is not a registered resource server");
            return new OAuth2TokenIntrospectionAuthenticationToken(answer.getToken(), caller,
                    OAuth2TokenIntrospection.builder().build());
        }
        finally {
            sample.stop(Timer.builder("authserver.introspection").tag("outcome", outcome).register(this.meters));
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return this.delegate.supports(authentication);
    }
}
