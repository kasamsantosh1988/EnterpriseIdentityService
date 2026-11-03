package com.example.authserver.token;

import java.util.List;

import com.example.authserver.directory.UserInfo;
import com.example.authserver.grant.HandoffGrant;
import com.example.authserver.refresh.FreshUserHolder;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

/**
 * Adds the claims applications rely on to every access token (they come back from /oauth2/introspect):
 * aud (which API the token is for), roles, dir (the application directory the user belongs to) and uid (the
 * application's own user id). "sub" is already "<clientId>:<userId>" because that is the principal name.
 *
 * Roles are those returned by the directory at login. On refresh they are the ones the refresh provider has just
 * re-read from the directory (FreshUserHolder).
 */
@Component
public class AccessTokenClaimsCustomizer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {

    private final ClientAudienceRepository audiences;

    public AccessTokenClaimsCustomizer(ClientAudienceRepository audiences) {
        this.audiences = audiences;
    }

    @Override
    public void customize(OAuth2TokenClaimsContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return;
        }
        OAuth2TokenClaimsSet.Builder claims = context.getClaims();

        List<String> audience = this.audiences.audiencesFor(context.getRegisteredClient().getClientId());
        if (!audience.isEmpty()) {
            claims.audience(new java.util.ArrayList<>(audience));
        }

        Authentication principal = context.getPrincipal();
        if (principal instanceof UsernamePasswordAuthenticationToken) {
            UserInfo fresh = FreshUserHolder.get();
            List<String> roles = (fresh != null
                    && AuthorizationGrantType.REFRESH_TOKEN.equals(context.getAuthorizationGrantType()))
                            ? new java.util.ArrayList<>(fresh.roles().stream().sorted().toList())
                            : principal.getAuthorities()
                                .stream()
                                .filter((a) -> !(a instanceof FactorGrantedAuthority))   // sign-in factor, not a role
                                .map(GrantedAuthority::getAuthority)
                                .sorted()
                                .collect(java.util.stream.Collectors.toCollection(java.util.ArrayList::new));
            claims.claim("roles", roles);
            String name = principal.getName();
            int separator = name.indexOf(':');
            if (separator > 0) {
                claims.claim("dir", name.substring(0, separator));
                claims.claim("uid", name.substring(separator + 1));
                if (HandoffGrant.TYPE.equals(context.getAuthorizationGrantType())) {
                    // The user was vouched for by another application: "dir" is that application, not this client.
                    claims.claim("src", name.substring(0, separator));
                }
            }
        }
    }
}
