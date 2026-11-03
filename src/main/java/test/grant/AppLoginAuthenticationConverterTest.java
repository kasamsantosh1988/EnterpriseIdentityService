package com.example.authserver.grant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AppLoginAuthenticationConverterTest {

    private final AppLoginAuthenticationConverter converter = new AppLoginAuthenticationConverter();

    @BeforeEach
    void authenticateClient() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("client", "secret"));
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static MockHttpServletRequest request(String grantType) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.setParameter("grant_type", grantType);
        return request;
    }

    @Test
    void ignoresOtherGrantTypes() {
        assertThat(this.converter.convert(request("client_credentials"))).isNull();
    }

    @Test
    void readsUsernamePasswordAndScopes() {
        MockHttpServletRequest request = request("app_login");
        request.setParameter("username", "alice");
        request.setParameter("password", "secret");
        request.setParameter("scope", "app reports");

        Authentication result = this.converter.convert(request);

        assertThat(result).isInstanceOf(AppLoginAuthenticationToken.class);
        AppLoginAuthenticationToken token = (AppLoginAuthenticationToken) result;
        assertThat(token.getUsername()).isEqualTo("alice");
        assertThat(token.getPassword()).isEqualTo("secret");
        assertThat(token.getScopes()).containsExactlyInAnyOrder("app", "reports");
    }

    @Test
    void refusesParametersInTheUrl() {
        MockHttpServletRequest request = request("app_login");
        request.setQueryString("username=alice&password=secret");
        request.setParameter("username", "alice");
        request.setParameter("password", "secret");
        assertThatThrownBy(() -> this.converter.convert(request)).isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void refusesRepeatedMissingAndUnknownParameters() {
        MockHttpServletRequest repeated = request("app_login");
        repeated.addParameter("username", "a");
        repeated.addParameter("username", "b");
        repeated.setParameter("password", "x");
        assertThatThrownBy(() -> this.converter.convert(repeated)).isInstanceOf(OAuth2AuthenticationException.class);

        MockHttpServletRequest missing = request("app_login");
        missing.setParameter("username", "alice");
        assertThatThrownBy(() -> this.converter.convert(missing)).isInstanceOf(OAuth2AuthenticationException.class);

        MockHttpServletRequest unknown = request("app_login");
        unknown.setParameter("username", "alice");
        unknown.setParameter("password", "x");
        unknown.setParameter("redirect_uri", "http://evil");
        assertThatThrownBy(() -> this.converter.convert(unknown)).isInstanceOf(OAuth2AuthenticationException.class);
    }
}
