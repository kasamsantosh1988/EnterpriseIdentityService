package com.example.authserver.config;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.example.authserver.admin.LocalOpaqueTokenIntrospector;
import com.example.authserver.audit.AuditService;
import com.example.authserver.directory.DirectoryProviderRegistry;
import com.example.authserver.grant.AppLoginAuthenticationConverter;
import com.example.authserver.grant.AppLoginAuthenticationProvider;
import com.example.authserver.grant.HandoffAuthenticationConverter;
import com.example.authserver.grant.HandoffAuthenticationProvider;
import com.example.authserver.handoff.HandoffRepository;
import com.example.authserver.grant.TokenErrorResponseHandler;
import com.example.authserver.introspection.AudienceCheckingIntrospectionProvider;
import com.example.authserver.introspection.ResourceServerRepository;
import com.example.authserver.login.DirectoryAuthenticationProvider;
import com.example.authserver.login.DirectoryLoginService;
import com.example.authserver.logout.RevokingOidcLogoutAuthenticationProvider;
import com.example.authserver.refresh.DirectoryRefreshTokenAuthenticationProvider;
import com.example.authserver.session.SessionRepository;
import com.example.authserver.session.SessionRevocationService;
import com.example.authserver.session.SessionTrackingAuthorizationService;
import com.example.authserver.login.DirectoryClientBindingFilter;
import com.example.authserver.login.LoginDetailsSource;
import com.example.authserver.login.LoginFailureHandler;
import io.micrometer.core.instrument.MeterRegistry;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.beans.factory.annotation.Value;
import java.util.List;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.StringUtils;

/**
 * Milestone 1 wiring: protocol endpoints, JDBC-backed stores, signing keys.
 *
 * Milestone 2: the central login page authenticates against the user directory of the application
 * (registered client) the login was started from, via DirectoryAuthenticationProvider.
 */
@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServerConfig.class);

    /** Chain 1: OAuth2/OIDC protocol endpoints (/oauth2/token, /oauth2/introspect, /oauth2/jwks, ...). */
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
            AuthorizationServerSettings settings, OAuth2AuthorizationService authorizationService,
            DirectoryLoginService loginService,
            TokenErrorResponseHandler tokenErrorHandler, DirectoryProviderRegistry registry,
            SessionRepository sessions, SessionRevocationService revocation, AuditService audit,
            AuthServerProperties props, ResourceServerRepository resourceServers, MeterRegistry meters,
            HandoffRepository handoffs)
            throws Exception {
        http
            .cors(Customizer.withDefaults())
            .headers(AuthorizationServerConfig::securityHeaders)
            .oauth2AuthorizationServer((authorizationServer) -> {
                http.securityMatcher(authorizationServer.getEndpointsMatcher());
                authorizationServer
                    // /oauth2/introspect: a caller only sees tokens issued for its own audience
                    .tokenIntrospectionEndpoint((introspection) -> introspection
                        .authenticationProviders((providers) -> providers
                            .replaceAll((provider) -> (provider instanceof OAuth2TokenIntrospectionAuthenticationProvider)
                                    ? new AudienceCheckingIntrospectionProvider(provider, resourceServers, audit, meters)
                                    : provider)))
                    // /oauth2/token: the app_login grant, the refresh-time directory check, JSON error responses
                    .tokenEndpoint((token) -> token
                        .accessTokenRequestConverter(new AppLoginAuthenticationConverter())
                        .accessTokenRequestConverter(new HandoffAuthenticationConverter())
                        .errorResponseHandler(tokenErrorHandler)
                        .authenticationProviders((providers) -> {
                            // The framework has already created its providers (and the shared token generator).
                            OAuth2TokenGenerator<? extends OAuth2Token> generator = http
                                .getSharedObject(OAuth2TokenGenerator.class);
                            providers.replaceAll((provider) -> (provider instanceof OAuth2RefreshTokenAuthenticationProvider)
                                    ? new DirectoryRefreshTokenAuthenticationProvider(provider, authorizationService,
                                            registry, sessions, revocation, audit, props.session())
                                    : provider);
                            providers.add(0, new AppLoginAuthenticationProvider(authorizationService, generator,
                                    loginService));
                            providers.add(0, new HandoffAuthenticationProvider(authorizationService, generator, handoffs,
                                    audit));
                        }))
                    .oidc((oidc) -> oidc
                        // /connect/logout also revokes the tokens of the session named by the id_token_hint
                        .logoutEndpoint((logout) -> logout.authenticationProviders((providers) -> providers
                            .replaceAll((provider) -> (provider instanceof OidcLogoutAuthenticationProvider)
                                    ? new RevokingOidcLogoutAuthenticationProvider(provider, authorizationService,
                                            revocation)
                                    : provider))));
            })
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
            // A login is tied to one application's directory; see DirectoryClientBindingFilter.
            .addFilterBefore(new DirectoryClientBindingFilter(settings.getAuthorizationEndpoint()),
                    AuthorizationFilter.class)
            // Browser requests to /oauth2/authorize that are not logged in go to the login page.
            .exceptionHandling((exceptions) -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
        return http.build();
    }

    /**
     * Admin API for application backends (/admin/**). Callers present a client_credentials access token that carries the
     * scope auth.revoke. Stateless; no browser session or CSRF involved.
     */
    @Bean
    @Order(-1)
    SecurityFilterChain adminSecurityFilterChain(HttpSecurity http, LocalOpaqueTokenIntrospector introspector)
            throws Exception {
        http
            .securityMatcher("/admin/**")
            .headers(AuthorizationServerConfig::securityHeaders)
            .authorizeHttpRequests((authorize) -> authorize
                .requestMatchers("/admin/sessions/**").hasAuthority("SCOPE_auth.revoke")
                .requestMatchers("/admin/apps/**", "/admin/resource-servers/**").hasAuthority("SCOPE_auth.admin")
                .anyRequest().denyAll())
            .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable)
            .oauth2ResourceServer((resourceServer) -> resourceServer
                .opaqueToken((opaque) -> opaque.introspector(introspector)));
        return http.build();
    }

    /**
     * Hand-off code endpoint (/oauth2/handoff). Stateless, no CSRF (callers are application backends, not browsers). The
     * controller authenticates the calling client itself (client id and secret) and checks the user's token.
     */
    @Bean
    @Order(0)
    SecurityFilterChain handoffSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/oauth2/handoff")
            .headers(AuthorizationServerConfig::securityHeaders)
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().permitAll())
            .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    /** Chain 2: the central login page and health. Users are checked against the calling application's directory. */
    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, DirectoryAuthenticationProvider provider,
            LoginDetailsSource detailsSource, LoginFailureHandler failureHandler,
            @Value("${authserver.metrics.allowed-addresses:127.0.0.1,::1}") List<String> metricsAddresses)
            throws Exception {
        http
            .authenticationProvider(provider)
            .headers(AuthorizationServerConfig::securityHeaders)
            .authorizeHttpRequests((authorize) -> {
                authorize.requestMatchers("/login", "/actuator/health/**", "/error").permitAll();
                // Metrics are scraped from the monitoring network only; everything else under /actuator stays closed.
                RequestMatcher monitoringNetwork = new OrRequestMatcher(metricsAddresses.stream()
                    .map(String::trim)
                    .filter((address) -> !address.isEmpty())
                    .<RequestMatcher>map(IpAddressMatcher::new)
                    .toList());
                authorize.requestMatchers(new AndRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher("/actuator/prometheus"), monitoringNetwork)).permitAll();
                authorize.requestMatchers("/actuator/prometheus").denyAll();
            })
            .authorizeHttpRequests((authorize) -> authorize
                .anyRequest().authenticated())
            .formLogin((form) -> form
                .loginPage("/login")
                .authenticationDetailsSource(detailsSource)
                .failureHandler(failureHandler)
                .permitAll());
        return http.build();
    }

    /** Response headers for every chain. (HSTS is added by the framework for HTTPS requests.) */
    private static void securityHeaders(HeadersConfigurer<HttpSecurity> headers) {
        headers
            .contentSecurityPolicy((csp) -> csp
                .policyDirectives("default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"))
            .referrerPolicy((referrer) -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER));
    }

    /**
     * Browsers may call the token endpoints only from origins listed in authserver.cors.allowed-origins.
     * Empty (the default) = no cross-origin browser access at all; the normal Option A setup (calls from the
     * application backend) needs none.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @Value("${authserver.cors.allowed-origins:}") List<String> allowedOrigins) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        List<String> origins = allowedOrigins.stream().map(String::trim).filter((o) -> !o.isEmpty()).toList();
        if (!origins.isEmpty()) {
            CorsConfiguration configuration = new CorsConfiguration();
            configuration.setAllowedOrigins(origins);
            configuration.setAllowedMethods(List.of("POST", "OPTIONS"));
            configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
            configuration.setAllowCredentials(false);
            configuration.setMaxAge(600L);
            source.registerCorsConfiguration("/oauth2/token", configuration);
            source.registerCorsConfiguration("/oauth2/revoke", configuration);
        }
        return source;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        // Delegating encoder: new secrets are bcrypt-hashed and stored as {bcrypt}...
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /** JDBC store, wrapped so that every login/refresh also keeps the session bookkeeping (see SessionTracking...). */
    @Bean
    OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository, SessionRepository sessions,
            AuthServerProperties props) {
        return new SessionTrackingAuthorizationService(
                new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository), sessions,
                registeredClientRepository, props.session());
    }

    @Bean
    OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(AuthServerProperties props) {
        return AuthorizationServerSettings.builder().issuer(props.issuer()).build();
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Signing keys. Production: PKCS12 keystore (later: Vault/HSM with rotation).
     * Dev only: an ephemeral key generated at startup (tokens/JWKS change on every restart and
     * differ per node, so never use it with more than one instance).
     */
    @Bean
    JWKSource<SecurityContext> jwkSource(AuthServerProperties props, ResourceLoader resourceLoader) throws Exception {
        AuthServerProperties.Signing signing = props.signing();
        RSAKey rsaKey;
        java.util.List<com.nimbusds.jose.jwk.JWK> retired = new java.util.ArrayList<>();

        if (StringUtils.hasText(signing.keystoreLocation())) {
            char[] password = signing.keystorePassword() == null ? new char[0] : signing.keystorePassword().toCharArray();
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream in = resourceLoader.getResource(signing.keystoreLocation()).getInputStream()) {
                keyStore.load(in, password);
            }
            RSAKey loaded = RSAKey.load(keyStore, signing.keyAlias(), password);
            if (loaded == null) {
                throw new IllegalStateException("No RSA key with alias '" + signing.keyAlias() + "' in keystore");
            }
            rsaKey = new RSAKey.Builder(loaded).keyIDFromThumbprint().build();
            // Extra published keys: only their PUBLIC part is served in the JWKS (used for key rotation).
            for (String alias : signing.publishedKeyAliases()) {
                RSAKey old = RSAKey.load(keyStore, alias, password);
                if (old == null) {
                    throw new IllegalStateException("No RSA key with alias '" + alias + "' in keystore");
                }
                retired.add(new RSAKey.Builder(old.toPublicJWK()).keyIDFromThumbprint().build());
            }
        }
        else if (signing.allowEphemeral()) {
            log.warn("Using an EPHEMERAL signing key. Development only - do not run like this in production.");
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyIDFromThumbprint()
                .build();
        }
        else {
            throw new IllegalStateException(
                "No signing key configured. Set authserver.signing.keystore-location (or allow-ephemeral=true for dev).");
        }
        java.util.List<com.nimbusds.jose.jwk.JWK> keys = new java.util.ArrayList<>();
        keys.add(rsaKey);
        keys.addAll(retired);
        return new ImmutableJWKSet<>(new JWKSet(keys));
    }
}
