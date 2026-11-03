package com.example.authserver.dev;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/** Dev only: lets the server call its own demo directory without a login. The controller checks its own key. */
@Configuration
@Profile("dev")
class DevSecurityConfig {

    @Bean
    @Order(0)
    SecurityFilterChain demoDirectoryChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/dev/**")
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().permitAll())
            .csrf((csrf) -> csrf.disable());
        return http.build();
    }
}
