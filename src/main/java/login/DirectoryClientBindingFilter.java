package com.example.authserver.login;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A login belongs to one application's directory. If a browser that is logged in for application A arrives at the
 * authorize endpoint for application B, the existing login is dropped so the user has to sign in again - otherwise
 * "A:1001" would silently receive tokens for B.
 */
public class DirectoryClientBindingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DirectoryClientBindingFilter.class);

    private final String authorizationEndpoint;

    public DirectoryClientBindingFilter(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return !this.authorizationEndpoint.equals(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String requested = request.getParameter("client_id");

        if (authentication instanceof UsernamePasswordAuthenticationToken && authentication.isAuthenticated()
                && requested != null) {
            String name = authentication.getName();
            int separator = name.indexOf(':');
            String boundClient = separator > 0 ? name.substring(0, separator) : null;
            if (boundClient == null || !boundClient.equals(requested)) {
                log.info("Login for '{}' is not valid for client '{}', asking for a new login", boundClient, requested);
                SecurityContextHolder.clearContext();
                HttpSession session = request.getSession(false);
                if (session != null) {
                    session.invalidate();
                }
                SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("anonymous",
                        "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
            }
        }
        chain.doFilter(request, response);
    }
}
