package com.example.authserver.directory;

import java.util.regex.Pattern;

import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Turns a secret reference stored in the database (e.g. "appa-db") into the actual secret.
 * Today it reads the property authserver.secrets.<ref>, which in production comes from an environment
 * variable such as AUTHSERVER_SECRETS_APPA_DB. Replace this class to read from Vault later.
 */
@Component
public class SecretResolver {

    private static final Pattern SAFE_REF = Pattern.compile("[A-Za-z0-9_.-]{1,100}");

    private final Environment environment;

    public SecretResolver(Environment environment) {
        this.environment = environment;
    }

    /** Returns null when no reference is configured; throws when a reference is configured but has no value. */
    public String resolve(String ref) {
        if (!StringUtils.hasText(ref)) {
            return null;
        }
        if (!SAFE_REF.matcher(ref).matches()) {
            throw new IllegalStateException("Invalid secret reference format");
        }
        String value = this.environment.getProperty("authserver.secrets." + ref);
        if (!StringUtils.hasText(value)) {
            throw new IllegalStateException("No secret configured for reference '" + ref + "'");
        }
        return value;
    }
}
