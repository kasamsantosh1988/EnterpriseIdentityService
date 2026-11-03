package com.example.authserver.handoff;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/** Hand-off links between applications and the one-time hand-off codes. */
@Repository
public class HandoffRepository {

    private static final int MAX_ROLES_LENGTH = 1000;

    /** What a successful redeem returns. */
    public record Redeemed(String sourceClientId, String subject, List<String> roles, String context) {
    }

    private final JdbcClient jdbc;

    public HandoffRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    // ---------------------------------------------------------------- links

    /** Replaces the list of applications this source may send users to. */
    @Transactional
    public void replaceTargets(String sourceClientId, Collection<String> targets) {
        this.jdbc.sql("DELETE FROM client_handoff_target WHERE source_client_id = :c").param("c", sourceClientId).update();
        for (String target : new LinkedHashSet<>(targets)) {
            this.jdbc.sql("INSERT INTO client_handoff_target (source_client_id, target_client_id) VALUES (:s, :t)")
                .param("s", sourceClientId)
                .param("t", target)
                .update();
        }
    }

    /** Replaces the list of applications whose users this target accepts. */
    @Transactional
    public void replaceAccepts(String targetClientId, Collection<String> sources) {
        this.jdbc.sql("DELETE FROM client_handoff_accept WHERE target_client_id = :c").param("c", targetClientId).update();
        for (String source : new LinkedHashSet<>(sources)) {
            this.jdbc.sql("INSERT INTO client_handoff_accept (target_client_id, source_client_id) VALUES (:t, :s)")
                .param("t", targetClientId)
                .param("s", source)
                .update();
        }
    }

    public List<String> targetsOf(String sourceClientId) {
        return this.jdbc
            .sql("SELECT target_client_id FROM client_handoff_target WHERE source_client_id = :c ORDER BY target_client_id")
            .param("c", sourceClientId)
            .query(String.class)
            .list();
    }

    public List<String> acceptsOf(String targetClientId) {
        return this.jdbc
            .sql("SELECT source_client_id FROM client_handoff_accept WHERE target_client_id = :c ORDER BY source_client_id")
            .param("c", targetClientId)
            .query(String.class)
            .list();
    }

    /** True only when the source lists the target AND the target accepts the source. */
    public boolean isAllowed(String sourceClientId, String targetClientId) {
        Integer count = this.jdbc.sql("""
                SELECT COUNT(*) FROM client_handoff_target t
                JOIN client_handoff_accept a
                  ON a.target_client_id = t.target_client_id AND a.source_client_id = t.source_client_id
                WHERE t.source_client_id = :s AND t.target_client_id = :t
                """)
            .param("s", sourceClientId)
            .param("t", targetClientId)
            .query(Integer.class)
            .single();
        return count != null && count > 0;
    }

    // ---------------------------------------------------------------- codes

    public void insertCode(String code, String sourceClientId, String targetClientId, String subject,
            Collection<String> roles, String context, Instant now, Instant expiresAt) {
        this.jdbc.sql("""
                INSERT INTO handoff_code
                    (code_hash, source_client_id, target_client_id, subject, roles, context_value, created_at, expires_at)
                VALUES (:h, :s, :t, :subject, :roles, :ctx, :created, :expires)
                """)
            .param("h", hash(code))
            .param("s", sourceClientId)
            .param("t", targetClientId)
            .param("subject", subject)
            .param("roles", joinRoles(roles))
            .param("ctx", StringUtils.hasText(context) ? context : null)
            .param("created", Timestamp.from(now))
            .param("expires", Timestamp.from(expiresAt))
            .update();
    }

    /**
     * Uses a code: it must exist, belong to this target, be unused and unexpired. The first caller wins (the update is
     * conditional), and the stored context and roles are wiped straight away.
     */
    @Transactional
    public Optional<Redeemed> consume(String code, String targetClientId, Instant now) {
        String hash = hash(code);
        int updated = this.jdbc.sql("""
                UPDATE handoff_code SET used_at = :now
                WHERE code_hash = :h AND target_client_id = :t AND used_at IS NULL AND expires_at > :now
                """)
            .param("now", Timestamp.from(now))
            .param("h", hash)
            .param("t", targetClientId)
            .update();
        if (updated != 1) {
            return Optional.empty();
        }
        Redeemed redeemed = this.jdbc
            .sql("SELECT source_client_id, subject, roles, context_value FROM handoff_code WHERE code_hash = :h")
            .param("h", hash)
            .query((rs, rowNum) -> new Redeemed(rs.getString(1), rs.getString(2), splitRoles(rs.getString(3)),
                    rs.getString(4)))
            .single();
        this.jdbc.sql("UPDATE handoff_code SET context_value = NULL, roles = NULL WHERE code_hash = :h")
            .param("h", hash)
            .update();
        return Optional.of(redeemed);
    }

    public int deleteExpired(Instant cutoff) {
        return this.jdbc.sql("DELETE FROM handoff_code WHERE expires_at < :cutoff")
            .param("cutoff", Timestamp.from(cutoff))
            .update();
    }

    // ---------------------------------------------------------------- helpers

    static String hash(String code) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(code.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    /** Roles are comma separated; a role containing a comma is skipped, and the list is cut to fit the column. */
    private static String joinRoles(Collection<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return null;                                // Oracle stores '' as NULL anyway
        }
        StringBuilder joined = new StringBuilder();
        for (String role : roles) {
            if (!StringUtils.hasText(role) || role.contains(",")) {
                continue;
            }
            int extra = role.length() + (joined.isEmpty() ? 0 : 1);
            if (joined.length() + extra > MAX_ROLES_LENGTH) {
                break;
            }
            if (!joined.isEmpty()) {
                joined.append(',');
            }
            joined.append(role);
        }
        return joined.isEmpty() ? null : joined.toString();
    }

    private static List<String> splitRoles(String value) {
        List<String> roles = new ArrayList<>();
        if (StringUtils.hasText(value)) {
            for (String role : value.split(",")) {
                if (!role.isBlank()) {
                    roles.add(role);
                }
            }
        }
        return roles;
    }
}
