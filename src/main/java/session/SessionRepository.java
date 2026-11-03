package com.example.authserver.session;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * Sessions (auth_session) and rotated refresh tokens (refresh_token_history).
 *
 * A session is keyed by the id of its OAuth2 authorization: that id stays the same every time the refresh token is
 * rotated, so one login = one session. All times are written from Java (the JVM runs in UTC) rather than from the
 * database clock, so they compare consistently.
 */
@Repository("authSessionRepository")
public class SessionRepository {

    public record SessionRow(String sid, String subject, String clientId, Instant authenticatedAt, Instant expiresAt,
            Instant revokedAt) {

        public boolean isRevoked() {
            return this.revokedAt != null;
        }

        public boolean isExpired(Instant now) {
            return now.isAfter(this.expiresAt);
        }
    }

    public record RotationRow(String sid, Instant rotatedAt) {
    }

    private final JdbcClient jdbc;

    public SessionRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** Hash used to recognise a rotated refresh token later. */
    public static String hash(String tokenValue) {
        return TokenHash.of(tokenValue);
    }

    public Optional<SessionRow> find(String sid) {
        return this.jdbc.sql("""
                SELECT sid, subject, client_id, authenticated_at, expires_at, revoked_at
                FROM auth_session WHERE sid = :sid
                """)
            .param("sid", sid)
            .query((rs, rowNum) -> new SessionRow(rs.getString("sid"), rs.getString("subject"),
                    rs.getString("client_id"), toInstant(rs.getTimestamp("authenticated_at")),
                    toInstant(rs.getTimestamp("expires_at")), toInstant(rs.getTimestamp("revoked_at"))))
            .optional();
    }

    /** Creates the session if it does not exist yet. Two requests racing to create it is fine. */
    public void ensure(String sid, String subject, String clientId, Instant now, Instant expiresAt) {
        try {
            this.jdbc.sql("""
                    INSERT INTO auth_session (sid, subject, client_id, authenticated_at, last_seen_at, expires_at)
                    VALUES (:sid, :subject, :clientId, :now, :now, :expires)
                    """)
                .param("sid", sid)
                .param("subject", subject)
                .param("clientId", clientId)
                .param("now", Timestamp.from(now))
                .param("expires", Timestamp.from(expiresAt))
                .update();
        }
        catch (DuplicateKeyException ex) {
            // already there
        }
    }

    /** Returns the number of rows updated (0 means the session does not exist). */
    public int touch(String sid, Instant now) {
        return this.jdbc.sql("UPDATE auth_session SET last_seen_at = :now WHERE sid = :sid")
            .param("now", Timestamp.from(now))
            .param("sid", sid)
            .update();
    }

    public void markRevoked(String sid, Instant now) {
        this.jdbc.sql("UPDATE auth_session SET revoked_at = :now WHERE sid = :sid AND revoked_at IS NULL")
            .param("now", Timestamp.from(now))
            .param("sid", sid)
            .update();
    }

    public void recordRotation(String tokenHash, String sid, Instant rotatedAt, Instant expiresAt) {
        try {
            this.jdbc.sql("""
                    INSERT INTO refresh_token_history (token_hash, sid, rotated_at, expires_at)
                    VALUES (:hash, :sid, :rotated, :expires)
                    """)
                .param("hash", tokenHash)
                .param("sid", sid)
                .param("rotated", Timestamp.from(rotatedAt))
                .param("expires", Timestamp.from(expiresAt))
                .update();
        }
        catch (DuplicateKeyException ex) {
            // already recorded
        }
    }

    public Optional<RotationRow> findRotation(String tokenHash) {
        return this.jdbc.sql("SELECT sid, rotated_at FROM refresh_token_history WHERE token_hash = :hash")
            .param("hash", tokenHash)
            .query((rs, rowNum) -> new RotationRow(rs.getString("sid"), toInstant(rs.getTimestamp("rotated_at"))))
            .optional();
    }

    public int deleteExpiredSessions(Instant cutoff) {
        return this.jdbc.sql("DELETE FROM auth_session WHERE expires_at < :cutoff")
            .param("cutoff", Timestamp.from(cutoff))
            .update();
    }

    public int deleteExpiredRotations(Instant cutoff) {
        return this.jdbc.sql("DELETE FROM refresh_token_history WHERE expires_at < :cutoff")
            .param("cutoff", Timestamp.from(cutoff))
            .update();
    }

    private static Instant toInstant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}
