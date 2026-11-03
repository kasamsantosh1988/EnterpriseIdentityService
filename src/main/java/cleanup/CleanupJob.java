package com.example.authserver.cleanup;

import java.sql.Timestamp;
import java.time.Instant;

import com.example.authserver.config.AuthServerProperties;
import com.example.authserver.handoff.HandoffRepository;
import com.example.authserver.ratelimit.AttemptLimiter;
import com.example.authserver.session.SessionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Removes data that can no longer matter: authorizations whose every token expired more than "retention" ago, expired
 * sessions, old rotated-token hashes, and stale in-memory rate-limit counters. Safe to run on several nodes at once
 * (it only deletes rows that are already dead).
 */
@Component
public class CleanupJob {

    private static final Logger log = LoggerFactory.getLogger(CleanupJob.class);

    private static final int BATCH = 5000;

    private static final int MAX_BATCHES = 100;

    private final JdbcClient jdbc;

    private final SessionRepository sessions;

    private final AttemptLimiter limiter;

    private final AuthServerProperties.Cleanup settings;

    private final HandoffRepository handoffs;

    public CleanupJob(JdbcClient jdbc, SessionRepository sessions, AttemptLimiter limiter, AuthServerProperties props,
            HandoffRepository handoffs) {
        this.jdbc = jdbc;
        this.sessions = sessions;
        this.limiter = limiter;
        this.settings = props.cleanup();
        this.handoffs = handoffs;
    }

    @Scheduled(fixedDelayString = "${authserver.cleanup.interval:PT1H}", initialDelayString = "${authserver.cleanup.interval:PT1H}")
    public void run() {
        try {
            Instant cutoff = Instant.now().minus(this.settings.retention());
            int authorizations = deleteExpiredAuthorizations(cutoff);
            int sessionRows = this.sessions.deleteExpiredSessions(cutoff);
            int rotations = this.sessions.deleteExpiredRotations(cutoff);
            int handoffCodes = this.handoffs.deleteExpired(cutoff);
            this.limiter.prune();
            log.info("Cleanup removed {} authorizations, {} sessions, {} rotated-token hashes, {} hand-off codes",
                    authorizations, sessionRows, rotations, handoffCodes);
        }
        catch (RuntimeException ex) {
            log.error("Cleanup failed", ex);
        }
    }

    private int deleteExpiredAuthorizations(Instant cutoff) {
        // GREATEST returns NULL in Oracle if any argument is NULL, so every column is COALESCEd to the epoch first.
        // A row where nothing was ever issued has the epoch as its latest expiry and is left alone.
        String sql = """
                DELETE FROM oauth2_authorization WHERE id IN (
                    SELECT id FROM (
                        SELECT id, GREATEST(
                            COALESCE(authorization_code_expires_at, :epoch),
                            COALESCE(access_token_expires_at, :epoch),
                            COALESCE(oidc_id_token_expires_at, :epoch),
                            COALESCE(refresh_token_expires_at, :epoch),
                            COALESCE(user_code_expires_at, :epoch),
                            COALESCE(device_code_expires_at, :epoch)) AS last_expiry
                        FROM oauth2_authorization)
                    WHERE last_expiry > :epoch AND last_expiry < :cutoff
                    FETCH FIRST %d ROWS ONLY)
                """.formatted(BATCH);
        int total = 0;
        for (int i = 0; i < MAX_BATCHES; i++) {
            int deleted = this.jdbc.sql(sql)
                .param("epoch", Timestamp.from(Instant.EPOCH))
                .param("cutoff", Timestamp.from(cutoff))
                .update();
            total += deleted;
            if (deleted < BATCH) {
                break;
            }
        }
        return total;
    }
}
