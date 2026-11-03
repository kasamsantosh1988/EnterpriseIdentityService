package com.example.authserver.ratelimit;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import com.example.authserver.config.AuthServerProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AttemptLimiterTest {

    private final AtomicLong now = new AtomicLong(1_000_000);

    private final AttemptLimiter limiter = new AttemptLimiter(
            new AuthServerProperties.Limits(30, 3, 300, Duration.ofMinutes(10), Duration.ofMinutes(15)),
            this.now::get);

    @Test
    void blocksAUserAfterTheConfiguredNumberOfFailures() {
        for (int i = 0; i < 3; i++) {
            this.limiter.check("app", "Alice", "10.0.0.1");
            this.limiter.recordFailure("app", "Alice", "10.0.0.1");
        }
        assertThatThrownBy(() -> this.limiter.check("app", "alice", "10.0.0.2"))
            .isInstanceOf(TooManyAttemptsException.class);
        // another user of the same application is not affected
        assertThatCode(() -> this.limiter.check("app", "bob", "10.0.0.2")).doesNotThrowAnyException();
        // the same username in another application is not affected either
        assertThatCode(() -> this.limiter.check("other", "alice", "10.0.0.2")).doesNotThrowAnyException();
    }

    @Test
    void allowsAgainOnceTheWindowHasPassed() {
        for (int i = 0; i < 3; i++) {
            this.limiter.recordFailure("app", "alice", "10.0.0.1");
        }
        assertThatThrownBy(() -> this.limiter.check("app", "alice", "10.0.0.1"))
            .isInstanceOf(TooManyAttemptsException.class);
        this.now.addAndGet(Duration.ofMinutes(16).toMillis());
        assertThatCode(() -> this.limiter.check("app", "alice", "10.0.0.1")).doesNotThrowAnyException();
    }

    @Test
    void aSuccessfulLoginClearsTheUsersFailures() {
        this.limiter.recordFailure("app", "alice", "10.0.0.1");
        this.limiter.recordFailure("app", "alice", "10.0.0.1");
        this.limiter.recordSuccess("app", "alice");
        this.limiter.recordFailure("app", "alice", "10.0.0.1");
        assertThatCode(() -> this.limiter.check("app", "alice", "10.0.0.1")).doesNotThrowAnyException();
    }

    @Test
    void reportsHowLongToWait() {
        for (int i = 0; i < 3; i++) {
            this.limiter.recordFailure("app", "alice", "10.0.0.1");
        }
        this.now.addAndGet(Duration.ofMinutes(5).toMillis());
        assertThatThrownBy(() -> this.limiter.check("app", "alice", "10.0.0.1"))
            .isInstanceOfSatisfying(TooManyAttemptsException.class,
                    (ex) -> assertThat(ex.getRetryAfterSeconds()).isBetween(590L, 610L));
    }

    @Test
    void pruneDropsExpiredCounters() {
        this.limiter.recordFailure("app", "alice", "10.0.0.1");
        assertThat(this.limiter.trackedKeys()).isEqualTo(3);
        this.now.addAndGet(Duration.ofMinutes(20).toMillis());
        this.limiter.prune();
        assertThat(this.limiter.trackedKeys()).isZero();
    }
}
