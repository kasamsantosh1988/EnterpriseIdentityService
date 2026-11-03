package com.example.authserver.ratelimit;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

import com.example.authserver.config.AuthServerProperties;

import org.springframework.stereotype.Component;

/**
 * Counts failed sign-ins (wrong password only) per source address, per user and per application, in sliding windows,
 * and refuses further attempts once a limit is reached.
 *
 * Limits: the counters live in this node's memory, so with several nodes each node enforces its own count.
 * The per-user limit also lets someone who knows a username lock that user out for the window; that is the
 * usual trade-off, and it is limited to userWindow (default 15 minutes).
 */
@Component
public class AttemptLimiter {

    private static final int MAX_KEYS = 200_000;

    private final AuthServerProperties.Limits limits;

    private final LongSupplier clockMillis;

    private final ConcurrentHashMap<String, Deque<Long>> failures = new ConcurrentHashMap<>();

    public AttemptLimiter(AuthServerProperties props) {
        this(props.limits(), System::currentTimeMillis);
    }

    AttemptLimiter(AuthServerProperties.Limits limits, LongSupplier clockMillis) {
        this.limits = limits;
        this.clockMillis = clockMillis;
    }

    /** Throws if any limit is already reached. Call before asking the directory. */
    public void check(String clientId, String username, String ip) {
        verify(ipKey(ip), this.limits.ipFailures(), this.limits.shortWindow());
        verify(userKey(clientId, username), this.limits.userFailures(), this.limits.userWindow());
        verify(clientKey(clientId), this.limits.clientFailures(), this.limits.shortWindow());
    }

    /** Record a wrong-password result. */
    public void recordFailure(String clientId, String username, String ip) {
        add(ipKey(ip), this.limits.ipFailures());
        add(userKey(clientId, username), this.limits.userFailures());
        add(clientKey(clientId), this.limits.clientFailures());
    }

    /** A correct password clears the user's failures (not the address's). */
    public void recordSuccess(String clientId, String username) {
        this.failures.remove(userKey(clientId, username));
    }

    /** Drops counters whose events are all outside their window. Called by the housekeeping job. */
    public void prune() {
        long now = this.clockMillis.getAsLong();
        this.failures.entrySet().removeIf((entry) -> {
            Deque<Long> events = entry.getValue();
            long cutoff = now - windowFor(entry.getKey()).toMillis();
            synchronized (events) {
                while (!events.isEmpty() && events.peekFirst() < cutoff) {
                    events.pollFirst();
                }
                return events.isEmpty();
            }
        });
    }

    int trackedKeys() {
        return this.failures.size();
    }

    private void verify(String key, int max, Duration window) {
        Deque<Long> events = this.failures.get(key);
        if (events == null) {
            return;
        }
        long now = this.clockMillis.getAsLong();
        long cutoff = now - window.toMillis();
        synchronized (events) {
            while (!events.isEmpty() && events.peekFirst() < cutoff) {
                events.pollFirst();
            }
            if (events.size() >= max) {
                long oldest = events.peekFirst();
                long waitMillis = Math.max(1000, oldest + window.toMillis() - now);
                throw new TooManyAttemptsException((waitMillis + 999) / 1000);
            }
        }
    }

    private void add(String key, int max) {
        if (this.failures.size() > MAX_KEYS) {
            prune();
            if (this.failures.size() > MAX_KEYS && !this.failures.containsKey(key)) {
                return;                      // memory guard: stop creating new counters; existing ones keep working
            }
        }
        Deque<Long> events = this.failures.computeIfAbsent(key, (k) -> new ArrayDeque<>());
        synchronized (events) {
            events.addLast(this.clockMillis.getAsLong());
            while (events.size() > max) {
                events.pollFirst();
            }
        }
    }

    private Duration windowFor(String key) {
        return key.startsWith("user:") ? this.limits.userWindow() : this.limits.shortWindow();
    }

    private static String ipKey(String ip) {
        return "ip:" + (ip == null || ip.isBlank() ? "unknown" : ip);
    }

    private static String userKey(String clientId, String username) {
        return "user:" + clientId + "|" + (username == null ? "" : username.trim().toLowerCase(Locale.ROOT));
    }

    private static String clientKey(String clientId) {
        return "client:" + clientId;
    }
}
