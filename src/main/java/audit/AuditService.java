package com.example.authserver.audit;

import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

/** Writes security events to audit_event. Never put passwords or tokens in {@code detail}. */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final JdbcClient jdbc;

    private final MeterRegistry meters;

    public AuditService(JdbcClient jdbc, MeterRegistry meters) {
        this.jdbc = jdbc;
        this.meters = meters;
    }

    /** A failure to write the audit row is logged but must not break the login itself. */
    public void record(String eventType, String clientId, String subject, String outcome, String ip, String detail) {
        try {
            this.jdbc.sql("""
                    INSERT INTO audit_event (event_type, client_id, subject, outcome, ip_address, detail)
                    VALUES (:type, :clientId, :subject, :outcome, :ip, :detail)
                    """)
                .param("type", eventType)
                .param("clientId", nz(clientId))
                .param("subject", nz(subject))
                .param("outcome", outcome)
                .param("ip", nz(ip))
                .param("detail", truncate(nz(detail)))
                .update();
        }
        catch (RuntimeException ex) {
            log.error("Could not write audit event {} ({})", eventType, outcome, ex);
        }
        this.meters.counter("authserver.events", "type", eventType, "outcome", outcome).increment();
        log.info("AUDIT type={} client={} subject={} outcome={}", eventType, clientId, subject, outcome);
    }

    // Oracle stores '' as NULL, and untyped null parameters can be awkward with some drivers, so pass '' for "no value".
    private static String nz(String value) {
        return value == null ? "" : value;
    }

    private static String truncate(String value) {
        return value.length() <= 500 ? value : value.substring(0, 500);
    }
}
