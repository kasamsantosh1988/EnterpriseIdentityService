package com.example.authserver.token;

import java.time.Duration;
import java.util.List;

import com.example.authserver.util.TtlCache;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Which audience(s) ("aud") the access tokens of a client are meant for. Cached briefly because it is read per token. */
@Repository
public class ClientAudienceRepository {

    private final JdbcClient jdbc;

    private final TtlCache<String, List<String>> cache = new TtlCache<>(Duration.ofSeconds(60));

    public ClientAudienceRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public List<String> audiencesFor(String clientId) {
        return this.cache.get(clientId, (id) -> this.jdbc
            .sql("SELECT audience FROM client_audience WHERE client_id = :clientId ORDER BY audience")
            .param("clientId", id)
            .query(String.class)
            .list());
    }
}
