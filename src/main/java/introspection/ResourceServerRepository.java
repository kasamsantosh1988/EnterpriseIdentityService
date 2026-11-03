package com.example.authserver.introspection;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import com.example.authserver.util.TtlCache;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** The APIs (resource servers) allowed to call /oauth2/introspect, and the audience each one stands for. */
@Repository
public class ResourceServerRepository {

    public record ResourceServer(String id, String audience, String name, String introspectionClientId,
            boolean enabled) {
    }

    private final JdbcClient jdbc;

    private final TtlCache<String, Optional<String>> audienceByClient = new TtlCache<>(Duration.ofSeconds(30));

    public ResourceServerRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** Audience of the enabled resource server that authenticates as this client, if there is one. */
    public Optional<String> audienceForClient(String clientId) {
        return this.audienceByClient.get(clientId, (id) -> this.jdbc
            .sql("SELECT audience FROM resource_server WHERE introspection_client_id = :c AND enabled = 1")
            .param("c", id)
            .query(String.class)
            .optional());
    }

    public List<ResourceServer> findAll() {
        return this.jdbc.sql("""
                SELECT id, audience, name, introspection_client_id, enabled FROM resource_server ORDER BY id
                """)
            .query((rs, n) -> new ResourceServer(rs.getString("id"), rs.getString("audience"), rs.getString("name"),
                    rs.getString("introspection_client_id"), rs.getInt("enabled") == 1))
            .list();
    }

    public boolean exists(String id) {
        Integer count = this.jdbc.sql("SELECT COUNT(*) FROM resource_server WHERE id = :id")
            .param("id", id)
            .query(Integer.class)
            .single();
        return count != null && count > 0;
    }

    public void insert(ResourceServer server) {
        this.jdbc.sql("""
                INSERT INTO resource_server (id, audience, name, introspection_client_id, enabled)
                VALUES (:id, :aud, :name, :client, :enabled)
                """)
            .param("id", server.id())
            .param("aud", server.audience())
            .param("name", server.name())
            .param("client", server.introspectionClientId())
            .param("enabled", server.enabled() ? 1 : 0)
            .update();
    }

    public int setEnabled(String id, boolean enabled) {
        return this.jdbc.sql("UPDATE resource_server SET enabled = :e WHERE id = :id")
            .param("e", enabled ? 1 : 0)
            .param("id", id)
            .update();
    }
}
