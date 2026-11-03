# Operating the auth server (Milestone 4)

## Running several nodes

* Run 2+ identical, stateless nodes behind a load balancer. Everything shared lives in Oracle: clients, tokens, sessions,
  login sessions of the central page (`SPRING_SESSION*`, no sticky sessions needed), audit.
* **All nodes must use the same signing keystore.** `allow-ephemeral` must be `false` outside local development.
* Set `SESSION_COOKIE_SECURE=true` (the default) and terminate TLS at the load balancer with `X-Forwarded-Proto`/`-For`
  passed through (`forward-headers-strategy: framework` is already set). Strip `X-Forwarded-For` from outside requests.
* Health check for the load balancer: `/actuator/health`.
* Per-node memory: login rate-limit counters (so the effective limit is *limit x nodes*; lower the `authserver.limits.*`
  numbers accordingly), directory-config cache (60 s), audience caches (30-60 s). Cleanup runs on every node; that is harmless.
* Keep the application servers' clocks in sync (NTP); the JVM runs in UTC.

## Metrics (`/actuator/prometheus`)

Reachable only from `authserver.metrics.allowed-addresses` (default localhost). Set it to your Prometheus address or
CIDR. Useful series:

| Metric | Meaning |
|---|---|
| `authserver_introspection_seconds{outcome=active|inactive|denied|unknown|error}` | latency and count of introspection calls |
| `authserver_events_total{type,outcome}` | one count per audit event: `LOGIN`, `LOGIN_FAILED`, `REFRESH`, `REFRESH_DENIED`, `REFRESH_REUSE`, `REVOKE`, `INTROSPECT_DENIED`, ... |
| `http_server_requests_seconds` | request latency/status; filter by `uri`/`status` for `/oauth2/token` (may show as `UNKNOWN` for framework-handled paths) |

Suggested alerts: `REFRESH_REUSE` > 0, a rising `LOGIN_FAILED` rate, `status=503` on the token endpoint (a directory is
down), introspection p95 above 100 ms.

## Secrets

* The database password, keystore password and every directory secret come from environment variables or a secret
  store, never from files in the repo. Directory secrets are referenced by name (`verify_secret_ref`) and resolved by
  `SecretResolver` from the property `authserver.secrets.<name>`.
* With HashiCorp Vault: use Spring Cloud Vault (`spring.config.import=vault://`) to load a KV path into properties named
  `authserver.secrets.*`, `spring.datasource.password` and `authserver.signing.keystore-password`. No code change is needed.
* Client secrets are stored only as bcrypt hashes; the plain value is shown once at registration.

## Signing-key rotation

Access tokens are opaque, so rotating the key does **not** affect them. It affects only the signed ID tokens and the JWKS.
Do it in three releases so every node and every client always sees a consistent JWKS:

1. Create the new key in the keystore (alias `auth-signing-2`) and deploy to all nodes with
   `authserver.signing.published-key-aliases: auth-signing-2` (the new key is published, but not used yet).
2. After clients have had time to refresh their JWKS cache (a day is plenty), switch:
   `key-alias: auth-signing-2` and `published-key-aliases: auth-signing` (old key still published so existing ID tokens verify).
3. After the longest ID token lifetime (30 minutes with the current token settings; waiting a day is safe), remove `published-key-aliases` and the old key.

## Database

* Flyway runs on startup (V1-V5). Give the application user only the rights it needs on its own schema.
* `CleanupJob` removes expired authorizations, sessions and rotation hashes (`authserver.cleanup.*`). Spring Session removes
  expired HTTP sessions itself.
* Back up the schema; losing it signs everyone out (tokens are all in it).

## Hardening already in place

Hashed client secrets; PKCE required; opaque tokens; rotation + reuse detection; login throttling; audit of logins,
refreshes, revocations, registrations and denied introspection; audience-checked introspection; no CORS by default
(`authserver.cors.allowed-origins`); CSP/Referrer-Policy/frame-denial headers; secure, HttpOnly, SameSite=Lax session
cookie; `/actuator` closed except health (and metrics from the monitoring network); admin API only for client-credentials
tokens carrying the right scope.
