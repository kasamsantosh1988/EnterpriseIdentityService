# Onboarding applications and APIs (Milestone 4)

Two kinds of things are registered:

* **An application** (has users, logs them in): an OAuth client + its user directory + the audience(s) its tokens are for.
* **An API / resource server** (validates tokens): an introspection client + the audience it stands for.

Everything is done with the admin API. Get an admin token first (the `platform-admin` client has scope `auth.admin`;
in production create it once with the bootstrap setting, then switch bootstrap off and keep its secret in Vault):

```bash
ADMIN=$(curl -s -u platform-admin:platform-admin-secret -d grant_type=client_credentials -d scope=auth.admin \
  http://localhost:9000/oauth2/token | sed 's/.*"access_token":"\([^"]*\)".*/\1/')
```

## 1. Register an API (once per API)

```bash
curl -s -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"id":"orders-api","audience":"orders-api","name":"Orders API"}' http://localhost:9000/admin/resource-servers
# 201 {"clientId":"orders-api","clientSecret":"..."}   <- shown once; give it to the API team (Vault)
```

The API calls `/oauth2/introspect` with that id/secret (see `auth-introspection-client`). It only ever sees tokens whose
`aud` contains `orders-api`; for anything else it gets `{"active":false}`.

## 2. Register an application

REMOTE directory (the app exposes a verify service, see `directory-contracts.md`):

```bash
curl -s -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{
  "clientId": "ilounge",
  "name": "iLounge",
  "grants": ["app_login", "authorization_code", "refresh_token"],
  "redirectUris": ["https://ilounge.example.com/callback"],
  "scopes": ["openid", "app", "auth.revoke"],
  "audiences": ["orders-api", "ilounge-api"],
  "directory": {
    "type": "REMOTE",
    "verifyUrl": "https://ilounge.internal/auth/verify",
    "statusUrl": "https://ilounge.internal/auth/status",
    "verifySecretRef": "ilounge-verify"
  }
}' http://localhost:9000/admin/apps
# 201 {"clientId":"ilounge","clientSecret":"..."}   <- the backend's client secret, shown once
```

Then provide the secret behind `verifySecretRef`: environment variable `AUTHSERVER_SECRETS_ILOUNGE_VERIFY` (or the same
key from Vault). The API never accepts directory secrets, only their reference names.

JDBC directory: `"type":"JDBC"` with `jdbcUrl`, `jdbcUsername`, `jdbcSecretRef`, `authQuery`, `loadQuery` (and optional
`passwordHashType`), see `directory-contracts.md`.

Rules checked by the API: client id 2-99 chars of letters/digits/`.`/`_`/`-` (no `:`), grants limited to
`authorization_code`, `app_login`, `refresh_token`, `client_credentials`, `handoff`; user-login grants need a directory;
scopes starting `auth.` are refused except `auth.revoke`.

An application that only receives users from another application (no user list of its own) is registered with grant
`handoff` and no directory; see `handoff.md` for `handoffTargets`, `acceptsHandoffFrom` and
`/admin/apps/{clientId}/handoff-links`.

## 3. Day-two operations

| Task | Call |
|---|---|
| New client secret (old one dies at once) | `POST /admin/apps/{clientId}/rotate-secret` |
| Stop all logins/refreshes of an application | `POST /admin/apps/{clientId}/directory/disable` (`/enable` to undo) |
| Stop an API from validating tokens | `POST /admin/resource-servers/{id}/disable` (`/enable`) |
| List APIs | `GET /admin/resource-servers` |
| Sign one user out everywhere | `POST /admin/sessions/revoke` (scope `auth.revoke`, the app's own token) |

Every one of these writes an `audit_event` row (`CLIENT_REGISTERED`, `RESOURCE_SERVER_REGISTERED`,
`CLIENT_SECRET_ROTATED`, `DIRECTORY_DISABLED`, ...). Changes to a directory config are picked up within 60 s; audience and
resource-server changes within 30-60 s (short in-memory caches).

Not covered by the API yet: editing/deleting an existing application, changing its redirect URIs or audiences.
Use SQL on `oauth2_registered_client` / `client_audience` for those for now.
