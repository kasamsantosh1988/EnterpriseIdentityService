# Connecting an application's user directory

Each application keeps its own users and passwords. The auth server only asks the application two questions:
**"is this username/password valid?"** (login) and **"is this user still active, and what are their roles?"** (used on refresh,
Milestone 3). There are two ways to answer, chosen per client in `client_directory_config`.

Every login is for one registered client (the `client_id` in the `/oauth2/authorize` request). The server looks up that
client's directory, so users of different applications never mix. The token subject is `<client_id>:<userId>`.

## Option 1: REMOTE - the application exposes a verify service (recommended)

The application's rules (hashing, lockout counters, password expiry) stay inside the application.

**Login:** `POST <verify_url>`  with header `X-Auth-Server-Key: <shared key>` and JSON body

```json
{ "username": "alice", "password": "...", "clientId": "demo-ui", "ipAddress": "10.1.2.3" }
```

Always answer **HTTP 200** with a JSON body, including for bad credentials:

```json
{ "status": "SUCCESS", "userId": "1001", "displayName": "Alice Example", "roles": ["USER"], "active": true }
{ "status": "INVALID_CREDENTIALS" }
```

`status` is one of `SUCCESS`, `INVALID_CREDENTIALS`, `LOCKED`, `EXPIRED`, `MUST_CHANGE_PASSWORD`, `DISABLED`.
Anything else is treated as an error and login fails closed. Return `LOCKED`/`DISABLED`/`EXPIRED` only after the
password was verified, so the answer does not reveal account state to someone who does not know the password.
Count failed attempts in the application as you do today; the request carries `ipAddress` for that purpose.

Any non-200 response, timeout or unreadable body is treated as "directory unavailable" (the user sees a try-again
message, and it is audited as an error), never as "wrong password". A 401 means your key was rejected.

**Status lookup (used by refresh, Milestone 3):** `POST <status_url>` with the same header and body `{ "userId": "1001" }`.
Answer 200 with the same JSON shape (`status` = `SUCCESS` means the user is active), or **404** if the user no longer exists.

**Security requirements**
- `verify_url` / `status_url` must be `https` (plain `http` is accepted only for `localhost`). Redirects are never followed.
- Protect the endpoints: require the `X-Auth-Server-Key` header, compare it in constant time, and ideally also restrict by
  network address. Do not log request bodies (they contain the password).
- The shared key is not stored in the database. `verify_secret_ref` names it, and the value is read from the property
  `authserver.secrets.<ref>` - in production an environment variable, e.g. `AUTHSERVER_SECRETS_ILOUNGE_VERIFY`
  for the ref `ilounge-verify`.

## Option 2: JDBC - the auth server queries the application database

Use only when an application cannot expose a verify service. It couples the auth server to that application's table design
and password hash format, and puts a database credential in the auth server. Use a **read-only** database account.

Both queries must return exactly these columns (names are not case-sensitive):

| column | meaning |
|---|---|
| `user_id` | the application's own user id (becomes the `uid` claim) |
| `password_hash` | the stored hash (not used by the status query, but the column must exist) |
| `display_name` | shown name; may be null |
| `status` | `ACTIVE`, `LOCKED`, `EXPIRED`, `MUST_CHANGE_PASSWORD`; anything else (or null) is treated as disabled |
| `roles` | comma-separated roles, e.g. `ADMIN,USER`; may be null |

- `auth_query` takes the named parameter `:username`; `load_query` takes `:userId`.
- Each must be a single `SELECT` (no `;`) returning at most one row. Two matching rows is treated as an error.
- Decide case handling in the query, e.g. `WHERE UPPER(u.username) = UPPER(:username)`.
- `password_hash_type` is `BCRYPT` (plain bcrypt hashes) or `DELEGATING` (`{bcrypt}...`, `{argon2}...`, `{pbkdf2}...`).
  Other formats (salted SHA, MD5, ...) need a new entry in `PasswordVerifiers`; do not guess.

Example:

```sql
-- auth_query
SELECT TO_CHAR(u.id) AS user_id, u.password_hash, u.full_name AS display_name, u.status,
       (SELECT LISTAGG(r.role_name, ',') WITHIN GROUP (ORDER BY r.role_name)
          FROM user_roles r WHERE r.user_id = u.id) AS roles
  FROM app_users u
 WHERE UPPER(u.username) = UPPER(:username)
```

## Registering an application

1. Register the UI as an OAuth client (Authorization Code + PKCE, `refresh_token`). Client ids must not contain `:`.
2. Add its directory:

```sql
INSERT INTO client_directory_config (client_id, directory_type, verify_url, status_url, verify_secret_ref)
VALUES ('ilounge-ui', 'REMOTE', 'https://ilounge.internal/auth/verify', 'https://ilounge.internal/auth/status', 'ilounge-verify');

-- JDBC alternative:
-- INSERT INTO client_directory_config (client_id, directory_type, jdbc_url, jdbc_username, jdbc_secret_ref,
--                                      auth_query, load_query, password_hash_type)
-- VALUES ('ilounge-ui', 'JDBC', 'jdbc:oracle:thin:@//apphost:1521/APPDB', 'auth_reader', 'ilounge-db', '<sql>', '<sql>', 'BCRYPT');
```

3. Set the audience of its tokens (the value the application's API will check later):

```sql
INSERT INTO client_audience (client_id, audience) VALUES ('ilounge-ui', 'ilounge-api');
```

4. Provide the secret (`AUTHSERVER_SECRETS_ILOUNGE_VERIFY` or `..._ILOUNGE_DB`) to the auth server environment.

Changes to `client_directory_config` are picked up within `authserver.directory.config-refresh` (default 60 s);
set `enabled = 0` to switch an application's logins off. `client_audience` changes apply within about a minute.
