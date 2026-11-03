# Application backend contract (Milestone 3)

Your backend is the OAuth2 *confidential client*. Keep `client_id` / `client_secret` only in the backend. The browser or
mobile UI talks to your backend; the backend talks to the auth server. All calls use HTTP Basic client authentication
(`Authorization: Basic base64(client_id:client_secret)`) and form-encoded bodies (POST body only, never the URL).

## 1. Login (your own login screen)

`POST /oauth2/token` with `grant_type=app_login`, `username`, `password`, optional `scope`.
Response: `access_token` (30 min), `refresh_token`, `token_type=Bearer`, `expires_in`, `scope`.
The auth server verifies the credentials against **your** verify service / database.

## 2. Calling your own API

The UI sends `Authorization: Bearer <access_token>` to your API. Validate with `POST /oauth2/introspect`
(`token=...`, client-authenticated). Cache the result until `exp` (or a shorter time). Use `active`, `sub`
(`clientId:userId`), `uid`, `roles`, `aud`, `exp`.

## 3. Refresh

`POST /oauth2/token` with `grant_type=refresh_token`, `refresh_token`. **Store the new refresh token from every response**;
the old one stops working. On a retry caused by a lost response, wait; a re-sent old token within 10 s is simply refused,
after that it revokes the session.

## 4. Logout

`POST /oauth2/revoke` with `token=<refresh_token>`, `token_type_hint=refresh_token`. The access token dies with it.
Browser (central login) sessions can also use `/connect/logout?id_token_hint=...`.

## 5. Sign a user out everywhere (admin)

Get a token: `grant_type=client_credentials&scope=auth.revoke` (the client must be registered with that scope and grant).
`POST /admin/sessions/revoke` with `Authorization: Bearer <token>`, JSON `{"userId":"<your user id>"}`.
Only your own users can be revoked.

## Errors (token endpoint, JSON `{"error","error_description"}`)

| HTTP | error | Meaning / what to do |
|---|---|---|
| 400 | `invalid_grant` | Wrong username/password, or the refresh token is invalid/expired/revoked, or the session ended. Ask the user to log in again |
| 400 | `invalid_grant` + `account_locked` / `account_disabled` / `password_expired` | Account state from your directory |
| 400 | `invalid_request`, `invalid_scope`, `unauthorized_client`, `unsupported_grant_type` | Fix the request / client registration |
| 401 | `invalid_client` | Wrong client id or secret |
| 429 | `too_many_attempts` | Too many failed logins; wait `Retry-After` seconds |
| 503 | `temporarily_unavailable` | Your directory could not be reached. The refresh token was **not** consumed; retry shortly |
| 500 | `server_error` | Auth server problem |

## Registering the client

The client needs grants `app_login`, `refresh_token` (and `client_credentials` for the admin call), authentication
method `client_secret_basic`, scopes it may request (`openid` and any `auth.*` scope are never granted through `app_login`),
and `refresh_token_time_to_live` equal to the idle timeout. The dev seed (`DevSeedRunner`) is a worked example.
