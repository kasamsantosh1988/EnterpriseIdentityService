# Hand-off: sending a signed-in user from one application to another

Use it when app1's page links to an app2 page and app2 has no user list of its own (its callers are partners with client
credentials). App1 vouches for its user; the auth server gives app2 a short-lived token for that user.

## Flow

1. The user is signed in to app1 (app1 holds the user's access token in its backend or gateway).
2. App1's backend calls `POST /oauth2/handoff` with its client id and secret (HTTP Basic):

   ```json
   { "targetClientId": "demo-app2", "subjectToken": "<user's access token>", "context": "ENC(proposal=P123;quote=Q9)" }
   ```

   Answer: `{ "code": "...", "expires_in": 60 }` (`Cache-Control: no-store`). The context is opaque to the platform
   (printable ASCII, up to 2048 characters). Encrypt it yourself if it is sensitive; it is kept until the code is used.
3. App1 redirects the browser: `http://app2/xyz?handoff=<code>`.
4. App2's gateway redeems the code: token endpoint, `grant_type=handoff`, `code`, `scope`, client authentication with app2's
   id and secret. It gets an access token (30 minutes, audience of app2, no refresh token) and the extra fields `sub`,
   `src` (the source application), `roles` (space separated) and `context`. It then redirects to the same URL without the code.
5. The app2 page calls `POST /me/context` once to read the context.

## What the auth server checks

| Step | Check |
| --- | --- |
| Issue | caller authenticated; token active and issued to the caller; token comes from `app_login` or `authorization_code`; subject starts with `<caller>:`; target exists and has the `handoff` grant; **app1 lists app2 in `handoffTargets` and app2 lists app1 in `acceptsHandoffFrom`**; context size |
| Code | 256-bit random, stored only as SHA-256, one use, 60 s (`authserver.handoff.code-ttl`) |
| Redeem | code unused and unexpired, issued for this target, redeemer authenticated as the target and holding the `handoff` grant, link re-checked, scopes registered for the target (no `openid`, no `auth.*`) |
| Token | subject `app1:userId`, roles from app1, claim `src=app1`; a handed-off token cannot be handed off again |

Every issue, denial and redemption is written to the audit table (`HANDOFF_ISSUED`, `HANDOFF_DENIED`, `HANDOFF_REDEEMED`,
`HANDOFF_REDEEM_FAILED`, `HANDOFF_LINKS_CHANGED`).

## Registration

Register the target with grant `handoff` and `acceptsHandoffFrom`, the source with `handoffTargets`:

```json
POST /admin/apps  { "clientId": "app2", "grants": ["handoff"], "scopes": ["app2.ui"], "audiences": ["app2-api"],
                    "acceptsHandoffFrom": ["app1"] }
POST /admin/apps/app1/handoff-links  { "handoffTargets": ["app2"] }
GET  /admin/apps/app1/handoff-links
```

In `handoff-links`, a missing field is left unchanged and `[]` clears it. Removing either side stops new hand-offs at once.
Revoking a user of app1 (`revokeAllFor`) also revokes the tokens app2 received for that user.

## Limits

* A handed-off session lasts the access token's 30 minutes and cannot be refreshed (app2 has no directory to re-check the
  user against). After that app1 must hand off again.
* The context is delivered once, to the first `/me/context` call of that session.
* The code is only valid for the application it was issued for, but anyone holding it within 60 s and the target's secret can
  redeem it; the secret stays in app2's gateway.
* Not compiled or run yet. Check the Spring Authorization Server API names used in `grant/Handoff*` first.
