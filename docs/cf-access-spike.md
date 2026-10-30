# Cloudflare Access Managed OAuth: Phase 0 spike runbook

Gate for the "Cloudflare Access native login" work. No app code is written until this passes.
Run by hand against a **staging** Access app on `odoo.swovo.de` (team domain `kiah.cloudflareaccess.com`).

Source rules:
- Facts come from the master plan (`Cloudflare Access native login for mobo_sales`).
- Anything the master plan does not document is marked **TEST**: run it, record the real answer, do not trust the "expected" value.
- No secrets in this file. Tokens live only in shell variables of your terminal session. Do not paste them anywhere.

Docs (from the master plan):
- <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/>
- <https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authenticate-agents/>

## Prerequisites

- A staging Access application (self-hosted) for `odoo.swovo.de`. Use a copy of the app or a staging policy so production Bypass rules stay untouched.
- A test user who passes the app's Allow policy (Google or email OTP).
- Tools: `curl`, `jq`, `openssl`, `base64`, a desktop browser.
- Shell access to the Traefik host (step 9) and an Odoo test login (step 10).

## Shell variables

Paste once. Re-paste after opening a new terminal.

```bash
export HOST="odoo.swovo.de"
export TEAM="kiah.cloudflareaccess.com"
# Placeholder callback from the master plan; must match the allowed redirect URI set in step 1.
export REDIRECT="https://auth.swovo.de/oauth/callback"
export ODOO_DB="<your_odoo_db>"
export ODOO_LOGIN="<test_odoo_user>"
# Password is read without echo at step 10, never written down.
```

---

## 1. Enable Managed OAuth (dashboard)

Master plan: Managed OAuth is a toggle on the existing self-hosted Access app (open beta, all plans, per app). It is not a separate login system.

Dashboard path (exact labels: **TEST**, the UI may differ):

1. Cloudflare dashboard → **Zero Trust** → **Access** → **Applications**.
2. Open the staging app for `odoo.swovo.de` → **Edit**.
3. **Advanced settings** → **Managed OAuth** → **On**.
4. Set:
   - Allowed redirect URIs: `https://auth.swovo.de/oauth/callback` (same value as `$REDIRECT`)
   - Access token lifetime: `15 min`
   - Grant session duration: `14 days`
   - Allow localhost / loopback redirects: **Off**
5. Save.
6. Confirm the app still has an Allow policy for your test user and **no Bypass** policy covering `/web/webclient/version_info`, `/web/session/*`, `/web/dataset/*` (otherwise step 2 returns 200 and proves nothing).

Expected: setting saves; browser visits to `https://odoo.swovo.de` still show the normal `kiah.cloudflareaccess.com` login page.

Record: exact UI labels, any option not listed above, whether a "resource" or audience setting exists (**TEST**).

---

## 2. Discovery probe: 401 + `WWW-Authenticate`

```bash
curl -si "https://$HOST/web/webclient/version_info" | tee /tmp/cf-probe.txt | head -20
grep -i '^www-authenticate' /tmp/cf-probe.txt
```

Expected (master plan, app flow step 2):
- `HTTP/2 401`
- `www-authenticate: Bearer resource_metadata="https://…"`

Interpretation:
- `302` to `*.cloudflareaccess.com` → Managed OAuth is off (or an app/policy mismatch). Fix step 1.
- `200` → a Bypass policy still matches this path. Remove it for staging.

Save the `resource_metadata` URL:

```bash
export RESOURCE_META="$(grep -i '^www-authenticate' /tmp/cf-probe.txt | sed -E 's/.*resource_metadata="([^"]+)".*/\1/' | tr -d '\r')"
echo "$RESOURCE_META"
```

Expected: a non-empty `https://` URL.

---

## 3. Discovery: resource metadata and authorization-server metadata

```bash
curl -s "$RESOURCE_META" | tee /tmp/cf-resource-meta.json | jq .
```

Expected: JSON naming the authorization server(s) (RFC 9728 style `authorization_servers` array). Field names: **TEST**.

```bash
export ISSUER="$(jq -r '.authorization_servers[0]' /tmp/cf-resource-meta.json)"
echo "$ISSUER"
curl -s "$ISSUER/.well-known/oauth-authorization-server" | tee /tmp/cf-as-meta.json | jq .
```

Expected: JSON with `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `revocation_endpoint`, `code_challenge_methods_supported` containing `S256`, `grant_types_supported` containing `authorization_code` and `refresh_token`.

If the `$ISSUER` path differs (for example it already includes `/.well-known/…`, or lives on `$TEAM`), try these and record which works (**TEST**):

```bash
curl -s "https://$HOST/.well-known/oauth-authorization-server" | jq .
curl -s "https://$TEAM/.well-known/oauth-authorization-server" | jq .
```

Extract the endpoints:

```bash
export AUTHZ_EP="$(jq -r '.authorization_endpoint' /tmp/cf-as-meta.json)"
export TOKEN_EP="$(jq -r '.token_endpoint' /tmp/cf-as-meta.json)"
export REG_EP="$(jq -r '.registration_endpoint' /tmp/cf-as-meta.json)"
export REVOKE_EP="$(jq -r '.revocation_endpoint' /tmp/cf-as-meta.json)"
printf 'authz=%s\ntoken=%s\nreg=%s\nrevoke=%s\n' "$AUTHZ_EP" "$TOKEN_EP" "$REG_EP" "$REVOKE_EP"
```

Expected: four non-`null` `https://` URLs.

---

## 4. Dynamic client registration (DCR) with an https redirect

Master plan: public client, `token_endpoint_auth_method: none`, redirect URI must be `https`.

```bash
curl -s -X POST "$REG_EP" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg r "$REDIRECT" '{
        client_name: "mobo-sales-spike",
        redirect_uris: [$r],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code","refresh_token"],
        response_types: ["code"]
      }')" | tee /tmp/cf-dcr.json | jq .
export CLIENT_ID="$(jq -r '.client_id' /tmp/cf-dcr.json)"
echo "$CLIENT_ID"
```

Expected: `201`-style JSON with a `client_id` and no `client_secret`. Request fields beyond `redirect_uris` and `token_endpoint_auth_method` are **TEST** (the server may reject or ignore `grant_types`, `response_types`, `client_name`).

Fail signals: `invalid_redirect_uri` for the https URI (check the allow-list from step 1), or a requirement for authentication on the registration endpoint (**TEST**).

---

## 5. PKCE verifier, S256 challenge, state

```bash
# 43-char base64url verifier (RFC 7636 allows 43-128)
export VERIFIER="$(openssl rand 32 | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
# challenge = BASE64URL(SHA256(verifier))
export CHALLENGE="$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
export STATE="$(openssl rand -hex 16)"
echo "verifier len: ${#VERIFIER}"; echo "challenge: $CHALLENGE"; echo "state: $STATE"
```

Sanity check against the RFC 7636 appendix B vector:

```bash
printf '%s' 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='; echo
```

Expected: `verifier len: 43`, and the vector prints `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`.

---

## 6. Authorize in the browser (system browser, PKCE)

Build the URL (`resource` is **TEST**: the master plan says tokens look bound to one hostname via the `resource` parameter, but the exact requirement is undocumented):

```bash
AUTH_URL="$AUTHZ_EP?response_type=code&client_id=$CLIENT_ID&redirect_uri=$(jq -rn --arg v "$REDIRECT" '$v|@uri')&code_challenge=$CHALLENGE&code_challenge_method=S256&state=$STATE&resource=$(jq -rn --arg v "https://$HOST" '$v|@uri')"
echo "$AUTH_URL"
xdg-open "$AUTH_URL" 2>/dev/null || open "$AUTH_URL"
```

In the browser:
1. Sign in with the test user (Google / email OTP). This is the same `kiah.cloudflareaccess.com` login page as for normal browser users.
2. You are redirected to `https://auth.swovo.de/oauth/callback?code=…&state=…`. The page itself may 404 or be blank (no callback page exists yet): that is fine. **Read the address bar.**

Copy `code` and `state` out of the address bar:

```bash
read -r -p 'Paste the full redirected URL: ' CB_URL
export CODE="$(printf '%s' "$CB_URL" | sed -E 's/.*[?&]code=([^&]+).*/\1/')"
CB_STATE="$(printf '%s' "$CB_URL" | sed -E 's/.*[?&]state=([^&#]+).*/\1/')"
[ "$CB_STATE" = "$STATE" ] && echo "state OK" || echo "STATE MISMATCH"
```

Expected: `state OK`; `$CODE` non-empty.

SSO re-check: repeat the `xdg-open` with a fresh `STATE`/`CHALLENGE` (step 5) in the same browser within the global session lifetime. Expected: no login prompt, straight redirect with a new `code` (master plan: global session on `$TEAM` gives single sign-on).

Record: whether the callback host needed to resolve or serve anything (**TEST**), and whether authorization codes are single-use and how long they live (**TEST**).

---

## 7. Token exchange

```bash
curl -s -X POST "$TOKEN_EP" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "resource=https://$HOST" | tee /tmp/cf-token.json | jq 'del(.access_token,.refresh_token)'
export AT="$(jq -r '.access_token' /tmp/cf-token.json)"
export RT="$(jq -r '.refresh_token' /tmp/cf-token.json)"
printf 'access prefix: %s\nexpires_in: %s\nrefresh present: %s\n' "${AT:0:12}" "$(jq -r '.expires_in' /tmp/cf-token.json)" "$([ -n "$RT" ] && [ "$RT" != null ] && echo yes || echo no)"
```

Expected (master plan):
- `token_type` Bearer; `access_token` begins `oauth:` (client sends `Authorization: Bearer oauth:<opaque>`).
- `expires_in` about `900` (15 min).
- A `refresh_token` is present.

**TEST:** whether `resource` is accepted/required on the token call, and the exact token field names.

Negative check (single-use code): repeat the same command a second time. Expected: `invalid_grant`.

Cleanup of token file when done: `shred -u /tmp/cf-token.json` (or `rm`).

---

## 8. Bearer call through Access

`/web/session/get_session_info` is a JSON-RPC route in Odoo, so POST an empty `call`.

```bash
curl -si -X POST "https://$HOST/web/session/get_session_info" \
  -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"call","params":{}}' | head -30
```

Expected: Access lets the request through, and **Odoo** answers (HTTP `200` with a JSON-RPC body such as a `result` with `uid: null`, or an Odoo `error` object). Not a `401`/`403`/`302` from Cloudflare.

Negative controls (expected: Cloudflare rejects):

```bash
curl -s -o /dev/null -w 'no token: %{http_code}\n' -X POST "https://$HOST/web/session/get_session_info" \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"call","params":{}}'
curl -s -o /dev/null -w 'forged token: %{http_code}\n' -X POST "https://$HOST/web/session/get_session_info" \
  -H 'Authorization: Bearer oauth:forged' \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"call","params":{}}'
```

Expected: `no token: 401`, `forged token: 401`.

---

## 9. Does `Authorization` reach the origin? (Traefik)

Master plan: unverified in docs, must be tested. Outcome decides whether the Traefik "strip `bearer oauth:`" router is needed. Run **A or B**.

### 9A. `whoami` container behind the same Access app

On the Traefik host, temporary compose service and route (adjust entrypoint/cert resolver names to your setup, **TEST**):

```yaml
# docker-compose.whoami.yml
services:
  whoami:
    image: traefik/whoami
    labels:
      - traefik.enable=true
      - traefik.http.routers.whoami-spike.rule=Host(`odoo.swovo.de`) && PathPrefix(`/__whoami`)
      - traefik.http.routers.whoami-spike.priority=200
      - traefik.http.routers.whoami-spike.entrypoints=web
      - traefik.http.services.whoami-spike.loadbalancer.server.port=80
```

```bash
docker compose -f docker-compose.whoami.yml up -d
curl -s "https://$HOST/__whoami" -H "Authorization: Bearer $AT" | grep -iE '^(authorization|cf-access-jwt-assertion|cf-access-authenticated-user-email):' | sed -E 's/(Authorization: Bearer ?.{12}).*/\1…/I'
```

Expected: see which headers arrive.
- `Cf-Access-Jwt-Assertion:` present (master plan: Access forwards the user identity JWT).
- `Authorization:` present or absent: **TEST**. This is the open question.

### 9B. Traefik access log (no extra container)

Static config:

```yaml
accessLog:
  fields:
    headers:
      defaultMode: drop
      names:
        Authorization: redact
        Cf-Access-Jwt-Assertion: keep
```

`redact` shows `REDACTED` when the header is present, without leaking the token into the log. Send the step 8 request, then:

```bash
docker logs traefik --tail 20 | grep get_session_info
```

Expected: the log entry shows `request_Authorization: "REDACTED"` if it reached Traefik, and no such field if Access stripped it (**TEST**).

Decision for this step:
- `Authorization` reaches origin **and** Odoo rejects/mishandles it (step 8/10 body is an error about the header) → deploy the strip router from the master plan (router `odoo-cf-bearer`, `HeaderRegexp(Authorization, (?i)^bearer oauth:)`, priority 100, middleware sets `Authorization: ""`). Odoo API keys are left alone.
- `Authorization` stripped by Access, or forwarded and Odoo ignores it → no Traefik change.

Cleanup: `docker compose -f docker-compose.whoami.yml down` and revert the log config.

---

## 10. `call_kw` with bearer + `session_id` cookie

Master plan: the app authenticates to Odoo with the `session_id` cookie, never with `Authorization`, so the Cloudflare bearer and the Odoo session travel side by side.

```bash
read -r -s -p 'Odoo password: ' ODOO_PW; echo
rm -f /tmp/cf-odoo.jar
curl -s -c /tmp/cf-odoo.jar -X POST "https://$HOST/web/session/authenticate" \
  -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg db "$ODOO_DB" --arg l "$ODOO_LOGIN" --arg p "$ODOO_PW" '{jsonrpc:"2.0",method:"call",params:{db:$db,login:$l,password:$p}}')" \
  | jq '{uid: .result.uid, error: .error.message}'
unset ODOO_PW
grep session_id /tmp/cf-odoo.jar | awk '{print "cookie session_id present, domain:", $1}'
```

Expected: `uid` is a number; `session_id` cookie present in the jar.

```bash
curl -s -b /tmp/cf-odoo.jar -X POST "https://$HOST/web/dataset/call_kw/res.users/search_read" \
  -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"call","params":{"model":"res.users","method":"search_read","args":[[]],"kwargs":{"fields":["name"],"limit":1}}}' | jq .
```

Expected: `result` is an array with one user record.

Negative controls:

```bash
# cookie only, no bearer: Access must block
curl -s -o /dev/null -w 'cookie, no bearer: %{http_code}\n' -b /tmp/cf-odoo.jar -X POST "https://$HOST/web/dataset/call_kw/res.users/search_read" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"call","params":{"model":"res.users","method":"search_read","args":[[]],"kwargs":{"limit":1}}}'
# bearer only, no cookie: Odoo must refuse (session expired / access denied)
curl -s -X POST "https://$HOST/web/dataset/call_kw/res.users/search_read" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"call","params":{"model":"res.users","method":"search_read","args":[[]],"kwargs":{"limit":1}}}' | jq '.error.data.name // .error.message'
```

Expected: `cookie, no bearer: 401`; bearer only returns an Odoo session/access error.

**TEST:** that the same Odoo `session_id` cookie keeps working after the bearer is refreshed (step 11).

---

## 11. Refresh

```bash
curl -s -X POST "$TOKEN_EP" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "refresh_token=$RT" \
  --data-urlencode "resource=https://$HOST" | tee /tmp/cf-refresh.json | jq 'del(.access_token,.refresh_token)'
OLD_AT="$AT"; OLD_RT="$RT"
export AT="$(jq -r '.access_token' /tmp/cf-refresh.json)"
NEW_RT="$(jq -r '.refresh_token // empty' /tmp/cf-refresh.json)"
[ -n "$NEW_RT" ] && export RT="$NEW_RT"
echo "new access prefix: ${AT:0:12}"; echo "refresh rotated: $([ -n "$NEW_RT" ] && [ "$NEW_RT" != "$OLD_RT" ] && echo yes || echo no)"
```

Expected: new access token, `expires_in` about `900`. Master plan: policies are re-checked on every refresh.

**TEST:**
- Does the refresh token rotate (new value returned)? If yes, is the old one rejected on reuse?
- Does the old access token still work until expiry?

```bash
# old refresh token reuse (only meaningful if it rotated)
curl -s -X POST "$TOKEN_EP" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=refresh_token" --data-urlencode "client_id=$CLIENT_ID" --data-urlencode "refresh_token=$OLD_RT" | jq '{error, error_description}'
# old access token
curl -s -o /dev/null -w 'old access: %{http_code}\n' -X POST "https://$HOST/web/session/get_session_info" \
  -H "Authorization: Bearer $OLD_AT" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"call","params":{}}'
```

Re-run the step 10 `search_read` with the new `$AT` and the existing cookie jar. Expected: still a result.

Optional (15 min wait): after `expires_in` elapses, a call with the expired access token. Expected: `401` carrying `WWW-Authenticate` (master plan: refresh-on-401 design).

```bash
curl -si -X POST "https://$HOST/web/session/get_session_info" -H "Authorization: Bearer $OLD_AT" \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"call","params":{}}' | grep -iE '^(HTTP|www-authenticate)'
```

---

## 12. Redirect-URI acceptance (https App Link vs custom scheme)

Master plan: dynamically registered clients must use `https` (or localhost/loopback if the admin allows it). Custom schemes such as `com.x.app:/cb` are not accepted, so the app needs an Android App Link / iOS Universal Link.

```bash
reg() { curl -s -o /tmp/cf-reg-out.json -w "$1 -> HTTP %{http_code}\n" -X POST "$REG_EP" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg r "$2" '{client_name:"mobo-sales-spike-uri",redirect_uris:[$r],token_endpoint_auth_method:"none"}')"; jq -c '{client_id, error, error_description}' /tmp/cf-reg-out.json; }

reg "https allow-listed (step 1)"   "$REDIRECT"
reg "https NOT allow-listed"        "https://not-allowed.example.com/oauth/callback"
reg "custom scheme"                 "com.mobo.sales:/oauth/callback"
reg "http loopback"                 "http://127.0.0.1:8765/oauth/callback"
reg "http (non-loopback)"           "http://auth.swovo.de/oauth/callback"
```

Expected:
- https allow-listed: accepted, returns `client_id`.
- custom scheme: rejected (`invalid_redirect_uri` or similar).
- http loopback: rejected (loopback is **Off** in step 1).
- http non-loopback: rejected.
- https not allow-listed: **TEST** (rejected at registration, or only at authorize?). Try the authorize step with it if registration accepts.

Not testable here: the https redirect completing end to end on a phone (App Link verified via `assetlinks.json` / AASA opens the app). That needs the callback domain files and app intent filter, which is Phase 1. Record it as "deferred to Phase 1" in the results table. This is the master plan's open item (b).

---

## 13. Revoke

```bash
curl -si -X POST "$REVOKE_EP" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "token=$RT" \
  --data-urlencode "token_type_hint=refresh_token" | head -5
```

Expected: `200` (RFC 7009 returns 200 even for unknown tokens). Parameter set (client_id required? Basic auth?) is **TEST**.

Then confirm the refresh token is dead:

```bash
curl -s -X POST "$TOKEN_EP" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=refresh_token" --data-urlencode "client_id=$CLIENT_ID" --data-urlencode "refresh_token=$RT" | jq '{error, error_description}'
```

Expected: `invalid_grant`.

**TEST:** does revoking the refresh token also invalidate the current access token immediately, or does it live until `expires_in`?

```bash
curl -s -o /dev/null -w 'access after revoke: %{http_code}\n' -X POST "https://$HOST/web/session/get_session_info" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"call","params":{}}'
```

---

## 14. Zero Trust → Users → Revoke on a live refresh token

Master plan: revoking an account is "remove the user from the Access group (next refresh ≤15 min fails); for immediate cut-off also Users → Revoke". This step shows what Revoke really does.

1. Repeat steps 5, 6, 7 to obtain a fresh `$AT` / `$RT` (the token from step 13 is dead). Confirm step 8 returns an Odoo answer.
2. Dashboard: **Zero Trust** → **Users** (under *Team & Resources*, **TEST**: label) → open the test user → **Revoke** (labelled "Revoke user" / "Revoke session"; **TEST**).
3. Immediately run:

```bash
echo "--- bearer call (access token, within 15 min) ---"
curl -s -o /dev/null -w 'access after Users>Revoke: %{http_code}\n' -X POST "https://$HOST/web/session/get_session_info" \
  -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"call","params":{}}'
echo "--- refresh ---"
curl -s -X POST "$TOKEN_EP" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=refresh_token" --data-urlencode "client_id=$CLIENT_ID" --data-urlencode "refresh_token=$RT" | jq '{error, error_description}'
echo "--- browser global session ---"
echo "Open https://$HOST in the browser used in step 6: do you get the login page again?"
```

Expected (**TEST**, undocumented in the master plan): refresh fails (`invalid_grant` or `access_denied`). Record separately:
- the access token: dead immediately, or alive until expiry?
- the refresh token: dead immediately, or only at next policy check?
- the browser global session (`CF_Authorization` / `$TEAM` cookie): killed?
- after revoke, can the same user log in again straight away (revoke is not a ban)?

Second variant (policy removal): re-obtain tokens, then remove the test user from the Allow group instead of using Revoke. Expected (master plan): the next refresh fails; the live access token dies by its 15 min expiry.

---

## 15. Cleanup

```bash
shred -u /tmp/cf-token.json /tmp/cf-refresh.json /tmp/cf-odoo.jar /tmp/cf-reg-out.json /tmp/cf-dcr.json 2>/dev/null
unset AT RT OLD_AT OLD_RT NEW_RT CODE VERIFIER CHALLENGE STATE CLIENT_ID
```

- Remove the `whoami` service/route and revert Traefik access-log header settings (step 9).
- Revoke any remaining spike tokens (step 13 command, or Users → Revoke).
- Delete spike clients if the dashboard lists registered clients (**TEST**: whether it does).
- Restore the staging app's policies if you changed them.

---

## Results (fill in)

| # | Question | Expected | Actual | Pass? |
|---|----------|----------|--------|-------|
| 1 | Managed OAuth toggle available on the app; redirect URI allow-list, 15 min / 14 d lifetimes settable | Yes; browser users still see the normal login | | |
| 2 | Unauthenticated probe returns 401 + `WWW-Authenticate: Bearer resource_metadata=…` | 401 + header | | |
| 3 | Resource metadata and `/.well-known/oauth-authorization-server` expose authorize/token/registration/revocation endpoints with S256 | All present | | |
| 4 | DCR with https redirect and `token_endpoint_auth_method:none` returns `client_id` | `client_id`, no secret | | |
| 5 | PKCE S256 generation matches RFC 7636 vector | `E9Melhoa…` | | |
| 6 | System-browser authorize with PKCE returns `code` + matching `state`; second authorize is silent (SSO) | `state OK`; no prompt on repeat | | |
| 7 | Token exchange returns `oauth:` access token (~900 s) and refresh token; code is single-use | Yes; replay → `invalid_grant` | | |
| 8 | `Authorization: Bearer` passes Access; no/forged token blocked | Odoo answers; no token and forged → 401 | | |
| 9 | `Authorization` header reaches Traefik/origin (TEST) | Report: yes / no. `Cf-Access-Jwt-Assertion` present | | |
| 10 | Odoo `authenticate` + `call_kw` work with bearer + `session_id` cookie; cookie alone or bearer alone fail | Result record; cookie only → 401; bearer only → Odoo error | | |
| 11 | Refresh returns new access token; rotation behavior and old-token behavior recorded (TEST); cookie still valid | New token; Odoo call still works | | |
| 12 | Redirect URIs: https allow-listed accepted; custom scheme, http, loopback rejected | Accepted / rejected. App Link on phone deferred to Phase 1 | | |
| 13 | Revoke: 200, then refresh → `invalid_grant`; access token fate recorded (TEST) | 200; `invalid_grant` | | |
| 14 | Users → Revoke on live refresh token (TEST) | Refresh fails; record access-token, global-session and re-login behavior | | |

## Decision rule

- All of steps 1 to 8, 10 to 13 pass, and step 12 shows the https redirect URI is accepted: **proceed to Phase 1** (Managed OAuth + system-browser SSO).
- **If any step fails**, use the fallback from the master plan: **Access for SaaS (OIDC) + Linked App Token**. Same client code with a manual `client_id`, registered by hand per service, same `Authorization: Bearer` header.
- Step 9 (does `Authorization` reach origin) does not trigger the fallback by itself. It only decides whether the Traefik strip router (`odoo-cf-bearer`) is deployed. If Authorization is forwarded and Odoo breaks on it, deploy the strip router; if not, no Traefik change.
- Step 14 is informational for the revocation procedure (is Users → Revoke instant or only at next refresh?). It does not trigger the fallback. If Revoke does not kill refresh tokens, shorten the grant session duration and document group removal as the primary cut-off.
- Step 12's end-to-end phone App Link check is verified in Phase 1. If it fails there, the fallback applies at that point.
