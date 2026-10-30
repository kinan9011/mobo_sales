# Odoo 2FA (TOTP) login without a WebView

Playbook for mobile apps that sign in to Odoo. Written from mobo_sales; the same steps apply to the other Odoo apps.
Reference implementation: `lib/services/odoo_totp_login.dart`, UI in `lib/screens/login/totp_page.dart`,
tests in `test/odoo_totp_login_test.dart`.

## The flow

Plain HTTP requests through the app's shared client (`SharedHttp.client`, so the Cloudflare Access header and timeouts
apply) with a small cookie jar of its own. No WebView, no JS.

1. `GET /web/login?db=<db>` — binds the database to the `session_id` cookie. If Odoo redirects to
   `/web/database/...` (db selector) fall back to `GET /web?db=<db>`.
2. `POST /web/session/authenticate` (JSON-RPC, `params: {db, login, password}`):
   - `error` → wrong credentials (`Access Denied` → "Wrong login/password").
   - `result.uid` is an int → account has no 2FA, session is already signed in.
   - `result.uid` is `null` → password accepted, 2FA pending in the session.
3. `GET /web/login/totp` → parse the form (`csrf_token`, `totp_token`, ...) with `parseForm`.
4. `POST` the form with `totp_token=<code>`:
   - page again with an `.alert` → wrong code, keep the form, user retries.
   - `303 → /odoo` + new `session_id` cookie → success; hand the `session_id` to the normal session setup.

Redirects are followed by hand (max 5) and **never leave the server origin**. Same-host `http://` hops are upgraded to
`https://` (Odoo without a correct proxy config emits absolute `http://` redirects).

## Why not post the HTML login form (`POST /web/login`)

Odoo 19 `web_login` runs `_verify_request_recaptcha_token('login')` for every password login. With Cloudflare Turnstile
(`website_cf_turnstile`) or reCAPTCHA configured, a form post without the browser-generated token is refused with
**HTTP 422**. A WebView passes because it runs the captcha JS; plain HTTP cannot.
`/web/session/authenticate` and `/web/login/totp` have no captcha check — this is the route Odoo's official mobile app
uses (the source even documents the `{'uid': None}` answer for 2FA users).

Symptom in the app: "Invalid code or login failed" / "Odoo ended the login session" right after pressing Authenticate,
while the browser login works.

## Diagnosing a failing server

The login keeps a short hop trace (`METHOD path status>location [cookie names]`, no cookie values or bodies). It is
printed with `debugPrint('[OdooTotpLogin] ...')` and appended to the "Odoo ended the login session" error.

| Trace | Meaning |
|-------|---------|
| `POST /web/login 422` | Login captcha is on (the old form flow) |
| `POST /web/login/totp 303>/web/login` | Session lost before the code check (cookie not kept) |
| `GET /odoo 303>/web/login...` after a good code | Session rejected after login (auth addon / session check) |
| redirect to another host | Host switch (two domains on one Odoo); refused on purpose |

Server side, usual suspects behind Cloudflare + Traefik: `--proxy-mode` set, Traefik forwarding
`X-Forwarded-Host/Proto` (trust Cloudflare IPs in `forwardedHeaders.trustedIPs`), one session store for all workers.

## Reproducing locally (Odoo 19)

```bash
docker network create t && docker run -d --name pg --network t \
  -e POSTGRES_USER=odoo -e POSTGRES_PASSWORD=odoo -e POSTGRES_DB=postgres postgres:16
docker run --rm --network t -e HOST=pg -e USER=odoo -e PASSWORD=odoo odoo:19.0 \
  odoo -d t -i auth_totp,website_cf_turnstile --without-demo --stop-after-init
# 2FA secret + a dummy captcha key (turns the 422 on)
docker exec pg psql -U odoo -d t \
  -c "UPDATE res_users SET totp_secret='JBSWY3DPEHPK3PXP' WHERE login='admin';" \
  -c "INSERT INTO ir_config_parameter(key,value,create_date,write_date) VALUES
      ('cf.turnstile_secret_key','1x0000000000000000000000000000000AA',now(),now())"
docker run -d --name odoo --network t -p 8069:8069 -e HOST=pg -e USER=odoo -e PASSWORD=odoo \
  odoo:19.0 odoo -d t --db-filter '^t$'
```

Admin password is `admin`. Generate the 6-digit code from the base32 secret (RFC 6238, SHA-1, 30 s). `odoo shell` with
stdin hangs in this image; set the secret with SQL as above. Clean up with `docker rm -f odoo pg; docker network rm t`.

## Porting to another Odoo app

1. Copy `odoo_totp_login.dart` (it only needs `package:http` and `debugPrint`) and its test file.
2. Give it the app's shared HTTP client so Cloudflare Access / proxies behave like every other request.
3. Replace the WebView step of the 2FA screen with `start()` → `submitCode()`; on `TotpLoginSuccess(sessionId)` continue
   with the app's usual "session id → session model" setup.
4. Use the `OdooTotpLogin` group in the tests as the contract (captcha-guarded `/web/login` returns 422 and must never be
   posted to).

Gotchas: show the specific failure messages (they name the failing step); a full restart is needed after changing
service code; Odoo ≤ 16 has the same two routes but verify the `/web/session/authenticate` 2FA answer on the target
version before relying on it.
