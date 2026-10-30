# Cloudflare Access login: rollout runbook

Team domain `kiah.cloudflareaccess.com`. User app `odoo.swovo.de`. New integrations hostname `odoo-api.swovo.de`. Callback host (placeholder) `auth.swovo.de`.
Anything Cloudflare does not document is marked **TEST**: try it and write down what you see.

**Do not start until the spike (`docs/cf-access-spike.md`, steps 1-14) has passed.** If it fails, switch to the Access for SaaS fallback from the master plan.

Shell variables used below:

```bash
export HOST=odoo.swovo.de
export API_HOST=odoo-api.swovo.de
export CB=auth.swovo.de
export TEAM=kiah.cloudflareaccess.com
```

---

## 1. Cloudflare dashboard changes (in this order)

Zero Trust → Access → Applications. Exact labels: **TEST**.

### 1a. New `odoo-api.swovo.de` (integrations)
1. Tunnel: add a public hostname `odoo-api.swovo.de` → same service as `odoo.swovo.de` (same Traefik/Odoo). Add a Traefik `Host(...)` rule for it (or an extra host in the existing router).
2. Zero Trust → Access → Service credentials → **Service Tokens** → create one token **per integration**. Copy the Client ID and Client Secret once; store them in that integration's secret store.
3. Access → Applications → Add → Self-hosted, domain `odoo-api.swovo.de`:
   - Policy: action **Service Auth**, Include → Service Token → the integration tokens. No Bypass, no Allow-for-users.
   - **Managed OAuth: Off.**
4. The integration then sends all three headers: `CF-Access-Client-Id`, `CF-Access-Client-Secret`, and `Authorization: bearer <odoo_api_key>` (unchanged).
5. Optional: Traefik IP allowlist on that router if the integrations have fixed egress IPs.

### 1b-alt. Classic Access, no Managed OAuth and no `auth.swovo.de`
If Managed OAuth is off, the app signs in through an in-app browser: it shows the normal Access login page, reads the `CF_Authorization` cookie, and sends it as the `cf-access-token` header. Needs only an Allow policy on the Odoo host (`/web/webclient/version_info` not Bypassed); the session duration on the Access app decides how often users log in again. There is no silent refresh: when the cookie expires the app shows the "sign-in expired" dialog. Google as identity provider is refused inside embedded browsers (`403 disallowed_useragent`), so users must pick One-time PIN or another IdP. Check header acceptance: `curl -si https://$HOST/web/webclient/version_info -H "cf-access-token: $JWT"` returns Odoo's 200. Whether iOS keeps the cookie readable via `CookieManager` is **TEST**.

### 1b. `odoo.swovo.de` (users and the app)
Do the steps in this order, and only after section 3 says so.
1. Applications → `odoo.swovo.de` → Edit → Advanced settings → **Managed OAuth: On** (browsers keep working; they still get the normal login page).
   - Allowed redirect URIs: `https://auth.swovo.de/oauth/callback` (exact, https, no trailing slash)
   - Access token lifetime: 15 min
   - Grant session duration: 14 days
   - Allow localhost / loopback redirects: **Off**
2. Policies: one **Allow** policy for the Access group `odoo-users`. Identity providers: Google and One-time PIN.
3. Settings → Session: global session duration 7-30 days (this is the "log in once" window).
4. **The app probes `/web/webclient/version_info` to detect Access. That path must not be Bypassed**, or the app sees a 200 and never asks for the Cloudflare sign-in.
5. DNS for `odoo.swovo.de` and `odoo-api.swovo.de` points **only** to the tunnel (CNAME to `<tunnel-id>.cfargotunnel.com`). Close any public port on the origin host (80/443/8069/Traefik dashboard). Otherwise Access can be bypassed by going to the origin directly.
6. Last step, only in section 3: delete every Bypass policy.

Traefik: if the spike shows Access forwards the app's `Authorization: Bearer oauth:...` to Odoo **and** Odoo rejects it, add the strip-header router from the master plan (it matches only `bearer oauth:` tokens; API keys are untouched). Otherwise add nothing.

---

## 2. Callback host (`auth.swovo.de`)

Static files only, no secrets. Full details: `deploy/auth-callback/README.md`.

1. DNS: `auth.swovo.de` → the Docker host. Valid public HTTPS (Traefik labels in `docker-compose.yml`). It must **not** be behind Cloudflare Access.
2. Fill the placeholders in `deploy/auth-callback/.well-known/`:
   - `assetlinks.json` → `REPLACE_WITH_RELEASE_SHA256_FINGERPRINT`
     ```bash
     keytool -list -v -keystore <release.jks> -alias <keyAlias> | grep SHA256
     # or: cd android && ./gradlew signingReport   (release variant)
     ```
     With Google Play App Signing, add the **App signing key** SHA-256 (Play Console → Setup → App signing) as a second entry. Add the debug fingerprint for local builds. Package name is `com.cybrosys.mobo_sales`.
   - `apple-app-site-association` → `REPLACE_TEAM_ID` (appears twice: `webcredentials` and `applinks`). `ios/Runner.xcodeproj` has `DEVELOPMENT_TEAM = KD8HL2F8P7`; confirm it is the right team. Bundle id `com.cybrosys.mobo-sale`.
   - The `webcredentials` block and `webcredentials:` entitlement were added for the iOS https callback (ASWebAuthenticationSession). Whether Apple requires them is **TEST**; they do no harm.
3. `docker compose up -d` in `deploy/auth-callback/`.
4. Verify (no redirect, JSON content type):
   ```bash
   curl -si https://$CB/.well-known/assetlinks.json | head -n 8
   curl -si https://$CB/.well-known/apple-app-site-association | head -n 8
   curl -si https://$CB/oauth/callback | head -n 5
   adb shell pm get-app-links com.cybrosys.mobo_sales    # after installing a release build: verified
   ```
5. If the host is not `auth.swovo.de`, change all of: `lib/services/cf_access/cf_access_config.dart`, `android/app/src/main/AndroidManifest.xml`, `ios/Runner/Runner.entitlements` (both entries), `docker-compose.yml`, and the redirect URI in 1b.

---

## 3. Production cut-over order

1. **Move integrations** to `odoo-api.swovo.de` (1a). Confirm each one works there with its service token. Leave the old Bypass rules in place meanwhile.
2. **Enable Managed OAuth** on `odoo.swovo.de` (1b steps 1-5). Browsers are unaffected. Check the existing app build still works (Bypass is still on).
3. **Ship the new app** (Play Store and App Store). Include the SHA-256 and Team ID from section 2.
4. **Wait for adoption.** Set a minimum supported version and tell users to update. Old builds stop working at step 5.
5. **Delete the Bypass rules last.** Re-run the security tests in section 4 right after.

Users who upgrade while still logged in have no Cloudflare tokens yet. After step 5 the first call that gets a Managed OAuth 401 shows the "Your organization sign-in expired" dialog, and "Sign in" opens the browser. Confirm this once on a device (section 5, upgrade test).

Rollback: re-add the Bypass rule for the paths the app uses (`/web/webclient/version_info`, `/web/session/*`, `/web/dataset/*`, `/web/database/*`, `/web/image/*`, `/web/content/*`, `/report/*`). Turning Managed OAuth off alone makes the app show "Managed OAuth is not enabled" on new sign-ins.

---

## 4. Security tests (checklist)

Run after step 5 (and once before it for the `odoo-api` rows).

- [ ] **Unauthenticated call is blocked** (repeat for each formerly bypassed path):
  ```bash
  for p in /web/webclient/version_info /web/session/authenticate /web/database/list /web/dataset/call_kw /web/image/res.partner/1/image_128 /web/content/1 /jsonrpc; do
    printf "%s -> " $p; curl -s -o /dev/null -w "%{http_code}\n" -X POST https://$HOST$p -H 'Content-Type: application/json' -d '{}'
  done
  # expect 401 (with www-authenticate: Bearer resource_metadata=...) or 403; a 302 to cloudflareaccess.com means Managed OAuth is off
  curl -si https://$HOST/web/webclient/version_info | grep -i '^www-authenticate'
  ```
- [ ] **Forged or expired bearer**:
  ```bash
  curl -s -o /dev/null -w "%{http_code}\n" https://$HOST/web/webclient/version_info -H 'Authorization: Bearer oauth:not-a-real-token'
  curl -s -o /dev/null -w "%{http_code}\n" https://$HOST/web/webclient/version_info -H 'Authorization: Bearer eyJhbGciOiJub25lIn0.e30.'
  # expect 401 / 403 for both. Also try an access token older than 15 min from a test device (TEST: expect 401).
  ```
- [ ] **Outside-group user** cannot get past authorize: sign in at the browser with an account that is not in `odoo-users`; Access must show "denied" and no code reaches `auth.swovo.de`. A direct attempt: open the `authorization_endpoint` URL from the spike step 6 with that account.
- [ ] **Direct origin unreachable** (use the real origin IP and ports):
  ```bash
  ORIGIN_IP=<origin public ip>
  curl -m 8 -sk -o /dev/null -w "%{http_code}\n" https://$ORIGIN_IP/ -H "Host: $HOST"   # expect timeout / connection refused
  curl -m 8 -s  -o /dev/null -w "%{http_code}\n" http://$ORIGIN_IP:8069/web/login        # expect timeout / connection refused
  nmap -Pn -p 22,80,443,8069,8080 $ORIGIN_IP                                              # only what you intend is open
  ```
- [ ] **`odoo-api` without service-token headers is blocked; with them it works**:
  ```bash
  curl -s -o /dev/null -w "%{http_code}\n" https://$API_HOST/web/webclient/version_info                     # expect 401/403
  curl -s -o /dev/null -w "%{http_code}\n" https://$API_HOST/jsonrpc -H "Authorization: bearer <odoo_key>"  # expect 401/403 (no service token)
  curl -s -o /dev/null -w "%{http_code}\n" https://$API_HOST/web/webclient/version_info \
    -H "CF-Access-Client-Id: <id>" -H "CF-Access-Client-Secret: <secret>"                                   # expect 200
  # a service token from another integration or a revoked token -> 403
  ```
- [ ] **Removing a user from `odoo-users`**: their next refresh (within 15 min) fails and the app shows the expiry dialog. Policies are re-checked on refresh (documented); the exact delay is **TEST**.
- [ ] **Logout revokes**: after logout, a captured refresh token is rejected at the token endpoint (spike step 13), expect `400`/`401`.
- [ ] **TLS is enforced**: on a phone with mitmproxy and a user-installed CA, the app refuses to connect (no accept-all certificate callback left).
- [ ] **No secrets at rest**: on a debug build run `adb shell run-as com.cybrosys.mobo_sales cat shared_prefs/FlutterSharedPreferences.xml | grep -iE 'password|sessionId|cf_access|access_token|refresh'` (expect no matches except non-secret keys); `adb backup` yields nothing (`allowBackup=false`). iOS: inspect the app container prefs plist.

---

## 5. Manual device checklist

Use a staging server (or production after step 2 with Bypass still on, then repeat the sign-in items after step 5). Watch the proxy/log for each.

- [ ] **First run**: enter server URL → "Sign in with your organization" → system browser (Google / email OTP) → returns to the app → database list → Odoo login → sales list loads.
- [ ] **Relaunch**: kill and reopen; no Cloudflare or Odoo prompts.
- [ ] **15 minute silent refresh**: leave the app open >15 min, reload a list; it works. The network log shows a single `/token` refresh call, even with several parallel screens.
- [ ] **2FA user**: enter password, then the authenticator code; no WebView appears; login completes.
- [ ] **PDFs and images**: quotation PDF, invoice PDF, product/customer images, profile avatar and attachments load. Check once after more than 15 minutes.
- [ ] **WebView pages** (in-app web screens) load. Only the first request carries the bearer; pages that load other resources from the protected host may fail (see limitations).
- [ ] **Logout without Cloudflare sign-out**: tokens deleted; next login still goes through the browser silently if the browser session is alive (**TEST**).
- [ ] **Logout with "Also sign out of Cloudflare on this device"**: the browser opens the Access logout page; the next login asks for the full Cloudflare login. Offline logout still completes locally.
- [ ] **Two accounts on one host**: add a second account; removing one keeps the host's tokens, removing the last one deletes them; switching accounts needs no browser step.
- [ ] **Two hosts**: add an account on a second server (with and without Cloudflare); switching asks for Cloudflare only when that host has no tokens; a cancelled sign-in leaves you on the current account.
- [ ] **Revoke in Zero Trust** (Users → Revoke, or remove from group) and keep using the app: after the next refresh the "Your organization sign-in expired" dialog appears once, "Sign in" re-authenticates, Cancel logs out locally.
- [ ] **Upgrade from an old build**: install the old build, log in, install the new build over it. You stay logged in; after the first Managed OAuth 401 you get the sign-in dialog; prefs hold no `password`, `sessionId`, `password_*` or account secrets (see section 4 check). "Settings → Clear cache" afterwards does **not** log you out.
- [ ] **Plain HTTP and self-signed**: `http://` to a non-local host is refused with "Only HTTPS servers are supported" (Android loopback `localhost`, `127.0.0.1`, `10.0.2.2` still work in debug). A self-signed or expired certificate shows the "SSL certificate is not trusted" message and cannot be bypassed.
- [ ] **iOS < 17.4**: a Cloudflare-protected server shows "Update iOS to 17.4 or newer"; plain servers still work.

---

## 6. Known limitations

- **iOS below 17.4** cannot receive the https callback reliably, so protected servers are blocked there with a message.
- **WebView subresources cannot carry the bearer.** Only the first request of an in-app web page gets `Authorization`; XHR, scripts and images loaded by that page do not. Pages that depend on them from the protected host will fail once Bypass is removed.
- **Managed OAuth is in beta**; behaviour or labels may change. Re-run the spike after Cloudflare announcements.
- **The spike in `docs/cf-access-spike.md` must pass first.** Unverified until then (**TEST**): whether `Authorization` is forwarded to the origin, whether the https callback works on a phone, token rotation on refresh, and how fast revocation takes effect.
- Cloudflare tokens are bound per host; a service on a new hostname needs its own Access app and sign-in (silent while the browser session lives).
- A revoke or refresh that is still running when the user logs out can write tokens back or delete the tokens of an immediate re-login (rare; see the review notes).
- The iOS Keychain can survive an app reinstall; the stored Cloudflare tokens may be present after reinstalling. They are revoked on logout.
- Callback host `auth.swovo.de` is a placeholder; changing it later needs an app release.
