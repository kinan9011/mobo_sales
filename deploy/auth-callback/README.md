# auth-callback

Static host for the Cloudflare Access OAuth callback of the mobo Sales app. No API, no secrets.

| Path | Purpose |
|---|---|
| `/.well-known/assetlinks.json` | Android App Links verification |
| `/.well-known/apple-app-site-association` | iOS Universal Links verification |
| `/oauth/callback` | Fallback page if the app does not intercept the link |

Both `.well-known` files are served as `application/json`, with no redirects and no directory listing.

## Placeholders you must fill

1. **`.well-known/assetlinks.json`** → `REPLACE_WITH_RELEASE_SHA256_FINGERPRINT`
   - Package name is already `com.cybrosys.mobo_sales`.
   - Release keystore fingerprint (same keystore as `android/key.properties`):
     ```sh
     keytool -list -v -keystore <path/to/release.jks> -alias <keyAlias> | grep SHA256
     ```
     or:
     ```sh
     cd android && ./gradlew signingReport
     ```
     (look at the `release` variant, `SHA-256` line)
   - If the app is distributed through Google Play App Signing, also add the **App signing key certificate** SHA-256 from Play Console → Setup → App signing. Add it as a second entry in `sha256_cert_fingerprints`. For local debug builds, add the debug keystore fingerprint too.
   - Format: uppercase hex with colons, e.g. `AB:CD:...`.
2. **`.well-known/apple-app-site-association`** → `REPLACE_TEAM_ID`
   - Apple Developer Team ID. `ios/Runner.xcodeproj` currently has `DEVELOPMENT_TEAM = KD8HL2F8P7`; confirm it is the right team.
   - Bundle id is `com.cybrosys.mobo-sale`.
3. **Domain**: `auth.swovo.de` is a placeholder. To change it, update all of:
   - `lib/services/cf_access/cf_access_config.dart` (`callbackHost`, `callbackPath`)
   - `android/app/src/main/AndroidManifest.xml` (callback intent-filter)
   - `ios/Runner/Runner.entitlements` (`applinks:` entry)
   - the Traefik `Host(...)` label in `docker-compose.yml` (when enabled)
4. **DNS / TLS / Traefik**: point the callback host at this container (uncomment the Traefik labels in `docker-compose.yml`). It must be reachable over valid public HTTPS. It must **not** sit behind Cloudflare Access, or the verifiers get a login page.

## Cloudflare redirect URI to register

```
https://auth.swovo.de/oauth/callback
```

Register this exact URL as the redirect URI for the app's OAuth client (Managed OAuth DCR / Access for SaaS fallback).

## Run

```sh
docker compose up -d
```

## Verify

```sh
curl -si https://auth.swovo.de/.well-known/assetlinks.json | head -n 5               # 200, application/json
curl -si https://auth.swovo.de/.well-known/apple-app-site-association | head -n 5     # 200, application/json, no redirect
curl -si https://auth.swovo.de/oauth/callback | head -n 5                             # 200, text/html
adb shell pm get-app-links com.cybrosys.mobo_sales                                    # Android: auth.swovo.de verified
```

iOS: Associated Domains need the Team's provisioning profile to include the capability; iOS caches the AASA via Apple's CDN, so changes can take a while.
