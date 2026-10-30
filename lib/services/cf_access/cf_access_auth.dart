import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_inappwebview/flutter_inappwebview.dart' as webview;
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:http/http.dart' as http;

import 'cf_access_config.dart';
import 'cf_access_store.dart';

/// Opens [authorizeUrl] in the system browser and returns the callback URL.
typedef CfAuthorize = Future<Uri> Function(Uri authorizeUrl);

/// Shows the Cloudflare Access login for [server] in an in-app browser and
/// returns the `CF_Authorization` cookie, or null when the user closed it.
typedef CfWebLogin = Future<String?> Function(Uri server);

/// Result of [CfAccessAuth.probe].
sealed class CfProbeResult {
  const CfProbeResult();
}

/// Server is reachable without Cloudflare Access.
class CfNoAccess extends CfProbeResult {
  const CfNoAccess();
}

/// Server is behind Access with Managed OAuth enabled.
class CfManagedOAuth extends CfProbeResult {
  const CfManagedOAuth(this.resourceMetadataUrl);
  final Uri resourceMetadataUrl;
}

/// Server is behind Access but redirects to the browser login page, i.e.
/// Managed OAuth is off. Signed in through an in-app browser instead.
class CfAccessLoginRedirect extends CfProbeResult {
  const CfAccessLoginRedirect();
}

/// OAuth endpoints discovered for a protected resource.
class CfServerMetadata {
  const CfServerMetadata({
    required this.authorizationEndpoint,
    required this.tokenEndpoint,
    this.registrationEndpoint,
    this.revocationEndpoint,
    this.resource,
  });

  final Uri authorizationEndpoint;
  final Uri tokenEndpoint;
  final Uri? registrationEndpoint;
  final Uri? revocationEndpoint;
  final String? resource;

  /// Parses RFC 8414 authorization-server metadata.
  factory CfServerMetadata.fromJson(
    Map<String, dynamic> json, {
    String? resource,
  }) {
    Uri? uri(String key) {
      final v = json[key];
      return v is String && v.isNotEmpty ? Uri.parse(v) : null;
    }

    final authorize = uri('authorization_endpoint');
    final token = uri('token_endpoint');
    // Tokens and the refresh token travel to these, so https only.
    if (authorize == null ||
        token == null ||
        authorize.scheme != 'https' ||
        token.scheme != 'https') {
      throw const CfAccessException(
        'Authorization server metadata lacks an https authorization_endpoint or token_endpoint',
      );
    }
    for (final optional in [
      uri('registration_endpoint'),
      uri('revocation_endpoint'),
    ]) {
      if (optional != null && optional.scheme != 'https') {
        throw const CfAccessException(
          'Authorization server endpoints must use https',
        );
      }
    }
    final methods = json['code_challenge_methods_supported'];
    if (methods is List && !methods.contains('S256')) {
      throw const CfAccessException(
        'Authorization server does not support PKCE S256',
      );
    }
    return CfServerMetadata(
      authorizationEndpoint: authorize,
      tokenEndpoint: token,
      registrationEndpoint: uri('registration_endpoint'),
      revocationEndpoint: uri('revocation_endpoint'),
      resource: resource,
    );
  }
}

class CfAccessException implements Exception {
  const CfAccessException(this.message);
  final String message;

  @override
  String toString() => 'CfAccessException: $message';
}

/// The OAuth `state` returned by the browser did not match the one we sent.
class CfStateMismatch extends CfAccessException {
  const CfStateMismatch() : super('OAuth state mismatch');
}

/// The server definitively rejected the refresh token (or there is none), so
/// the user has to sign in again. Transport errors and 5xx are NOT this.
class CfRefreshRejected extends CfAccessException {
  const CfRefreshRejected(super.message);
}

class CfAccessAuth {
  CfAccessAuth({
    http.Client? client,
    CfAccessStore? store,
    CfAuthorize? authorize,
    CfWebLogin? webLogin,
  }) : _client = client ?? http.Client(),
       store = store ?? CfAccessStore(),
       _authorize = authorize ?? _defaultAuthorize,
       _webLogin = webLogin ?? _defaultWebLogin;

  final http.Client _client;
  final CfAccessStore store;
  final CfAuthorize _authorize;
  final CfWebLogin _webLogin;

  static const _wellKnownAs = '/.well-known/oauth-authorization-server';
  static const _probePath = '/web/webclient/version_info';

  static Future<Uri> _defaultAuthorize(Uri url) async {
    final result = await FlutterWebAuth2.authenticate(
      url: url.toString(),
      callbackUrlScheme: 'https',
      options: const FlutterWebAuth2Options(
        httpsHost: CfAccessConfig.callbackHost,
        httpsPath: CfAccessConfig.callbackPath,
      ),
    );
    return Uri.parse(result);
  }

  /// Opens the server in an in-app browser; Access shows its login page, and
  /// once the user is back on the server's own host the `CF_Authorization`
  /// cookie is there to read.
  static Future<String?> _defaultWebLogin(Uri server) async {
    final done = Completer<String?>();
    final browser = _AccessLoginBrowser(server, done);
    await browser.openUrlRequest(
      urlRequest: webview.URLRequest(
        url: webview.WebUri.uri(_origin(server).replace(path: _probePath)),
      ),
    );
    return done.future;
  }

  // --- PKCE helpers -------------------------------------------------------

  /// RFC 7636 code_verifier: 32 random bytes, base64url without padding.
  static String generateVerifier([Random? random]) => _randomToken(32, random);

  static String generateState([Random? random]) => _randomToken(16, random);

  /// RFC 7636 S256: BASE64URL(SHA256(ASCII(verifier))) without padding.
  static String codeChallengeS256(String verifier) =>
      _b64(sha256.convert(ascii.encode(verifier)).bytes);

  static String _randomToken(int bytes, Random? random) {
    final r = random ?? Random.secure();
    return _b64(List<int>.generate(bytes, (_) => r.nextInt(256)));
  }

  static String _b64(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  // --- probe --------------------------------------------------------------

  Future<CfProbeResult> probe(Uri server) async {
    final request = http.Request(
      'GET',
      _origin(server).replace(path: _probePath),
    )..followRedirects = false;
    final res = await http.Response.fromStream(await _client.send(request));

    if (res.statusCode == 401) {
      final meta = _resourceMetadataFrom(res.headers['www-authenticate']);
      if (meta != null) return CfManagedOAuth(request.url.resolve(meta));
      return const CfNoAccess();
    }
    if (res.statusCode >= 300 && res.statusCode < 400) {
      final location = res.headers['location'];
      if (location != null && _isAccessHost(request.url.resolve(location))) {
        return const CfAccessLoginRedirect();
      }
      return const CfNoAccess();
    }
    if (res.statusCode == 200) {
      final finalUrl = res.request?.url;
      final contentType = res.headers['content-type'] ?? '';
      if ((finalUrl != null && _isAccessHost(finalUrl)) ||
          (contentType.contains('html') &&
              res.body.contains('cloudflareaccess.com'))) {
        return const CfAccessLoginRedirect();
      }
    }
    return const CfNoAccess();
  }

  static Uri _origin(Uri u) =>
      Uri(scheme: u.scheme, host: u.host, port: u.hasPort ? u.port : null);

  static bool _isAccessHost(Uri u) => u.host.endsWith('.cloudflareaccess.com');

  static String? _resourceMetadataFrom(String? header) {
    if (header == null || !header.toLowerCase().contains('bearer')) return null;
    final m = RegExp(
      r'resource_metadata\s*=\s*"?([^",\s]+)"?',
    ).firstMatch(header);
    return m?.group(1);
  }

  // --- discovery ----------------------------------------------------------

  /// Follows the `resource_metadata` URL from the 401 challenge to the
  /// authorization server metadata. Works with both
  /// `/.well-known/cloudflare-access-protected-resource` and
  /// `/.well-known/oauth-authorization-server` style documents.
  Future<CfServerMetadata> discover(Uri resourceMetadataUrl) async {
    final resourceDoc = await _getJson(resourceMetadataUrl);
    final resource = resourceDoc['resource'] as String?;

    // Some deployments hand out the authorization-server document directly.
    if (resourceDoc['authorization_endpoint'] != null) {
      return CfServerMetadata.fromJson(resourceDoc, resource: resource);
    }

    final servers = resourceDoc['authorization_servers'];
    final issuer = servers is List && servers.isNotEmpty
        ? Uri.parse(servers.first as String)
        : _origin(resourceMetadataUrl);

    CfAccessException? last;
    for (final candidate in _asMetadataCandidates(issuer)) {
      try {
        return CfServerMetadata.fromJson(
          await _getJson(candidate),
          resource: resource,
        );
      } on CfAccessException catch (e) {
        last = e;
      }
    }
    throw last ??
        const CfAccessException('No authorization server metadata found');
  }

  static Iterable<Uri> _asMetadataCandidates(Uri issuer) {
    final path = issuer.path.replaceAll(RegExp(r'/+$'), '');
    final origin = _origin(issuer);
    final out = <Uri>[];
    if (path.contains('/.well-known/')) {
      out.add(issuer);
    } else {
      out.add(
        origin.replace(path: '$path$_wellKnownAs'),
      ); // <issuer>/.well-known/...
      if (path.isNotEmpty) {
        out.add(
          origin.replace(path: '$_wellKnownAs$path'),
        ); // RFC 8414 insertion
      }
    }
    out.add(origin.replace(path: _wellKnownAs));
    return out.toSet();
  }

  Future<Map<String, dynamic>> _getJson(Uri url) async {
    final res = await _client.get(url, headers: {'Accept': 'application/json'});
    if (res.statusCode != 200) {
      throw CfAccessException('GET ${url.path} failed (${res.statusCode})');
    }
    final body = jsonDecode(res.body);
    if (body is! Map<String, dynamic>) {
      throw CfAccessException('GET ${url.path} returned non-object JSON');
    }
    return body;
  }

  // --- DCR (RFC 7591) -----------------------------------------------------

  /// Returns the cached client_id for [host], registering the app first if
  /// there is none.
  Future<String> register(String host, CfServerMetadata meta) async {
    final cached = await store.read(host);
    if (cached != null && cached.clientId.isNotEmpty) return cached.clientId;

    final endpoint = meta.registrationEndpoint;
    if (endpoint == null) {
      throw const CfAccessException(
        'Server does not offer dynamic client registration',
      );
    }
    final res = await _client.post(
      endpoint,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: jsonEncode({
        'client_name': 'Mobo Sales',
        'redirect_uris': [CfAccessConfig.callbackUrl],
        'grant_types': ['authorization_code', 'refresh_token'],
        'response_types': ['code'],
        'token_endpoint_auth_method': 'none',
      }),
    );
    if (res.statusCode != 200 && res.statusCode != 201) {
      throw CfAccessException('Client registration failed (${res.statusCode})');
    }
    final clientId =
        (jsonDecode(res.body) as Map<String, dynamic>)['client_id'];
    if (clientId is! String || clientId.isEmpty) {
      throw const CfAccessException(
        'Client registration returned no client_id',
      );
    }
    await store.write(
      host,
      CfTokenSet(
        clientId: clientId,
        tokenEndpoint: meta.tokenEndpoint.toString(),
        revocationEndpoint: meta.revocationEndpoint?.toString(),
        resource: meta.resource,
      ),
    );
    return clientId;
  }

  // --- sign in ------------------------------------------------------------

  /// Full interactive login. Returns null when [server] needs no Cloudflare
  /// sign-in. Managed OAuth uses the system browser; classic Access uses an
  /// in-app browser and keeps the login cookie.
  Future<CfTokenSet?> signIn(Uri server) async {
    final probed = await probe(server);
    switch (probed) {
      case CfNoAccess():
        return null;
      case CfAccessLoginRedirect():
        final jwt = await _webLogin(server);
        if (jwt == null || jwt.isEmpty) {
          throw PlatformException(code: 'CANCELED');
        }
        final tokens = CfTokenSet.accessCookie(jwt);
        await store.write(server.host, tokens);
        return tokens;
      case CfManagedOAuth(:final resourceMetadataUrl):
        final host = server.host;
        final meta = await discover(resourceMetadataUrl);
        final clientId = await register(host, meta);

        final verifier = generateVerifier();
        final state = generateState();
        final authorizeUrl = meta.authorizationEndpoint.replace(
          queryParameters: {
            ...meta.authorizationEndpoint.queryParameters,
            'response_type': 'code',
            'client_id': clientId,
            'redirect_uri': CfAccessConfig.callbackUrl,
            'code_challenge': codeChallengeS256(verifier),
            'code_challenge_method': 'S256',
            'state': state,
            if (meta.resource != null) 'resource': meta.resource!,
          },
        );

        final callback = await _authorize(authorizeUrl);
        if (callback.queryParameters['state'] != state) {
          throw const CfStateMismatch();
        }
        final error = callback.queryParameters['error'];
        if (error != null) {
          throw CfAccessException('Authorization failed: $error');
        }
        final code = callback.queryParameters['code'];
        if (code == null || code.isEmpty) {
          throw const CfAccessException('Authorization callback had no code');
        }

        final res = await _client.post(
          meta.tokenEndpoint,
          body: {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': CfAccessConfig.callbackUrl,
            'client_id': clientId,
            'code_verifier': verifier,
            if (meta.resource != null) 'resource': meta.resource!,
          },
        );
        if (res.statusCode != 200) {
          throw CfAccessException('Token exchange failed (${res.statusCode})');
        }
        final tokens = _tokensFrom(
          res.body,
          CfTokenSet(
            clientId: clientId,
            tokenEndpoint: meta.tokenEndpoint.toString(),
            revocationEndpoint: meta.revocationEndpoint?.toString(),
            resource: meta.resource,
          ),
        );
        await store.write(host, tokens);
        return tokens;
    }
  }

  // --- refresh / revoke ---------------------------------------------------

  /// Exchanges the stored refresh token. Throws [CfRefreshRejected] when the
  /// server refuses it (or none is stored); other failures (network, 5xx)
  /// surface as-is so callers can keep the tokens and retry later.
  Future<CfTokenSet> refresh(String host) async {
    final current = await store.read(host);
    final refreshToken = current?.refreshToken;
    if (current == null || refreshToken == null || refreshToken.isEmpty) {
      throw const CfRefreshRejected('No refresh token stored');
    }
    final res = await _client.post(
      Uri.parse(current.tokenEndpoint),
      body: {
        'grant_type': 'refresh_token',
        'refresh_token': refreshToken,
        'client_id': current.clientId,
        if (current.resource != null) 'resource': current.resource!,
      },
    );
    if (res.statusCode >= 400 && res.statusCode < 500) {
      throw CfRefreshRejected('Refresh rejected (${res.statusCode})');
    }
    if (res.statusCode != 200) {
      throw CfAccessException('Refresh failed (${res.statusCode})');
    }
    final next = _tokensFrom(res.body, current);
    await store.write(host, next);
    return next;
  }

  /// Best-effort RFC 7009 revocation of the refresh token, then forgets the
  /// host's token set regardless of the network outcome.
  Future<void> revoke(String host) async {
    final current = await store.read(host);
    final endpoint = current?.revocationEndpoint;
    final refreshToken = current?.refreshToken;
    if (current != null && endpoint != null && refreshToken != null) {
      try {
        await _client.post(
          Uri.parse(endpoint),
          body: {
            'token': refreshToken,
            'token_type_hint': 'refresh_token',
            'client_id': current.clientId,
          },
        );
      } catch (_) {
        // Offline logout must still clear local state.
      }
    }
    await store.delete(host);
  }

  CfTokenSet _tokensFrom(String body, CfTokenSet base) {
    final json = jsonDecode(body) as Map<String, dynamic>;
    final access = json['access_token'];
    if (access is! String || access.isEmpty) {
      throw const CfAccessException('Token response had no access_token');
    }
    final expiresIn = json['expires_in'];
    // ponytail: assume the 15 min dashboard default when expires_in is absent.
    final seconds = expiresIn is num ? expiresIn.toInt() : 900;
    return base.copyWith(
      accessToken: access,
      refreshToken: json['refresh_token'] as String?,
      expiresAt: DateTime.now().toUtc().add(Duration(seconds: seconds)),
    );
  }
}

/// In-app browser that completes [_done] with the `CF_Authorization` cookie as
/// soon as a page of the server's own host has loaded, or null if closed first.
class _AccessLoginBrowser extends webview.InAppBrowser {
  _AccessLoginBrowser(this._server, this._done);

  final Uri _server;
  final Completer<String?> _done;

  @override
  Future<void> onLoadStop(webview.WebUri? url) async {
    if (url == null || url.host != _server.host || _done.isCompleted) return;
    final cookie = await webview.CookieManager.instance().getCookie(
      url: url,
      name: 'CF_Authorization',
    );
    final value = cookie?.value;
    if (value is String && value.isNotEmpty && !_done.isCompleted) {
      _done.complete(value);
      await close();
    }
  }

  @override
  void onExit() {
    if (!_done.isCompleted) _done.complete(null);
  }
}
