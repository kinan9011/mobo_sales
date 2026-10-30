import 'package:http/http.dart' as http;

import 'cf_access_auth.dart';
import 'cf_access_store.dart';
import 'cf_expiry_notifier.dart';

/// The Cloudflare Access session for [host] is gone and cannot be renewed
/// silently; the user has to sign in again.
class CfAuthRequired implements Exception {
  const CfAuthRequired(this.host);
  final String host;

  @override
  String toString() => 'CfAuthRequired: sign-in required for $host';
}

/// Adds the Access credential (`Authorization: Bearer <access>` for Managed
/// OAuth, `cf-access-token` for the classic login cookie) to requests for
/// hosts that have a stored [CfTokenSet], refreshing it when needed. Hosts
/// without one are passed through untouched, so non-Cloudflare servers keep
/// working.
class CfHttpClient extends http.BaseClient {
  CfHttpClient({
    required http.Client inner,
    required CfAccessStore store,
    required CfAccessAuth auth,
    CfExpiryNotifier? expiry,
  }) : _inner = inner,
       _store = store,
       _auth = auth,
       _expiry = expiry;

  static const Duration refreshSkew = Duration(seconds: 60);

  final http.Client _inner;
  final CfAccessStore _store;
  final CfAccessAuth _auth;
  final CfExpiryNotifier? _expiry;

  /// In-flight refresh per host; concurrent callers share the same Future.
  final Map<String, Future<CfTokenSet>> _refreshing = {};

  /// Last known token set per host, so widgets that need headers
  /// synchronously (Image.network, WebView requests) can read the credential.
  final Map<String, CfTokenSet> _cache = {};

  /// Access header for [host] if a fresh token is cached, else empty. Never
  /// blocks.
  Map<String, String> cachedAuthHeader(String host) {
    final tokens = _cache[host];
    if (tokens == null || tokens.expiresWithin(refreshSkew)) return const {};
    return tokens.authHeader;
  }

  /// Access header for [host], refreshed when near expiry; empty when the host
  /// has no stored tokens or the Access session is gone.
  Future<Map<String, String>> authHeaderFor(String host) async {
    try {
      final tokens = await _freshTokens(host);
      return tokens?.authHeader ?? const {};
    } on CfAuthRequired {
      return const {};
    }
  }

  /// Fire-and-forget [authHeaderFor] to fill the cache for the next sync read.
  void warm(String host) {
    authHeaderFor(host).then<void>((_) {}, onError: (Object _) {});
  }

  Future<CfTokenSet?> _freshTokens(String host) async {
    var tokens = await _store.read(host);
    if (tokens == null || !tokens.hasTokens) {
      _cache.remove(host);
      return null;
    }
    if (tokens.expiresWithin(refreshSkew)) tokens = await _refresh(host);
    return _cache[host] = tokens;
  }

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final host = request.url.host;
    // The credential is never sent in clear text.
    if (request.url.scheme != 'https') return _inner.send(request);
    final tokens = await _freshTokens(host);
    if (tokens == null) {
      final response = await _inner.send(request);
      // Access now guards a host we hold no tokens for (e.g. a session from
      // before the Cloudflare login existed): ask for a sign-in.
      if ((response.statusCode == 401 && _isManagedOAuthChallenge(response)) ||
          _isAccessLoginRedirect(response)) {
        _expiry?.report(host);
      }
      return response;
    }

    request.headers.addAll(tokens.authHeader);
    final response = await _inner.send(request);

    // The login cookie was refused: Access sends the browser to its login page.
    if (_isAccessLoginRedirect(response)) {
      await response.stream.drain<void>();
      _cache.remove(host);
      await _store.delete(host);
      _expiry?.report(host);
      throw CfAuthRequired(host);
    }

    // Streamed / multipart bodies can't be replayed, so they are not retried.
    if (response.statusCode != 401 ||
        request is! http.Request ||
        !_isBearerChallenge(response)) {
      return response;
    }

    await response.stream.drain<void>();
    final sent = tokens.accessToken;
    // Another request may already have renewed the token while this one was
    // in flight; reuse it instead of refreshing again.
    final stored = await _store.read(host);
    final fresh =
        stored != null &&
            stored.hasTokens &&
            stored.accessToken != sent &&
            !stored.expiresWithin(refreshSkew)
        ? stored
        : await _refresh(host);

    _cache[host] = fresh;
    final retry = _clone(request)..headers.addAll(fresh.authHeader);
    return _inner.send(retry);
  }

  static bool _isBearerChallenge(http.StreamedResponse r) =>
      (r.headers['www-authenticate'] ?? '').toLowerCase().startsWith('bearer');

  static bool _isManagedOAuthChallenge(http.StreamedResponse r) {
    final header = (r.headers['www-authenticate'] ?? '').toLowerCase();
    return header.startsWith('bearer') && header.contains('resource_metadata');
  }

  static bool _isAccessLoginRedirect(http.StreamedResponse r) {
    if (r.statusCode < 300 || r.statusCode >= 400) return false;
    final location = Uri.tryParse(r.headers['location'] ?? '');
    return location != null && location.host.endsWith('.cloudflareaccess.com');
  }

  static http.Request _clone(http.Request r) => http.Request(r.method, r.url)
    ..headers.addAll(r.headers)
    ..bodyBytes = r.bodyBytes
    ..followRedirects = r.followRedirects
    ..maxRedirects = r.maxRedirects
    ..persistentConnection = r.persistentConnection;

  Future<CfTokenSet> _refresh(String host) =>
      _refreshing[host] ??= _doRefresh(host).whenComplete(() {
        // Block body on purpose: returning remove()'s Future would make
        // whenComplete wait on itself.
        _refreshing.remove(host);
      });

  Future<CfTokenSet> _doRefresh(String host) async {
    try {
      return await _auth.refresh(host);
    } on CfRefreshRejected {
      _cache.remove(host);
      await _store.delete(host);
      _expiry?.report(host);
      throw CfAuthRequired(host);
    }
  }

  @override
  void close() => _inner.close();
}
