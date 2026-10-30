import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// OAuth state for one Cloudflare Access protected host.
///
/// [clientId] is kept even before the first sign-in so the dynamic client
/// registration (RFC 7591) only runs once per server.
class CfTokenSet {
  const CfTokenSet({
    required this.clientId,
    required this.tokenEndpoint,
    this.accessToken,
    this.refreshToken,
    this.expiresAt,
    this.revocationEndpoint,
    this.resource,
  });

  final String clientId;
  final String? accessToken;
  final String? refreshToken;

  /// UTC expiry of [accessToken].
  final DateTime? expiresAt;
  final String tokenEndpoint;
  final String? revocationEndpoint;
  final String? resource;

  /// Token set for a host behind classic Access (no Managed OAuth): the
  /// `CF_Authorization` cookie value read after the in-app browser login. It
  /// has no refresh token, so when it expires the user signs in again.
  factory CfTokenSet.accessCookie(String jwt, {DateTime? now}) => CfTokenSet(
    clientId: '',
    tokenEndpoint: '',
    accessToken: jwt,
    expiresAt:
        _jwtExpiry(jwt) ??
        (now ?? DateTime.now()).toUtc().add(_cookieFallbackTtl),
  );

  static const Duration _cookieFallbackTtl = Duration(hours: 1);

  static DateTime? _jwtExpiry(String jwt) {
    final parts = jwt.split('.');
    if (parts.length != 3) return null;
    try {
      final payload = jsonDecode(
        utf8.decode(base64Url.decode(base64Url.normalize(parts[1]))),
      );
      final exp = payload is Map ? payload['exp'] : null;
      return exp is num
          ? DateTime.fromMillisecondsSinceEpoch(exp.toInt() * 1000, isUtc: true)
          : null;
    } catch (_) {
      return null;
    }
  }

  bool get hasTokens => accessToken != null && accessToken!.isNotEmpty;

  /// True for a [CfTokenSet.accessCookie] set (no OAuth client behind it).
  bool get isAccessCookie => tokenEndpoint.isEmpty;

  /// Header that carries [accessToken] to Cloudflare Access.
  Map<String, String> get authHeader => !hasTokens
      ? const {}
      : isAccessCookie
      ? {'cf-access-token': accessToken!}
      : {'Authorization': 'Bearer $accessToken'};

  /// True when the access token is missing or expires within [skew].
  bool expiresWithin(Duration skew, {DateTime? now}) {
    final exp = expiresAt;
    if (!hasTokens || exp == null) return true;
    return exp.difference((now ?? DateTime.now()).toUtc()) < skew;
  }

  CfTokenSet copyWith({
    String? accessToken,
    String? refreshToken,
    DateTime? expiresAt,
  }) => CfTokenSet(
    clientId: clientId,
    tokenEndpoint: tokenEndpoint,
    revocationEndpoint: revocationEndpoint,
    resource: resource,
    accessToken: accessToken ?? this.accessToken,
    refreshToken: refreshToken ?? this.refreshToken,
    expiresAt: expiresAt ?? this.expiresAt,
  );

  Map<String, dynamic> toJson() => {
    'clientId': clientId,
    'accessToken': accessToken,
    'refreshToken': refreshToken,
    'expiresAt': expiresAt?.toUtc().toIso8601String(),
    'tokenEndpoint': tokenEndpoint,
    'revocationEndpoint': revocationEndpoint,
    'resource': resource,
  };

  factory CfTokenSet.fromJson(Map<String, dynamic> json) => CfTokenSet(
    clientId: json['clientId'] as String,
    accessToken: json['accessToken'] as String?,
    refreshToken: json['refreshToken'] as String?,
    expiresAt: json['expiresAt'] == null
        ? null
        : DateTime.parse(json['expiresAt'] as String).toUtc(),
    tokenEndpoint: json['tokenEndpoint'] as String,
    revocationEndpoint: json['revocationEndpoint'] as String?,
    resource: json['resource'] as String?,
  );

  // Deliberately no toString(): never risk printing tokens.
}

/// Secure-storage (Keystore / Keychain) backed [CfTokenSet] store, one entry
/// per host under `cf_access.<host>`.
class CfAccessStore {
  CfAccessStore([FlutterSecureStorage? storage])
    : _storage = storage ?? const FlutterSecureStorage();

  static const String keyPrefix = 'cf_access.';

  final FlutterSecureStorage _storage;

  static String _key(String host) => '$keyPrefix${host.toLowerCase()}';

  Future<CfTokenSet?> read(String host) async {
    final raw = await _storage.read(key: _key(host));
    if (raw == null) return null;
    try {
      return CfTokenSet.fromJson(jsonDecode(raw) as Map<String, dynamic>);
    } catch (_) {
      // Corrupt entry: treat as absent rather than crash the request path.
      await delete(host);
      return null;
    }
  }

  Future<void> write(String host, CfTokenSet tokens) =>
      _storage.write(key: _key(host), value: jsonEncode(tokens.toJson()));

  Future<void> delete(String host) => _storage.delete(key: _key(host));

  Future<void> deleteAll() async {
    final all = await _storage.readAll();
    for (final key in all.keys.where((k) => k.startsWith(keyPrefix)).toList()) {
      await _storage.delete(key: key);
    }
  }
}
