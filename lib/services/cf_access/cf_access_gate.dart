import 'dart:io';

import 'package:flutter/services.dart' show PlatformException;

import 'cf_access_auth.dart';
import 'cf_http_client.dart';

/// What the login UI has to do before it may talk to a server.
enum CfGateStatus {
  /// No Cloudflare step needed (plain server, or tokens already stored).
  open,

  /// Behind Access with no tokens yet: the user has to sign in.
  signInRequired,

  /// Sign-in needed, but this iOS cannot deliver the https callback.
  iosTooOld,
}

/// A Cloudflare sign-in problem with a message that is safe to show as is.
class CfGateException implements Exception {
  const CfGateException(this.message);
  final String message;

  @override
  String toString() => 'CfGateException: $message';
}

/// The https OAuth callback (Universal Link) can only be caught reliably on
/// iOS 17.4+. Anything that is not iOS, or a version we cannot parse, passes.
bool supportsHttpsCallback({required bool isIOS, required String osVersion}) {
  if (!isIOS) return true;
  final m = RegExp(r'(\d+)(?:\.(\d+))?').firstMatch(osVersion);
  if (m == null) return true;
  final major = int.parse(m.group(1)!);
  final minor = int.tryParse(m.group(2) ?? '') ?? 0;
  return major > 17 || (major == 17 && minor >= 4);
}

/// Shared by both login flows: decides whether a Cloudflare sign-in is needed
/// for a server and runs it. Servers without Cloudflare are left untouched.
class CfAccessGate {
  CfAccessGate(CfAccessAuth auth, {bool? isIOS, String? osVersion})
    : _auth = auth,
      _isIOS = isIOS ?? Platform.isIOS,
      _osVersion = osVersion ?? Platform.operatingSystemVersion;

  static const String iosTooOldMessage =
      'Update iOS to 17.4 or newer to sign in to this server.';
  static const String cancelledMessage =
      'Sign-in was cancelled. Tap the button to try again.';
  static const String failedMessage =
      'Could not sign in with your organization. Please try again.';
  static const String expiredMessage =
      'Your organization sign-in expired. Please sign in again.';

  final CfAccessAuth _auth;
  final bool _isIOS;
  final String _osVersion;

  bool get _callbackSupported =>
      supportsHttpsCallback(isIOS: _isIOS, osVersion: _osVersion);

  /// User-facing text for a blocking [status]; null when nothing is wrong.
  static String? messageFor(CfGateStatus status) => switch (status) {
    CfGateStatus.iosTooOld => iosTooOldMessage,
    CfGateStatus.open || CfGateStatus.signInRequired => null,
  };

  Future<bool> _hasTokens(String host) async =>
      (await _auth.store.read(host))?.hasTokens ?? false;

  /// Probes [server]. A failing probe counts as [CfGateStatus.open], so the
  /// regular flow reports network problems exactly as it does today.
  Future<CfGateStatus> check(Uri server) async {
    final CfProbeResult probed;
    try {
      probed = await _auth.probe(server);
    } catch (_) {
      return CfGateStatus.open;
    }
    switch (probed) {
      case CfNoAccess():
        return CfGateStatus.open;
      case CfAccessLoginRedirect():
        // Signed in through an in-app browser; no https callback needed.
        return await _hasTokens(server.host)
            ? CfGateStatus.open
            : CfGateStatus.signInRequired;
      case CfManagedOAuth():
        // CfHttpClient refreshes stored tokens silently.
        if (await _hasTokens(server.host)) return CfGateStatus.open;
        return _callbackSupported
            ? CfGateStatus.signInRequired
            : CfGateStatus.iosTooOld;
    }
  }

  /// Only Managed OAuth needs the https callback; the in-app browser login of
  /// classic Access does not. A failing probe counts as needed (old behaviour).
  Future<bool> _needsHttpsCallback(Uri server) async {
    try {
      return await _auth.probe(server) is! CfAccessLoginRedirect;
    } catch (_) {
      return true;
    }
  }

  /// Interactive sign-in: system browser (Managed OAuth) or in-app browser.
  Future<void> signIn(Uri server) async {
    if (!_callbackSupported && await _needsHttpsCallback(server)) {
      throw const CfGateException(iosTooOldMessage);
    }
    try {
      await _auth.signIn(server);
    } on PlatformException catch (e) {
      throw CfGateException(
        e.code == 'CANCELED' ? cancelledMessage : failedMessage,
      );
    } catch (_) {
      throw const CfGateException(failedMessage);
    }
  }

  /// Makes sure [server] can be used: returns at once when its host already
  /// has tokens, otherwise signs in if Cloudflare asks for it. Throws
  /// [CfGateException] when the server is blocked or the sign-in fails or is
  /// cancelled. Servers without Cloudflare only cost one probe.
  Future<void> ensureAccess(Uri server) async {
    if (await _hasTokens(server.host)) return;
    final status = await check(server);
    final blocked = messageFor(status);
    if (blocked != null) throw CfGateException(blocked);
    if (status == CfGateStatus.signInRequired) await signIn(server);
  }

  /// Runs [body]; if the Access session turns out to be gone (refresh
  /// rejected), signs in again once and reruns it. Some login paths swallow
  /// the [CfAuthRequired] and just return false, so a host that had tokens
  /// and lost them during [body] counts as well.
  Future<T> guard<T>(Uri server, Future<T> Function() body) async {
    final host = server.host;
    final hadTokens = await _hasTokens(host);
    var expired = false;
    T? result;
    try {
      result = await body();
    } on CfAuthRequired {
      expired = true;
    } catch (_) {
      if (!hadTokens || await _hasTokens(host)) rethrow;
      expired = true;
    }
    if (!expired && hadTokens && !await _hasTokens(host)) expired = true;
    if (!expired) return result as T;

    await signIn(server);
    try {
      return await body();
    } on CfAuthRequired {
      throw const CfGateException(expiredMessage);
    }
  }
}
