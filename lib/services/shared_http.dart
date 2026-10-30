import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'cf_access/cf_access_auth.dart';
import 'cf_access/cf_access_store.dart';
import 'cf_access/cf_expiry_notifier.dart';
import 'cf_access/cf_http_client.dart';

/// HTTP client wrapper that enforces an overall timeout on every request,
/// bounding the wait for the server's response (which `connectionTimeout`
/// alone does not) so a stalled response can never hang the UI indefinitely.
class _TimeoutHttpClient extends http.BaseClient {
  _TimeoutHttpClient(this._inner, this._timeout);

  final http.Client _inner;
  final Duration _timeout;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    final timeout = Zone.current[SharedHttp._timeoutKey] as Duration?;
    return _inner.send(request).timeout(timeout ?? _timeout);
  }

  /// The client is app-wide; `OdooClient.close()` must not tear it down.
  @override
  void close() {}
}

/// The one HTTP client every network call in the app goes through, so the
/// Cloudflare Access bearer can be attached in a single place. Hosts without
/// stored Cloudflare tokens are passed through untouched.
class SharedHttp {
  const SharedHttp._();

  /// Maximum time to wait for a server response before failing with a
  /// [TimeoutException]. Kept generous because creating a `sale.order` is a
  /// heavy server-side operation, but bounded so the UI never hangs forever.
  static const Duration requestTimeout = Duration(seconds: 60);

  /// Maximum time to wait while establishing the TCP connection.
  static const Duration connectionTimeout = Duration(seconds: 30);

  static const Object _timeoutKey = #sharedHttpTimeout;

  static final CfAccessStore store = CfAccessStore();

  static final http.BaseClient _base = _createBaseClient();

  static final CfAccessAuth auth = CfAccessAuth(client: _base, store: store);

  /// Fires once per episode when a Cloudflare session can no longer be
  /// renewed silently; the app root reacts to it.
  static final CfExpiryNotifier expiry = CfExpiryNotifier();

  static CfHttpClient _client = CfHttpClient(
    inner: _base,
    store: store,
    auth: auth,
    expiry: expiry,
  );

  static CfHttpClient get client => _client;

  @visibleForTesting
  static set client(CfHttpClient value) => _client = value;

  static http.BaseClient _createBaseClient() {
    // Default certificate validation applies (no accept-all override).
    final HttpClient client = HttpClient()
      ..connectionTimeout = connectionTimeout;
    return _TimeoutHttpClient(IOClient(client), requestTimeout);
  }

  /// Runs [body] with [timeout] replacing the default [requestTimeout] for
  /// every request it sends through [client] (e.g. slow PDF rendering).
  static Future<T> withTimeout<T>(Duration timeout, Future<T> Function() body) {
    return runZoned(body, zoneValues: {_timeoutKey: timeout});
  }
}
