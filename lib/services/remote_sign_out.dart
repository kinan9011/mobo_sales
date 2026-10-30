import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'cf_access/cf_access_auth.dart';

/// Server-side sign-out steps that must never block a logout: every step is
/// best-effort and time-bounded.
///
/// Order matters: the Odoo session is destroyed first, while the Cloudflare
/// bearer is still valid, then the refresh tokens of [releaseHosts] are
/// revoked and every host's local token set is deleted. [releaseAll] also
/// wipes token sets of hosts not listed.
Future<void> remoteSignOut({
  required http.Client client,
  required CfAccessAuth auth,
  Uri? odooServer,
  String? sessionId,
  Iterable<String> releaseHosts = const [],
  bool releaseAll = false,
  bool remote = true,
  Duration destroyTimeout = const Duration(seconds: 3),
  Duration revokeTimeout = const Duration(seconds: 5),
}) async {
  final hosts = releaseHosts.map((h) => h.toLowerCase()).toSet();

  if (remote && odooServer != null && (sessionId?.isNotEmpty ?? false)) {
    try {
      await client
          .post(
            odooServer.replace(path: '/web/session/destroy'),
            headers: {
              'Content-Type': 'application/json',
              'Cookie': 'session_id=$sessionId',
            },
            body: jsonEncode({
              'jsonrpc': '2.0',
              'method': 'call',
              'params': {},
            }),
          )
          .timeout(destroyTimeout);
    } catch (_) {
      // The local logout goes on regardless.
    }
  }

  if (remote && hosts.isNotEmpty) {
    try {
      await Future.wait(hosts.map(auth.revoke)).timeout(revokeTimeout);
    } catch (_) {}
  }

  for (final host in hosts) {
    try {
      await auth.store.delete(host);
    } catch (_) {}
  }
  if (releaseAll) {
    try {
      await auth.store.deleteAll();
    } catch (_) {}
  }
}
