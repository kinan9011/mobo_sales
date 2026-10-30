import 'dart:async';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mobo_sales/services/cf_access/cf_access_auth.dart';
import 'package:mobo_sales/services/cf_access/cf_access_store.dart';
import 'package:mobo_sales/services/remote_sign_out.dart';
import 'package:mobo_sales/utils/cf_host_release.dart';

CfTokenSet _tokens(String host) => CfTokenSet(
  clientId: 'client-$host',
  tokenEndpoint: 'https://$host/token',
  revocationEndpoint: 'https://$host/revoke',
  accessToken: 'access-$host',
  refreshToken: 'refresh-$host',
  expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
);

Map<String, dynamic> _account(String url) => {'serverUrl': url};

void main() {
  late CfAccessStore store;
  late List<String> log;

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    store = CfAccessStore(const FlutterSecureStorage());
    log = [];
    await store.write('a.test', _tokens('a.test'));
    await store.write('b.test', _tokens('b.test'));
  });

  group('remoteSignOut', () {
    /// One client for both the Odoo destroy call and the revoke call, so the
    /// log shows the real request order.
    Future<http.Response> ok(http.Request r) async {
      log.add(r.url.path);
      return http.Response('', 200);
    }

    test(
      'destroys the Odoo session, then revokes, then deletes tokens',
      () async {
        final shared = MockClient((r) async {
          // The token set is still stored while both requests are in flight.
          expect(await store.read('a.test'), isNotNull);
          if (r.url.path == '/revoke') {
            expect(r.bodyFields['token'], 'refresh-a.test');
          }
          return ok(r);
        });

        await remoteSignOut(
          client: shared,
          auth: CfAccessAuth(client: shared, store: store),
          odooServer: Uri.parse('https://a.test'),
          sessionId: 'sid',
          releaseHosts: ['a.test'],
        );

        expect(log, ['/web/session/destroy', '/revoke']);
        expect(await store.read('a.test'), isNull);
        expect(await store.read('b.test'), isNotNull);
      },
    );

    test('destroy request carries the session cookie', () async {
      http.Request? seen;
      final shared = MockClient((r) async {
        seen = r;
        return http.Response('{}', 200);
      });
      await remoteSignOut(
        client: shared,
        auth: CfAccessAuth(client: shared, store: store),
        odooServer: Uri.parse('https://a.test'),
        sessionId: 'sid',
      );
      expect(seen!.headers['Cookie'], 'session_id=sid');
    });

    test('failing destroy and revoke still delete the tokens', () async {
      final shared = MockClient((_) async => throw Exception('offline'));

      await remoteSignOut(
        client: shared,
        auth: CfAccessAuth(client: shared, store: store),
        odooServer: Uri.parse('https://a.test'),
        sessionId: 'sid',
        releaseHosts: ['a.test'],
      );

      expect(await store.read('a.test'), isNull);
    });

    test('hanging destroy and revoke time out and still delete', () async {
      final never = Completer<http.Response>();
      final shared = MockClient((_) => never.future);

      await remoteSignOut(
        client: shared,
        auth: CfAccessAuth(client: shared, store: store),
        odooServer: Uri.parse('https://a.test'),
        sessionId: 'sid',
        releaseHosts: ['a.test'],
        destroyTimeout: const Duration(milliseconds: 50),
        revokeTimeout: const Duration(milliseconds: 50),
      );

      expect(await store.read('a.test'), isNull);
      expect(await store.read('b.test'), isNotNull);
    });

    test('releaseAll wipes every host', () async {
      final shared = MockClient(ok);
      await remoteSignOut(
        client: shared,
        auth: CfAccessAuth(client: shared, store: store),
        releaseHosts: ['a.test'],
        releaseAll: true,
      );
      expect(await store.read('a.test'), isNull);
      expect(await store.read('b.test'), isNull);
    });

    test('remote false skips the network but deletes locally', () async {
      final shared = MockClient(ok);
      await remoteSignOut(
        client: shared,
        auth: CfAccessAuth(client: shared, store: store),
        odooServer: Uri.parse('https://a.test'),
        sessionId: 'sid',
        releaseHosts: ['a.test'],
        remote: false,
      );
      expect(log, isEmpty);
      expect(await store.read('a.test'), isNull);
    });
  });

  group('hostsToReleaseAfterRemoval', () {
    test('keeps the host while another account uses it', () {
      final removed = _account('https://a.test');
      expect(
        hostsToReleaseAfterRemoval([_account('https://a.test')], removed, null),
        isEmpty,
      );
    });

    test('releases the host of the last account on it', () {
      final removed = _account('https://a.test');
      expect(
        hostsToReleaseAfterRemoval([_account('https://b.test')], removed, null),
        {'a.test'},
      );
    });

    test('never releases the active host', () {
      final removed = _account('https://a.test');
      expect(hostsToReleaseAfterRemoval([], removed, 'a.test'), isEmpty);
      expect(hostsToReleaseAfterRemoval([], removed, 'A.TEST'), isEmpty);
    });

    test('compares hosts case-insensitively and ignores ports and paths', () {
      final removed = _account('https://A.test:8443/odoo');
      expect(
        hostsToReleaseAfterRemoval([_account('https://a.test')], removed, null),
        isEmpty,
      );
    });

    test('falls back to the url key', () {
      expect(
        hostsToReleaseAfterRemoval([], {'url': 'https://a.test'}, 'b.test'),
        {'a.test'},
      );
    });

    test('an account without a usable host releases nothing', () {
      expect(hostsToReleaseAfterRemoval([], {'serverUrl': ''}, null), isEmpty);
    });
  });
}
