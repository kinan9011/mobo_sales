import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mobo_sales/services/cf_access/cf_access_auth.dart';
import 'package:mobo_sales/services/cf_access/cf_access_store.dart';
import 'package:mobo_sales/services/cf_access/cf_expiry_notifier.dart';
import 'package:mobo_sales/services/cf_access/cf_http_client.dart';
import 'package:mobo_sales/services/cf_access/cf_sign_out.dart';

CfTokenSet _expiredTokens() => CfTokenSet(
  clientId: 'client-1',
  tokenEndpoint: 'https://team.cloudflareaccess.com/token',
  accessToken: 'old',
  refreshToken: 'refresh-old',
  expiresAt: DateTime.now().toUtc().subtract(const Duration(minutes: 1)),
);

void main() {
  group('CfExpiryNotifier', () {
    test('a burst of reports is one event', () async {
      final notifier = CfExpiryNotifier();
      final events = <String>[];
      notifier.events.listen(events.add);

      for (var i = 0; i < 5; i++) {
        notifier.report('odoo.test');
      }
      await pumpEventQueue();

      expect(events, ['odoo.test']);
      expect(notifier.episodeOpen, isTrue);
    });

    test('resolve opens the way for the next episode', () async {
      final notifier = CfExpiryNotifier();
      final events = <String>[];
      notifier.events.listen(events.add);

      notifier.report('odoo.test');
      notifier.resolve();
      notifier.report('odoo.test');
      await pumpEventQueue();

      expect(events, ['odoo.test', 'odoo.test']);
    });
  });

  test('concurrent rejected refreshes reach the notifier once', () async {
    FlutterSecureStorage.setMockInitialValues({});
    final store = CfAccessStore(const FlutterSecureStorage());
    await store.write('odoo.test', _expiredTokens());

    final inner = MockClient((req) async {
      if (req.url.path == '/token') return http.Response('{}', 400);
      return http.Response('ok', 200);
    });
    final notifier = CfExpiryNotifier();
    final events = <String>[];
    notifier.events.listen(events.add);
    final client = CfHttpClient(
      inner: inner,
      store: store,
      auth: CfAccessAuth(client: inner, store: store),
      expiry: notifier,
    );

    final results = await Future.wait(
      List.generate(
        4,
        (_) => client
            .get(Uri.parse('https://odoo.test/web/x'))
            .then<Object>((r) => r, onError: (Object e) => e),
      ),
    );
    await pumpEventQueue();

    expect(results.every((r) => r is CfAuthRequired), isTrue);
    expect(events, ['odoo.test']);
  });

  group('cfAccessLogoutUrl', () {
    test('uses the token endpoint host, not the Odoo host', () {
      final url = cfAccessLogoutUrl(_expiredTokens());
      expect(
        url.toString(),
        'https://team.cloudflareaccess.com/cdn-cgi/access/logout',
      );
    });

    test('drops port, path and query of the token endpoint', () {
      final tokens = CfTokenSet(
        clientId: 'c',
        tokenEndpoint: 'https://team.example.com:8443/cdn-cgi/access/token?x=1',
      );
      expect(
        cfAccessLogoutUrl(tokens).toString(),
        'https://team.example.com/cdn-cgi/access/logout',
      );
    });

    test('is null when the endpoint has no host', () {
      expect(
        cfAccessLogoutUrl(const CfTokenSet(clientId: 'c', tokenEndpoint: '')),
        isNull,
      );
    });
  });
}
