import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mobo_sales/services/cf_access/cf_access_auth.dart';
import 'package:mobo_sales/services/cf_access/cf_access_store.dart';
import 'package:mobo_sales/services/cf_access/cf_http_client.dart';
import 'package:mobo_sales/services/odoo_session_manager.dart';
import 'package:mobo_sales/services/shared_http.dart';

const _cfHost = 'cf.odoo.test';
const _plainHost = 'plain.odoo.test';

void main() {
  late List<http.BaseRequest> seen;

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    final store = CfAccessStore(const FlutterSecureStorage());
    await store.write(
      _cfHost,
      CfTokenSet(
        clientId: 'client-1',
        tokenEndpoint: 'https://$_cfHost/token',
        accessToken: 'access-1',
        refreshToken: 'refresh-1',
        expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
      ),
    );
    seen = [];
    final inner = MockClient((req) async {
      seen.add(req);
      return http.Response('{}', 200);
    });
    SharedHttp.client = CfHttpClient(
      inner: inner,
      store: store,
      auth: CfAccessAuth(client: inner, store: store),
    );
  });

  test('shared client sends Bearer to a host with stored tokens', () async {
    await OdooSessionManager.ioClient.get(Uri.parse('https://$_cfHost/web'));

    expect(seen.single.headers['Authorization'], 'Bearer access-1');
  });

  test(
    'shared client sends no Authorization to a host without tokens',
    () async {
      await OdooSessionManager.ioClient.get(
        Uri.parse('https://$_plainHost/web'),
      );

      expect(seen.single.headers.containsKey('Authorization'), isFalse);
    },
  );

  test('authHeadersAsync has cookie and bearer when both exist', () async {
    final headers = await OdooSessionManager.authHeadersAsync(
      'https://$_cfHost/web/image/1',
      sessionId: 'sid-1',
    );

    expect(headers['Cookie'], 'session_id=sid-1');
    expect(headers.containsKey('X-Openerp-Session-Id'), isFalse);
    expect(headers['Authorization'], 'Bearer access-1');
  });

  test('authHeadersAsync has cookie only for a host without tokens', () async {
    final headers = await OdooSessionManager.authHeadersAsync(
      'https://$_plainHost/web/image/1',
      sessionId: 'sid-1',
    );

    expect(headers['Cookie'], 'session_id=sid-1');
    expect(headers.containsKey('Authorization'), isFalse);
  });

  test(
    'sync authHeaders carries the bearer once a request filled the cache',
    () async {
      final url = 'https://$_cfHost/web/image/1';
      expect(
        OdooSessionManager.authHeaders(
          url,
          sessionId: 'sid-1',
        ).containsKey('Authorization'),
        isFalse,
      );

      await OdooSessionManager.ioClient.get(Uri.parse(url));

      final headers = OdooSessionManager.authHeaders(url, sessionId: 'sid-1');
      expect(headers['Authorization'], 'Bearer access-1');
      expect(headers['Cookie'], 'session_id=sid-1');
      expect(OdooSessionManager.bearerHeaders(url), {
        'Authorization': 'Bearer access-1',
      });
    },
  );
}
