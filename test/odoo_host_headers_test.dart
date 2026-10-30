import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mobo_sales/services/cf_access/cf_access_auth.dart';
import 'package:mobo_sales/services/cf_access/cf_access_store.dart';
import 'package:mobo_sales/services/cf_access/cf_http_client.dart';
import 'package:mobo_sales/services/odoo_session_manager.dart';
import 'package:mobo_sales/services/shared_http.dart';
import 'package:mobo_sales/utils/odoo_host_headers.dart';

const _odooHost = 'odoo.test';

void main() {
  final session = OdooSessionModel(
    sessionId: 'sid-1',
    userLogin: 'u',
    password: 'p',
    serverUrl: 'https://$_odooHost',
    database: 'db',
  );

  setUp(() async {
    FlutterSecureStorage.setMockInitialValues({});
    final store = CfAccessStore(const FlutterSecureStorage());
    await store.write(
      _odooHost,
      CfTokenSet(
        clientId: 'client-1',
        tokenEndpoint: 'https://$_odooHost/token',
        accessToken: 'access-1',
        refreshToken: 'refresh-1',
        expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
      ),
    );
    final inner = MockClient((_) async => http.Response('{}', 200));
    SharedHttp.client = CfHttpClient(
      inner: inner,
      store: store,
      auth: CfAccessAuth(client: inner, store: store),
    );
    await SharedHttp.client.authHeaderFor(_odooHost);
  });

  test('Odoo host gets session cookie and bearer', () {
    final h = odooHostHeaders(
      'https://$_odooHost/web/image/res.partner/1',
      session,
    );
    expect(h?['Cookie'], 'session_id=sid-1');
    expect(h?['Authorization'], 'Bearer access-1');
  });

  test('no X-Openerp-Session-Id: it survives cross-origin redirects', () {
    final h = odooHostHeaders('https://$_odooHost/web/image/x', session);
    expect(h, isNot(contains('X-Openerp-Session-Id')));
  });

  test('plain-http URL on the Odoo host gets no cookie and no bearer', () {
    expect(odooHostHeaders('http://$_odooHost/web/image/x', session), isNull);
    expect(OdooSessionManager.bearerHeaders('http://$_odooHost/x'), isEmpty);
    expect(
      OdooSessionManager.authHeaders('http://$_odooHost/x', sessionId: 's'),
      isNot(contains('Authorization')),
    );
  });

  test('external fallback URL gets no headers (no cookie leak)', () {
    expect(
      odooHostHeaders('https://dummyimage.com/150x150/000/fff', session),
      isNull,
    );
  });

  test('no session gets no headers', () {
    expect(odooHostHeaders('https://$_odooHost/web/image/x', null), isNull);
  });
}
