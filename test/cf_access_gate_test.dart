import 'dart:convert';

import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mobo_sales/services/cf_access/cf_access_auth.dart';
import 'package:mobo_sales/services/cf_access/cf_access_config.dart';
import 'package:mobo_sales/services/cf_access/cf_access_gate.dart';
import 'package:mobo_sales/services/cf_access/cf_access_store.dart';
import 'package:mobo_sales/services/cf_access/cf_http_client.dart';

const _host = 'odoo.test';
final _server = Uri.parse('https://$_host');
const _challenge =
    'Bearer resource_metadata="https://$_host/.well-known/cloudflare-access-protected-resource"';

http.Response _json(Object body) => http.Response(
  jsonEncode(body),
  200,
  headers: {'content-type': 'application/json'},
);

/// Unsigned JWT whose payload is {"exp": 4102444800} (year 2100).
final _jwt =
    '${base64Url.encode(utf8.encode('{}'))}.${base64Url.encode(utf8.encode('{"exp":4102444800}')).replaceAll('=', '')}.sig';

enum _Server { plain, managedOAuth, loginRedirect, down }

MockClient _fakeServer(_Server kind) => MockClient((req) async {
  switch (req.url.path) {
    case '/web/webclient/version_info':
      switch (kind) {
        case _Server.plain:
          return http.Response('{}', 200);
        case _Server.managedOAuth:
          return http.Response(
            '',
            401,
            headers: {'www-authenticate': _challenge},
          );
        case _Server.loginRedirect:
          return http.Response(
            '',
            302,
            headers: {'location': 'https://team.cloudflareaccess.com/login'},
          );
        case _Server.down:
          throw http.ClientException('offline');
      }
    case '/.well-known/cloudflare-access-protected-resource':
      return _json({
        'resource': 'https://$_host',
        'authorization_servers': ['https://$_host'],
      });
    case '/.well-known/oauth-authorization-server':
      return _json({
        'authorization_endpoint': 'https://$_host/authorize',
        'token_endpoint': 'https://$_host/token',
        'registration_endpoint': 'https://$_host/register',
        'code_challenge_methods_supported': ['S256'],
      });
    case '/register':
      return _json({'client_id': 'client-1'});
    case '/token':
      return _json({
        'access_token': 'access-1',
        'refresh_token': 'refresh-1',
        'expires_in': 900,
      });
  }
  return http.Response('not found', 404);
});

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late CfAccessStore store;
  late int browserOpens;
  late int webLogins;

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    store = CfAccessStore(const FlutterSecureStorage());
    browserOpens = 0;
    webLogins = 0;
  });

  /// Gate over a fake server; the fake "browser" returns a valid callback
  /// unless [browser] says otherwise.
  CfAccessGate gate(
    _Server kind, {
    bool isIOS = false,
    String osVersion = '',
    Future<Uri> Function(Uri url)? browser,
    Future<String?> Function(Uri server)? webLogin,
  }) => CfAccessGate(
    CfAccessAuth(
      client: _fakeServer(kind),
      store: store,
      webLogin:
          webLogin ??
          (server) async {
            webLogins++;
            return _jwt;
          },
      authorize:
          browser ??
          (url) async {
            browserOpens++;
            return Uri.parse(CfAccessConfig.callbackUrl).replace(
              queryParameters: {
                'code': 'the-code',
                'state': url.queryParameters['state']!,
              },
            );
          },
    ),
    isIOS: isIOS,
    osVersion: osVersion,
  );

  Future<void> storeTokens() => store.write(
    _host,
    CfTokenSet(
      clientId: 'client-1',
      tokenEndpoint: 'https://$_host/token',
      accessToken: 'a',
      refreshToken: 'r',
      expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
    ),
  );

  group('supportsHttpsCallback', () {
    bool ios(String v) => supportsHttpsCallback(isIOS: true, osVersion: v);

    test('iOS needs 17.4', () {
      expect(ios('17.4'), isTrue);
      expect(ios('Version 17.4 (Build 21E213)'), isTrue);
      expect(ios('17.4.1'), isTrue);
      expect(ios('18'), isTrue);
      expect(ios('Version 18.0 (Build 22A)'), isTrue);
      expect(ios('17.3.1'), isFalse);
      expect(ios('Version 16.7.2 (Build 20H115)'), isFalse);
      expect(ios('17'), isFalse);
    });

    test('unparseable version and other platforms pass', () {
      expect(ios('garbage'), isTrue);
      expect(ios(''), isTrue);
      expect(
        supportsHttpsCallback(isIOS: false, osVersion: 'Linux 5.4'),
        isTrue,
      );
    });
  });

  group('check', () {
    test('plain server: open, nothing else touched', () async {
      expect(await gate(_Server.plain).check(_server), CfGateStatus.open);
      expect(await store.read(_host), isNull);
    });

    test('probe failure counts as open', () async {
      expect(await gate(_Server.down).check(_server), CfGateStatus.open);
    });

    test('Managed OAuth without tokens: sign-in required', () async {
      expect(
        await gate(_Server.managedOAuth).check(_server),
        CfGateStatus.signInRequired,
      );
      expect(browserOpens, 0); // check never opens the browser
    });

    test('Managed OAuth with stored tokens: open', () async {
      await storeTokens();
      expect(
        await gate(_Server.managedOAuth).check(_server),
        CfGateStatus.open,
      );
    });

    test('registered but never signed in still needs sign-in', () async {
      await store.write(
        _host,
        const CfTokenSet(
          clientId: 'client-1',
          tokenEndpoint: 'https://$_host/token',
        ),
      );
      expect(
        await gate(_Server.managedOAuth).check(_server),
        CfGateStatus.signInRequired,
      );
    });

    test('Access login redirect: in-app sign-in required', () async {
      final status = await gate(_Server.loginRedirect).check(_server);
      expect(status, CfGateStatus.signInRequired);
      expect(CfAccessGate.messageFor(status), isNull);
    });

    test('Access login redirect with stored cookie is open', () async {
      await store.write(_host, CfTokenSet.accessCookie(_jwt));
      expect(
        await gate(_Server.loginRedirect).check(_server),
        CfGateStatus.open,
      );
    });

    test(
      'iOS 17.3: Access login redirect still signs in (no callback)',
      () async {
        final g = gate(_Server.loginRedirect, isIOS: true, osVersion: '17.3');
        expect(await g.check(_server), CfGateStatus.signInRequired);
        await g.signIn(_server);
        expect(webLogins, 1);
      },
    );

    test('iOS 17.3: too old, with the update message', () async {
      final status = await gate(
        _Server.managedOAuth,
        isIOS: true,
        osVersion: 'Version 17.3 (Build 21D50)',
      ).check(_server);
      expect(status, CfGateStatus.iosTooOld);
      expect(CfAccessGate.messageFor(status), contains('17.4'));
    });

    test('iOS 17.3 with stored tokens is still open', () async {
      await storeTokens();
      expect(
        await gate(
          _Server.managedOAuth,
          isIOS: true,
          osVersion: '17.3',
        ).check(_server),
        CfGateStatus.open,
      );
    });

    test('open and signInRequired have no error message', () {
      expect(CfAccessGate.messageFor(CfGateStatus.open), isNull);
      expect(CfAccessGate.messageFor(CfGateStatus.signInRequired), isNull);
    });
  });

  group('signIn', () {
    test('runs the browser flow and stores tokens', () async {
      await gate(_Server.managedOAuth).signIn(_server);
      expect(browserOpens, 1);
      expect((await store.read(_host))!.accessToken, 'access-1');
    });

    test('iOS 17.3: no browser, update message', () async {
      final g = gate(_Server.managedOAuth, isIOS: true, osVersion: '17.3');
      await expectLater(
        g.signIn(_server),
        throwsA(
          isA<CfGateException>().having(
            (e) => e.message,
            'message',
            CfAccessGate.iosTooOldMessage,
          ),
        ),
      );
      expect(browserOpens, 0);
    });

    test('closing the browser gives the cancelled message', () async {
      final g = gate(
        _Server.managedOAuth,
        browser: (_) async => throw PlatformException(code: 'CANCELED'),
      );
      await expectLater(
        g.signIn(_server),
        throwsA(
          isA<CfGateException>().having(
            (e) => e.message,
            'message',
            CfAccessGate.cancelledMessage,
          ),
        ),
      );
    });

    test('other failures give the generic message', () async {
      final g = gate(
        _Server.managedOAuth,
        browser: (_) async => throw StateError('boom'),
      );
      await expectLater(
        g.signIn(_server),
        throwsA(
          isA<CfGateException>().having(
            (e) => e.message,
            'message',
            CfAccessGate.failedMessage,
          ),
        ),
      );
    });
  });

  group('ensureAccess', () {
    test('host that already has tokens: no probe, no browser', () async {
      await storeTokens();
      await gate(_Server.down).ensureAccess(_server);
      expect(browserOpens, 0);
    });

    test('plain server: nothing to do', () async {
      await gate(_Server.plain).ensureAccess(_server);
      expect(browserOpens, 0);
      expect(await store.read(_host), isNull);
    });

    test('Managed OAuth without tokens: signs in', () async {
      await gate(_Server.managedOAuth).ensureAccess(_server);
      expect(browserOpens, 1);
      expect((await store.read(_host))!.hasTokens, isTrue);
    });

    test('cancelled sign-in throws the cancelled message', () async {
      final g = gate(
        _Server.managedOAuth,
        browser: (_) async => throw PlatformException(code: 'CANCELED'),
      );
      await expectLater(
        g.ensureAccess(_server),
        throwsA(
          isA<CfGateException>().having(
            (e) => e.message,
            'message',
            CfAccessGate.cancelledMessage,
          ),
        ),
      );
      // Client registration is kept, but there are no tokens.
      expect((await store.read(_host))?.hasTokens ?? false, isFalse);
    });

    test(
      'Access login redirect: signs in through the in-app browser',
      () async {
        await gate(_Server.loginRedirect).ensureAccess(_server);
        expect(webLogins, 1);
        expect(browserOpens, 0);
        final saved = (await store.read(_host))!;
        expect(saved.accessToken, _jwt);
        expect(saved.isAccessCookie, isTrue);
        expect(saved.authHeader, {'cf-access-token': _jwt});
      },
    );

    test('Access login redirect: closing the browser is a cancel', () async {
      await expectLater(
        gate(
          _Server.loginRedirect,
          webLogin: (_) async => null,
        ).ensureAccess(_server),
        throwsA(
          isA<CfGateException>().having(
            (e) => e.message,
            'message',
            CfAccessGate.cancelledMessage,
          ),
        ),
      );
      expect(await store.read(_host), isNull);
    });
  });

  group('guard', () {
    test('plain server: body runs once, no sign-in', () async {
      var runs = 0;
      final result = await gate(_Server.plain).guard(_server, () async {
        runs++;
        return 'ok';
      });
      expect(result, 'ok');
      expect(runs, 1);
      expect(browserOpens, 0);
    });

    test('CfAuthRequired mid-login: signs in once and retries', () async {
      var runs = 0;
      final result = await gate(_Server.managedOAuth).guard(_server, () async {
        if (++runs == 1) throw const CfAuthRequired(_host);
        return 'ok';
      });
      expect(result, 'ok');
      expect(runs, 2);
      expect(browserOpens, 1);
    });

    test('tokens vanishing while the body swallows the error', () async {
      await storeTokens();
      var runs = 0;
      final result = await gate(_Server.managedOAuth).guard(_server, () async {
        if (++runs == 1) {
          await store.delete(_host); // refresh rejected, body returns false
          return false;
        }
        return true;
      });
      expect(result, isTrue);
      expect(runs, 2);
      expect(browserOpens, 1);
    });

    test('a second CfAuthRequired becomes a gate exception', () async {
      var runs = 0;
      await expectLater(
        gate(_Server.managedOAuth).guard(_server, () async {
          runs++;
          throw const CfAuthRequired(_host);
        }),
        throwsA(isA<CfGateException>()),
      );
      expect(runs, 2);
      expect(browserOpens, 1);
    });

    test('unrelated errors pass through without a sign-in', () async {
      await storeTokens();
      await expectLater(
        gate(_Server.managedOAuth).guard(_server, () async {
          throw StateError('bad password');
        }),
        throwsA(isA<StateError>()),
      );
      expect(browserOpens, 0);
    });
  });
}
