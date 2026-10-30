import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mobo_sales/services/odoo_totp_login.dart';

const _server = 'https://odoo.test';

const _loginPage = '''
<html><body>
<form class="oe_login_form" role="form" method="post" action="/web/login">
  <input type="hidden" name="csrf_token" value="tok&amp;1"/>
  <input type="text" name="login" id="login" value=""/>
  <input type="password" name="password"/>
  <input type="hidden" name="redirect" value="/odoo"/>
  <input type="checkbox" name="remember"/>
  <button type="submit">Log in</button>
</form></body></html>''';

String _totpPage({String? error}) =>
    '''
<html><body>
${error == null ? '' : '<p class="alert alert-danger" role="alert">$error</p>'}
<form method="post">
  <input type="hidden" name="csrf_token" value="tok2"/>
  <input type="text" name="totp_token" autocomplete="one-time-code"/>
  <input type="checkbox" name="trust_device_check"/>
</form></body></html>''';

http.Response _html(String body, [Map<String, String> headers = const {}]) =>
    http.Response(
      body,
      200,
      headers: {'content-type': 'text/html', ...headers},
    );

http.Response _redirect(String to, {String? cookie}) => http.Response(
  '',
  303,
  headers: {'location': to, if (cookie != null) 'set-cookie': cookie},
);

OdooTotpLogin _login(MockClient client) => OdooTotpLogin(
  client: client,
  serverUrl: _server,
  database: 'mydb',
  userAgent: 'test-agent',
);

void main() {
  group('parseForm', () {
    test('keeps hidden inputs and decodes entities', () {
      final form = parseForm(_loginPage, field: 'login')!;
      expect(form.action, '/web/login');
      expect(form.fields['csrf_token'], 'tok&1');
      expect(form.fields['redirect'], '/odoo');
      expect(form.fields.containsKey('remember'), isFalse); // unchecked
      expect(form.fields.containsKey('Log in'), isFalse);
    });

    test('overrides login/password/totp_token without losing the rest', () {
      final login = parseForm(
        _loginPage,
        field: 'login',
      )!.filled({'login': 'me', 'password': 'pw'});
      expect(login, {
        'csrf_token': 'tok&1',
        'login': 'me',
        'password': 'pw',
        'redirect': '/odoo',
      });
      final totp = parseForm(
        _totpPage(),
        field: 'totp_token',
      )!.filled({'totp_token': '123456'});
      expect(totp, {'csrf_token': 'tok2', 'totp_token': '123456'});
    });

    test('picks the form holding the field; null when absent', () {
      const html =
          '<form action="/search"><input name="q"></form>'
          '<form action="/web/login"><input name="login"></form>';
      expect(parseForm(html, field: 'login')!.action, '/web/login');
      expect(parseForm(html, field: 'totp_token'), isNull);
    });

    test('notes a db select by name', () {
      final form = parseForm(
        '<form><input name="login"><select name="db"><option>a</option></select></form>',
        field: 'login',
      )!;
      expect(form.fields.containsKey('db'), isTrue);
    });
  });

  test('alertText returns the alert element text', () {
    expect(alertText(_totpPage(error: 'Invalid <b>code</b>')), 'Invalid code');
    expect(alertText(_loginPage), isNull);
    expect(alertText('<div class="o_alert_x">no</div>'), isNull);
  });

  group('mergeSetCookies', () {
    test('merges several cookies, including an Expires comma', () {
      final jar = {'old': '1'};
      mergeSetCookies(
        jar,
        'session_id=abc; Expires=Wed, 21 Oct 2037 07:28:00 GMT; HttpOnly; Path=/, '
        'td_id=xyz; Max-Age=100; Path=/',
      );
      expect(jar, {'old': '1', 'session_id': 'abc', 'td_id': 'xyz'});
    });

    test('replaces values and removes expired or emptied cookies', () {
      final jar = {'session_id': 'abc', 'a': '1', 'b': '2'};
      mergeSetCookies(
        jar,
        'session_id=def; Path=/, a=; Path=/, b=2; Max-Age=0',
      );
      expect(jar, {'session_id': 'def'});
    });

    test('ignores null and malformed headers', () {
      final jar = {'k': 'v'};
      mergeSetCookies(jar, null);
      mergeSetCookies(jar, 'garbage');
      expect(jar, {'k': 'v'});
    });
  });

  group('OdooTotpLogin', () {
    late List<http.Request> log;
    late String? postedCode;

    http.Response json(Object body, {String? cookie}) => http.Response(
      jsonEncode(body),
      200,
      headers: {
        'content-type': 'application/json',
        if (cookie != null) 'set-cookie': cookie,
      },
    );

    /// Mirrors Odoo 19 with a login captcha: the form post to /web/login is
    /// refused (422), /web/session/authenticate answers `uid: null` for a 2FA
    /// user, then the totp page, wrong code alert, right code 303 to /odoo.
    MockClient fakeOdoo({
      http.Response Function(http.Request)? onAuth,
      http.Response Function(http.Request)? onTotp,
    }) {
      log = [];
      postedCode = null;
      return MockClient((req) async {
        log.add(req);
        final path = req.url.path;
        if (req.method == 'GET' && path == '/web/login') {
          return _html(_loginPage, {'set-cookie': 'session_id=anon; Path=/'});
        }
        if (req.method == 'POST' && path == '/web/login') {
          return http.Response('captcha', 422);
        }
        if (req.method == 'POST' && path == '/web/session/authenticate') {
          if (onAuth != null) return onAuth(req);
          final params = jsonDecode(req.body)['params'];
          if (params['password'] != 'pw') {
            return json({
              'error': {
                'data': {'message': 'Access Denied'},
              },
            });
          }
          return json({
            'result': {'uid': null},
          }, cookie: 'session_id=pre; Path=/');
        }
        if (req.method == 'GET' && path == '/web/login/totp') {
          return _html(_totpPage());
        }
        if (req.method == 'POST' && path == '/web/login/totp') {
          if (onTotp != null) return onTotp(req);
          postedCode = req.bodyFields['totp_token'];
          if (postedCode != '222222') {
            return _html(_totpPage(error: 'Verification failed, please retry'));
          }
          return _redirect('/odoo', cookie: 'session_id=final; Path=/');
        }
        if (path == '/odoo') return _html('<html>web client</html>');
        return http.Response('not found', 404);
      });
    }

    test('full 2FA flow: wrong code can retry, right code succeeds', () async {
      final login = _login(fakeOdoo());

      expect(await login.start('me', 'pw'), isA<TotpCodeRequired>());
      expect(login.awaitingCode, isTrue);

      final wrong = await login.submitCode('111111');
      expect(wrong, isA<TotpLoginFailed>());
      expect(
        (wrong as TotpLoginFailed).message,
        contains('Verification failed'),
      );
      expect(login.awaitingCode, isTrue); // retry without restarting

      final ok = await login.submitCode('222222');
      expect(ok, isA<TotpLoginSuccess>());
      expect((ok as TotpLoginSuccess).sessionId, 'final');

      // Credentials go to the JSON route, never to the captcha-guarded form.
      expect(
        log.where((r) => r.method == 'POST' && r.url.path == '/web/login'),
        isEmpty,
      );
      final auth = log.firstWhere(
        (r) => r.url.path == '/web/session/authenticate',
      );
      expect(jsonDecode(auth.body)['params'], {
        'db': 'mydb',
        'login': 'me',
        'password': 'pw',
      });
      expect(auth.headers['Content-Type'], contains('application/json'));
      expect(auth.headers['Cookie'], 'session_id=anon');
      expect(auth.headers['User-Agent'], 'test-agent');
      expect(log.first.url.queryParameters['db'], 'mydb');
      final totpPost = log.lastWhere(
        (r) => r.method == 'POST' && r.url.path == '/web/login/totp',
      );
      expect(totpPost.bodyFields['csrf_token'], 'tok2');
      expect(totpPost.headers['Cookie'], 'session_id=pre');
      expect(log.every((r) => !r.followRedirects), isTrue);
    });

    test('wrong password reports it and is not awaitingCode', () async {
      final login = _login(fakeOdoo());
      final result = await login.start('me', 'nope');
      expect(result, isA<TotpLoginFailed>());
      expect((result as TotpLoginFailed).message, 'Wrong login/password');
      expect(login.awaitingCode, isFalse);
      expect((await login.submitCode('222222')), isA<TotpLoginFailed>());
    });

    test('user without 2FA is signed in straight away', () async {
      final client = fakeOdoo(
        onAuth: (_) => json({
          'result': {'uid': 7},
        }, cookie: 'session_id=direct; Path=/'),
      );
      final result = await _login(client).start('me', 'pw');
      expect((result as TotpLoginSuccess).sessionId, 'direct');
    });

    test('redirect loops stop after 5 hops', () async {
      var hops = 0;
      final client = MockClient((req) async {
        if (req.method == 'GET' && req.url.path == '/web/login') {
          return _html(_loginPage);
        }
        hops++;
        return _redirect('/loop');
      });
      final result = await _login(client).start('me', 'pw');
      expect(result, isA<TotpLoginFailed>());
      expect(hops, OdooTotpLogin.maxRedirects + 1);
    });

    test('cookies are not sent to another host', () async {
      final seen = <Uri, String?>{};
      final client = MockClient((req) async {
        seen[req.url] = req.headers['Cookie'];
        if (req.url.path == '/web/login' && req.method == 'GET') {
          return _html(_loginPage, {'set-cookie': 'session_id=s; Path=/'});
        }
        if (req.method == 'POST') return _redirect('https://other.test/x');
        return _html('elsewhere');
      });
      await _login(client).start('me', 'pw');
      expect(seen[Uri.parse('https://other.test/x')], isNull);
    });

    test('falls back to /web?db= when the database selector shows', () async {
      var loginGets = 0;
      final client = MockClient((req) async {
        if (req.url.path == '/web/login' && req.method == 'GET') {
          return ++loginGets == 1
              ? _redirect('/web/database/selector')
              : _html(_loginPage);
        }
        if (req.url.path == '/web/database/selector') return _html('pick');
        if (req.url.path == '/web' && req.url.queryParameters['db'] == 'mydb') {
          return _redirect('/web/login');
        }
        if (req.url.path == '/web/session/authenticate') {
          return json({
            'result': {'uid': 7},
          }, cookie: 'session_id=z');
        }
        return _html(_loginPage);
      });
      // selector -> /web?db=mydb -> /web/login -> authenticate -> signed in
      final result = await _login(client).start('me', 'pw');
      expect(result, isA<TotpLoginSuccess>());
    });

    group('stays on the server origin', () {
      // Every request that reached a host other than https://odoo.test.
      Future<List<Uri>> offOrigin(
        http.Response Function(http.Request) onPost,
      ) async {
        final seen = <Uri>[];
        final client = MockClient((req) async {
          if (req.url.origin != _server) seen.add(req.url);
          if (req.method == 'POST') return onPost(req);
          return _html(_loginPage, {'set-cookie': 'session_id=s; Path=/'});
        });
        final result = await _login(client).start('me', 'pw');
        expect(result, isA<TotpLoginFailed>());
        return seen;
      }

      test('a 307 to another host does not replay the password', () async {
        final seen = await offOrigin((_) {
          return http.Response(
            '',
            307,
            headers: {'location': 'https://other.test/x'},
          );
        });
        expect(seen, isEmpty);
      });

      test(
        'a same-host http redirect is upgraded to https, not followed',
        () async {
          final seen = <Uri>[];
          final client = fakeOdoo(
            onTotp: (_) =>
                _redirect('http://odoo.test/odoo', cookie: 'session_id=n'),
          );
          final login = _login(client);
          expect(await login.start('me', 'pw'), isA<TotpCodeRequired>());
          expect(await login.submitCode('222222'), isA<TotpLoginSuccess>());
          seen.addAll(log.map((r) => r.url));
          expect(seen.where((u) => u.scheme == 'http'), isEmpty);
          expect(seen.last, Uri.parse('https://odoo.test/odoo'));
        },
      );
    });
  });
}
