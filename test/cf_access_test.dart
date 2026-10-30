import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mobo_sales/services/cf_access/cf_access_auth.dart';
import 'package:mobo_sales/services/cf_access/cf_access_config.dart';
import 'package:mobo_sales/services/cf_access/cf_access_store.dart';
import 'package:mobo_sales/services/cf_access/cf_expiry_notifier.dart';
import 'package:mobo_sales/services/cf_access/cf_http_client.dart';

const _host = 'odoo.test';
final _server = Uri.parse('https://$_host');
const _challenge =
    'Bearer resource_metadata="https://$_host/.well-known/cloudflare-access-protected-resource"';

http.Response _json(Object body, [int status = 200]) => http.Response(
  jsonEncode(body),
  status,
  headers: {'content-type': 'application/json'},
);

/// Fake Cloudflare Access Managed OAuth server for [_host].
MockClient _accessServer({List<http.Request>? log}) => MockClient((req) async {
  log?.add(req);
  switch (req.url.path) {
    case '/web/webclient/version_info':
      return http.Response('', 401, headers: {'www-authenticate': _challenge});
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
        'revocation_endpoint': 'https://$_host/revoke',
        'code_challenge_methods_supported': ['S256'],
      });
    case '/register':
      return _json({'client_id': 'client-1'}, 201);
    case '/token':
      return _json({
        'access_token': 'access-1',
        'refresh_token': 'refresh-1',
        'expires_in': 900,
      });
    case '/revoke':
      return http.Response('', 200);
  }
  return http.Response('not found', 404);
});

CfTokenSet _tokens({
  String access = 'old',
  String? refresh = 'refresh-old',
  Duration expiresIn = const Duration(hours: 1),
}) => CfTokenSet(
  clientId: 'client-1',
  accessToken: access,
  refreshToken: refresh,
  expiresAt: DateTime.now().toUtc().add(expiresIn),
  tokenEndpoint: 'https://$_host/token',
  revocationEndpoint: 'https://$_host/revoke',
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late CfAccessStore store;

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    store = CfAccessStore(const FlutterSecureStorage());
  });

  group('PKCE', () {
    test('S256 challenge matches RFC 7636 appendix B', () {
      expect(
        CfAccessAuth.codeChallengeS256(
          'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        ),
        'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      );
    });

    test('verifier is 43 url-safe chars and random', () {
      final a = CfAccessAuth.generateVerifier();
      expect(a, matches(RegExp(r'^[A-Za-z0-9_-]{43}$')));
      expect(CfAccessAuth.generateVerifier(), isNot(a));
    });
  });

  group('store', () {
    test(
      'round-trips under cf_access.<host> and deleteAll leaves other keys',
      () async {
        FlutterSecureStorage.setMockInitialValues({'other': 'keep'});
        const raw = FlutterSecureStorage();
        store = CfAccessStore(raw);
        final set = _tokens();
        await store.write('Odoo.Test', set);

        expect(await raw.read(key: 'cf_access.odoo.test'), isNotNull);
        final read = await store.read('odoo.test');
        expect(read!.accessToken, 'old');
        expect(read.expiresAt!.isUtc, isTrue);
        expect(read.toJson(), set.toJson());

        await store.deleteAll();
        expect(await store.read('odoo.test'), isNull);
        expect(await raw.read(key: 'other'), 'keep');
      },
    );
  });

  group('probe', () {
    CfAccessAuth authFor(http.Response Function(http.Request) h) =>
        CfAccessAuth(client: MockClient((r) async => h(r)), store: store);

    test('200 -> NoAccess', () async {
      final r = await authFor((_) => http.Response('{}', 200)).probe(_server);
      expect(r, isA<CfNoAccess>());
    });

    test('401 + Bearer resource_metadata -> ManagedOAuth', () async {
      final r = await authFor(
        (_) =>
            http.Response('', 401, headers: {'www-authenticate': _challenge}),
      ).probe(_server);
      expect(r, isA<CfManagedOAuth>());
      expect(
        (r as CfManagedOAuth).resourceMetadataUrl.toString(),
        'https://$_host/.well-known/cloudflare-access-protected-resource',
      );
    });

    test('302 to cloudflareaccess.com -> AccessLoginRedirect', () async {
      final r = await authFor(
        (_) => http.Response(
          '',
          302,
          headers: {
            'location':
                'https://team.cloudflareaccess.com/cdn-cgi/access/login/$_host',
          },
        ),
      ).probe(_server);
      expect(r, isA<CfAccessLoginRedirect>());
    });

    test('200 html login page -> AccessLoginRedirect', () async {
      final r = await authFor(
        (_) => http.Response(
          '<html>https://team.cloudflareaccess.com/cdn-cgi/access/login</html>',
          200,
          headers: {'content-type': 'text/html; charset=utf-8'},
        ),
      ).probe(_server);
      expect(r, isA<CfAccessLoginRedirect>());
    });

    test('401 without resource_metadata -> NoAccess', () async {
      final r = await authFor(
        (_) => http.Response(
          '',
          401,
          headers: {'www-authenticate': 'Basic realm="x"'},
        ),
      ).probe(_server);
      expect(r, isA<CfNoAccess>());
    });
  });

  group('discovery', () {
    test(
      'follows resource_metadata to authorization server metadata',
      () async {
        final auth = CfAccessAuth(client: _accessServer(), store: store);
        final meta = await auth.discover(
          Uri.parse(
            'https://$_host/.well-known/cloudflare-access-protected-resource',
          ),
        );
        expect(
          meta.authorizationEndpoint.toString(),
          'https://$_host/authorize',
        );
        expect(meta.tokenEndpoint.toString(), 'https://$_host/token');
        expect(meta.registrationEndpoint.toString(), 'https://$_host/register');
        expect(meta.revocationEndpoint.toString(), 'https://$_host/revoke');
        expect(meta.resource, 'https://$_host');
      },
    );

    test(
      'accepts an authorization-server document as resource_metadata',
      () async {
        final auth = CfAccessAuth(
          client: MockClient(
            (_) async => _json({
              'authorization_endpoint': 'https://$_host/a',
              'token_endpoint': 'https://$_host/t',
            }),
          ),
          store: store,
        );
        final meta = await auth.discover(
          Uri.parse('https://$_host/.well-known/oauth-authorization-server'),
        );
        expect(meta.tokenEndpoint.path, '/t');
        expect(meta.registrationEndpoint, isNull);
      },
    );

    test('falls back to origin well-known when issuer path has none', () async {
      final seen = <String>[];
      final auth = CfAccessAuth(
        client: MockClient((req) async {
          seen.add(req.url.toString());
          if (req.url.path == '/meta') {
            return _json({
              'authorization_servers': ['https://$_host/team'],
            });
          }
          if (req.url.path == '/.well-known/oauth-authorization-server') {
            return _json({
              'authorization_endpoint': 'https://$_host/a',
              'token_endpoint': 'https://$_host/t',
            });
          }
          return http.Response('', 404);
        }),
        store: store,
      );
      final meta = await auth.discover(Uri.parse('https://$_host/meta'));
      expect(meta.authorizationEndpoint.path, '/a');
      expect(
        seen,
        contains('https://$_host/team/.well-known/oauth-authorization-server'),
      );
    });

    test('rejects non-https endpoints (refresh token must not go clear)', () {
      for (final key in [
        'authorization_endpoint',
        'token_endpoint',
        'registration_endpoint',
        'revocation_endpoint',
      ]) {
        expect(
          () => CfServerMetadata.fromJson({
            'authorization_endpoint': 'https://x/a',
            'token_endpoint': 'https://x/t',
            key: 'http://x/y',
          }),
          throwsA(isA<CfAccessException>()),
          reason: key,
        );
      }
    });

    test('rejects servers without S256', () {
      expect(
        () => CfServerMetadata.fromJson({
          'authorization_endpoint': 'https://x/a',
          'token_endpoint': 'https://x/t',
          'code_challenge_methods_supported': ['plain'],
        }),
        throwsA(isA<CfAccessException>()),
      );
    });
  });

  group('register', () {
    test('posts RFC 7591 body once and caches client_id', () async {
      final log = <http.Request>[];
      final auth = CfAccessAuth(
        client: _accessServer(log: log),
        store: store,
      );
      final meta = await auth.discover(
        Uri.parse(
          'https://$_host/.well-known/cloudflare-access-protected-resource',
        ),
      );

      expect(await auth.register(_host, meta), 'client-1');
      expect(await auth.register(_host, meta), 'client-1');

      final posts = log.where((r) => r.url.path == '/register').toList();
      expect(posts, hasLength(1));
      final body = jsonDecode(posts.single.body) as Map<String, dynamic>;
      expect(body['redirect_uris'], [CfAccessConfig.callbackUrl]);
      expect(body['token_endpoint_auth_method'], 'none');
      expect((await store.read(_host))!.clientId, 'client-1');
    });
  });

  group('signIn', () {
    test('PKCE + state round trip stores tokens', () async {
      final log = <http.Request>[];
      late Uri authorizeUrl;
      final auth = CfAccessAuth(
        client: _accessServer(log: log),
        store: store,
        authorize: (url) async {
          authorizeUrl = url;
          return Uri.parse(CfAccessConfig.callbackUrl).replace(
            queryParameters: {
              'code': 'the-code',
              'state': url.queryParameters['state']!,
            },
          );
        },
      );

      final set = await auth.signIn(_server);

      expect(set!.accessToken, 'access-1');
      expect(set.refreshToken, 'refresh-1');
      expect(set.expiresAt!.isUtc, isTrue);
      expect((await store.read(_host))!.accessToken, 'access-1');

      final q = authorizeUrl.queryParameters;
      expect(q['response_type'], 'code');
      expect(q['client_id'], 'client-1');
      expect(q['redirect_uri'], CfAccessConfig.callbackUrl);
      expect(q['code_challenge_method'], 'S256');

      final token = log.singleWhere((r) => r.url.path == '/token').bodyFields;
      expect(token['grant_type'], 'authorization_code');
      expect(token['code'], 'the-code');
      expect(
        CfAccessAuth.codeChallengeS256(token['code_verifier']!),
        q['code_challenge'],
      );
    });

    test('state mismatch is rejected before the code exchange', () async {
      final log = <http.Request>[];
      final auth = CfAccessAuth(
        client: _accessServer(log: log),
        store: store,
        authorize: (url) async => Uri.parse(
          CfAccessConfig.callbackUrl,
        ).replace(queryParameters: {'code': 'the-code', 'state': 'forged'}),
      );

      await expectLater(auth.signIn(_server), throwsA(isA<CfStateMismatch>()));
      expect(log.where((r) => r.url.path == '/token'), isEmpty);
      expect((await store.read(_host))!.hasTokens, isFalse);
    });

    test('returns null for servers without Access', () async {
      final auth = CfAccessAuth(
        client: MockClient((_) async => http.Response('{}', 200)),
        store: store,
      );
      expect(await auth.signIn(_server), isNull);
    });
  });

  group('refresh / revoke', () {
    test('refresh keeps the old refresh token when none is returned', () async {
      await store.write(_host, _tokens());
      final auth = CfAccessAuth(
        client: MockClient(
          (_) async => _json({'access_token': 'new', 'expires_in': 900}),
        ),
        store: store,
      );
      final next = await auth.refresh(_host);
      expect(next.accessToken, 'new');
      expect(next.refreshToken, 'refresh-old');
    });

    test('revoke posts the refresh token and clears the store', () async {
      await store.write(_host, _tokens());
      final log = <http.Request>[];
      final auth = CfAccessAuth(
        client: _accessServer(log: log),
        store: store,
      );
      await auth.revoke(_host);
      expect(log.single.bodyFields['token'], 'refresh-old');
      expect(await store.read(_host), isNull);
    });

    test('revoke clears the store even when offline', () async {
      await store.write(_host, _tokens());
      final auth = CfAccessAuth(
        client: MockClient((_) async => throw http.ClientException('offline')),
        store: store,
      );
      await auth.revoke(_host);
      expect(await store.read(_host), isNull);
    });
  });

  group('CfHttpClient', () {
    late int refreshCalls;
    late List<http.Request> apiCalls;
    late CfHttpClient Function(
      http.Response Function(http.Request) api, {
      http.Response Function(http.Request)? token,
      Duration tokenDelay,
    })
    build;

    setUp(() {
      refreshCalls = 0;
      apiCalls = [];
      build = (api, {token, tokenDelay = Duration.zero}) {
        final authClient = MockClient((req) async {
          refreshCalls++;
          await Future<void>.delayed(tokenDelay);
          return (token ??
              (_) => _json({
                'access_token': 'new',
                'refresh_token': 'refresh-new',
                'expires_in': 900,
              }))(req);
        });
        return CfHttpClient(
          inner: MockClient((req) async {
            apiCalls.add(req);
            return api(req);
          }),
          store: store,
          auth: CfAccessAuth(client: authClient, store: store),
        );
      };
    });

    String? authOf(http.Request r) => r.headers['Authorization'];

    http.Response bearerAware(http.Request r) => authOf(r) == 'Bearer old'
        ? http.Response('', 401, headers: {'www-authenticate': _challenge})
        : http.Response('ok', 200);

    test('adds bearer header for hosts with tokens', () async {
      await store.write(_host, _tokens());
      final client = build((_) => http.Response('ok', 200));
      await client.get(Uri.parse('https://$_host/x'));
      expect(authOf(apiCalls.single), 'Bearer old');
      expect(refreshCalls, 0);
    });

    test('refreshes before the request when < 60s remain', () async {
      await store.write(_host, _tokens(expiresIn: const Duration(seconds: 10)));
      final client = build((_) => http.Response('ok', 200));
      await client.get(Uri.parse('https://$_host/x'));
      expect(refreshCalls, 1);
      expect(apiCalls, hasLength(1));
      expect(authOf(apiCalls.single), 'Bearer new');
      expect((await store.read(_host))!.refreshToken, 'refresh-new');
    });

    test(
      '401 triggers exactly one refresh and one retry with the same body',
      () async {
        await store.write(_host, _tokens());
        final client = build(bearerAware);
        final res = await client.post(
          Uri.parse('https://$_host/x'),
          body: 'payload',
        );
        expect(res.statusCode, 200);
        expect(refreshCalls, 1);
        expect(apiCalls, hasLength(2));
        expect(authOf(apiCalls.last), 'Bearer new');
        expect(apiCalls.last.body, 'payload');
      },
    );

    test('a second 401 is returned, not looped', () async {
      await store.write(_host, _tokens());
      final client = build(
        (_) =>
            http.Response('', 401, headers: {'www-authenticate': _challenge}),
      );
      final res = await client.get(Uri.parse('https://$_host/x'));
      expect(res.statusCode, 401);
      expect(refreshCalls, 1);
      expect(apiCalls, hasLength(2));
    });

    test('non-Bearer 401 is not retried', () async {
      await store.write(_host, _tokens());
      final client = build((_) => http.Response('', 401));
      final res = await client.get(Uri.parse('https://$_host/x'));
      expect(res.statusCode, 401);
      expect(refreshCalls, 0);
      expect(apiCalls, hasLength(1));
    });

    test('streamed requests are not retried on 401', () async {
      await store.write(_host, _tokens());
      final client = build(bearerAware);
      final req = http.StreamedRequest('POST', Uri.parse('https://$_host/x'))
        ..sink.add([1, 2, 3])
        ..sink.close();
      final res = await client.send(req);
      expect(res.statusCode, 401);
      expect(refreshCalls, 0);
    });

    test('5 concurrent requests share one refresh', () async {
      await store.write(_host, _tokens(expiresIn: const Duration(seconds: 5)));
      final client = build(
        (_) => http.Response('ok', 200),
        tokenDelay: const Duration(milliseconds: 50),
      );
      final results = await Future.wait(
        List.generate(5, (i) => client.get(Uri.parse('https://$_host/x$i'))),
      );
      expect(results.every((r) => r.statusCode == 200), isTrue);
      expect(refreshCalls, 1);
      expect(apiCalls.map(authOf).toSet(), {'Bearer new'});
    });

    test('5 concurrent 401s also cause a single refresh', () async {
      await store.write(_host, _tokens());
      final client = build(
        bearerAware,
        tokenDelay: const Duration(milliseconds: 50),
      );
      final results = await Future.wait(
        List.generate(5, (i) => client.get(Uri.parse('https://$_host/x$i'))),
      );
      expect(results.every((r) => r.statusCode == 200), isTrue);
      expect(refreshCalls, 1);
    });

    test('hosts without tokens pass through untouched', () async {
      await store.write(_host, _tokens());
      final client = build((_) => http.Response('ok', 200));
      await client.get(
        Uri.parse('https://plain.test/x'),
        headers: {'Authorization': 'Basic abc'},
      );
      expect(authOf(apiCalls.single), 'Basic abc');
      expect(refreshCalls, 0);

      await client.get(Uri.parse('https://plain.test/y'));
      expect(authOf(apiCalls.last), isNull);
    });

    test('never sends the bearer over plain http', () async {
      await store.write(_host, _tokens(expiresIn: const Duration(seconds: 5)));
      final client = build((_) => http.Response('ok', 200));
      await client.get(Uri.parse('http://$_host/x'));
      expect(authOf(apiCalls.single), isNull);
      expect(refreshCalls, 0);
    });

    group('host without tokens', () {
      late CfExpiryNotifier expiry;
      late List<String> reported;

      CfHttpClient plain(http.Response Function(http.Request) api) {
        expiry = CfExpiryNotifier();
        reported = [];
        expiry.events.listen(reported.add);
        final inner = MockClient((req) async => api(req));
        return CfHttpClient(
          inner: inner,
          store: store,
          auth: CfAccessAuth(client: inner, store: store),
          expiry: expiry,
        );
      }

      test('a Managed OAuth challenge asks for sign-in once', () async {
        final client = plain(
          (_) => http.Response(
            'denied',
            401,
            headers: {'www-authenticate': _challenge},
          ),
        );
        final res = await client.get(Uri.parse('https://$_host/x'));
        await client.get(Uri.parse('https://$_host/y'));
        await Future<void>.delayed(Duration.zero);
        expect(res.statusCode, 401);
        expect(res.body, 'denied');
        expect(reported, [_host]);
      });

      test('other 401s and non-Access hosts do not', () async {
        final client = plain(
          (r) => r.url.path == '/basic'
              ? http.Response(
                  '',
                  401,
                  headers: {'www-authenticate': 'Basic realm="x"'},
                )
              : http.Response('', 401, headers: {'www-authenticate': 'Bearer'}),
        );
        await client.get(Uri.parse('https://$_host/basic'));
        await client.get(Uri.parse('https://$_host/bare'));
        await Future<void>.delayed(Duration.zero);
        expect(reported, isEmpty);
      });
    });

    test('rejected refresh clears tokens and throws CfAuthRequired', () async {
      await store.write(_host, _tokens(expiresIn: const Duration(seconds: 5)));
      final client = build(
        (_) => http.Response('ok', 200),
        token: (_) => _json({'error': 'invalid_grant'}, 400),
      );
      await expectLater(
        client.get(Uri.parse('https://$_host/x')),
        throwsA(isA<CfAuthRequired>().having((e) => e.host, 'host', _host)),
      );
      expect(await store.read(_host), isNull);
      expect(apiCalls, isEmpty);
    });

    test(
      'rejected refresh after a 401 clears tokens and throws CfAuthRequired',
      () async {
        await store.write(_host, _tokens());
        final client = build(bearerAware, token: (_) => http.Response('', 401));
        await expectLater(
          client.get(Uri.parse('https://$_host/x')),
          throwsA(isA<CfAuthRequired>()),
        );
        expect(await store.read(_host), isNull);
      },
    );

    test('server error during refresh keeps the tokens', () async {
      await store.write(_host, _tokens(expiresIn: const Duration(seconds: 5)));
      final client = build(
        (_) => http.Response('ok', 200),
        token: (_) => http.Response('', 503),
      );
      await expectLater(
        client.get(Uri.parse('https://$_host/x')),
        throwsA(isA<CfAccessException>()),
      );
      expect((await store.read(_host))!.refreshToken, 'refresh-old');
    });
  });

  group('Access login cookie (no Managed OAuth)', () {
    final jwt =
        'e30.${base64Url.encode(utf8.encode('{"exp":4102444800}')).replaceAll('=', '')}.sig';
    late CfExpiryNotifier expiry;
    late List<String> reported;
    late List<http.Request> calls;

    CfHttpClient clientFor(http.Response Function(http.Request) api) {
      expiry = CfExpiryNotifier();
      reported = [];
      expiry.events.listen(reported.add);
      calls = [];
      final inner = MockClient((req) async {
        calls.add(req);
        return api(req);
      });
      return CfHttpClient(
        inner: inner,
        store: store,
        auth: CfAccessAuth(client: inner, store: store),
        expiry: expiry,
      );
    }

    final loginRedirect = http.Response(
      '',
      302,
      headers: {'location': 'https://team.cloudflareaccess.com/login'},
    );

    test('expiry comes from the JWT exp claim', () {
      final t = CfTokenSet.accessCookie(jwt);
      expect(t.expiresAt, DateTime.utc(2100));
      expect(t.hasTokens, isTrue);
      expect(t.refreshToken, isNull);
    });

    test('a token that is not a JWT falls back to one hour', () {
      final now = DateTime.utc(2026, 1, 1);
      expect(
        CfTokenSet.accessCookie('opaque', now: now).expiresAt,
        now.add(const Duration(hours: 1)),
      );
    });

    test('sends cf-access-token, not Authorization', () async {
      await store.write(_host, CfTokenSet.accessCookie(jwt));
      final client = clientFor((_) => http.Response('ok', 200));
      await client.get(Uri.parse('https://$_host/x'));
      expect(calls.single.headers['cf-access-token'], jwt);
      expect(calls.single.headers['Authorization'], isNull);
    });

    test('survives a store round trip', () async {
      await store.write(_host, CfTokenSet.accessCookie(jwt));
      final t = (await store.read(_host))!;
      expect(t.isAccessCookie, isTrue);
      expect(t.authHeader, {'cf-access-token': jwt});
    });

    test(
      'redirect to the Access login page: token dropped, expiry reported',
      () async {
        await store.write(_host, CfTokenSet.accessCookie(jwt));
        final client = clientFor((_) => loginRedirect);
        await expectLater(
          client.post(Uri.parse('https://$_host/jsonrpc')),
          throwsA(isA<CfAuthRequired>()),
        );
        expect(await store.read(_host), isNull);
        await Future<void>.delayed(Duration.zero);
        expect(reported, [_host]);
      },
    );

    test('host without a token reports expiry on a login redirect', () async {
      final client = clientFor((_) => loginRedirect);
      final res = await client.post(Uri.parse('https://$_host/jsonrpc'));
      expect(res.statusCode, 302);
      await Future<void>.delayed(Duration.zero);
      expect(reported, [_host]);
    });

    test('expired cookie needs a new sign-in instead of a refresh', () async {
      await store.write(
        _host,
        CfTokenSet.accessCookie(
          'x.${base64Url.encode(utf8.encode('{"exp":1}')).replaceAll('=', '')}.y',
        ),
      );
      final client = clientFor((_) => http.Response('ok', 200));
      await expectLater(
        client.get(Uri.parse('https://$_host/x')),
        throwsA(isA<CfAuthRequired>()),
      );
      expect(calls, isEmpty);
      expect(await store.read(_host), isNull);
    });
  });
}
