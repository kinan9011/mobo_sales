import 'dart:convert';

import 'package:flutter/foundation.dart' show debugPrint;
import 'package:http/http.dart' as http;

/// A parsed HTML `<form>`: where it posts to and every named field it holds.
class HtmlForm {
  const HtmlForm(this.action, this.fields);

  /// The `action` attribute as written; empty means "the current URL".
  final String action;
  final Map<String, String> fields;

  /// All fields, with [overrides] replacing or adding values.
  Map<String, String> filled(Map<String, String> overrides) => {
    ...fields,
    ...overrides,
  };
}

final _tagRe = RegExp(r'<[^>]*>');
final _attrRe = RegExp(
  r'''([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))''',
);

Map<String, String> _attrs(String tag) => {
  for (final m in _attrRe.allMatches(tag))
    m.group(1)!.toLowerCase(): _decode(m.group(2) ?? m.group(3) ?? m.group(4)!),
};

String _decode(String s) => s
    .replaceAllMapped(RegExp(r'&#x([0-9a-fA-F]+);'), (m) {
      return String.fromCharCode(int.parse(m.group(1)!, radix: 16));
    })
    .replaceAllMapped(
      RegExp(r'&#(\d+);'),
      (m) => String.fromCharCode(int.parse(m.group(1)!)),
    )
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&apos;', "'")
    .replaceAll('&amp;', '&');

/// Finds the form that holds an input named [field] and collects ALL of its
/// named inputs (csrf_token, redirect, ...), so nothing is hard-coded.
/// Returns null when no such form exists.
HtmlForm? parseForm(String html, {required String field}) {
  final forms = RegExp(
    r'<form\b([^>]*)>(.*?)</form>',
    caseSensitive: false,
    dotAll: true,
  );
  for (final form in forms.allMatches(html)) {
    final fields = <String, String>{};
    final inputs = RegExp(r'<input\b[^>]*>', caseSensitive: false);
    for (final input in inputs.allMatches(form.group(2)!)) {
      final a = _attrs(input.group(0)!);
      final name = a['name'];
      if (name == null || name.isEmpty) continue;
      final type = (a['type'] ?? 'text').toLowerCase();
      if (const {'submit', 'button', 'image', 'file', 'reset'}.contains(type)) {
        continue;
      }
      if ((type == 'checkbox' || type == 'radio') &&
          !input.group(0)!.toLowerCase().contains('checked')) {
        continue;
      }
      fields[name] = a['value'] ?? (type == 'checkbox' ? 'on' : '');
    }
    // ponytail: selects are only noted by name (value ''), callers override
    // the ones they care about (`db`).
    final selects = RegExp(r'<select\b[^>]*>', caseSensitive: false);
    for (final s in selects.allMatches(form.group(2)!)) {
      final name = _attrs(s.group(0)!)['name'];
      if (name != null && name.isNotEmpty) fields.putIfAbsent(name, () => '');
    }
    if (fields.containsKey(field)) {
      return HtmlForm(_attrs(form.group(1)!)['action'] ?? '', fields);
    }
  }
  return null;
}

/// Text of the first element carrying the `alert` class, or null.
// ponytail: stops at the first closing tag of the same name; fine for Odoo's
// flat `<p class="alert ...">` / `<div class="alert ...">` messages.
String? alertText(String html) {
  final m = RegExp(
    r'''<(\w+)\b[^>]*\bclass\s*=\s*["'](?:[^"']*\s)?alert(?:\s[^"']*)?["'][^>]*>(.*?)</\1>''',
    caseSensitive: false,
    dotAll: true,
  ).firstMatch(html);
  if (m == null) return null;
  final text = _decode(
    m.group(2)!.replaceAll(_tagRe, ' '),
  ).replaceAll(RegExp(r'\s+'), ' ').trim();
  return text.isEmpty ? null : text;
}

/// Merges the (comma-joined) `Set-Cookie` header of a response into [jar].
/// Cookies that are emptied or expired (`Max-Age<=0`) are removed.
void mergeSetCookies(Map<String, String> jar, String? header) {
  if (header == null || header.isEmpty) return;
  // A comma only separates cookies when a `name=` follows; the comma inside
  // `Expires=Wed, 21 Oct ...` is followed by a date, not a name.
  for (final cookie in header.split(RegExp(r',(?=\s*[^;,=\s]+=)'))) {
    final parts = cookie.split(';');
    final eq = parts.first.indexOf('=');
    if (eq <= 0) continue;
    final name = parts.first.substring(0, eq).trim();
    final value = parts.first.substring(eq + 1).trim();
    final maxAge = parts
        .skip(1)
        .map((p) => p.trim().toLowerCase())
        .where((p) => p.startsWith('max-age='))
        .map((p) => int.tryParse(p.substring(8)))
        .firstOrNull;
    if (value.isEmpty || (maxAge != null && maxAge <= 0)) {
      jar.remove(name);
    } else {
      jar[name] = value;
    }
  }
}

sealed class TotpLoginResult {
  const TotpLoginResult();
}

/// Credentials accepted; Odoo now wants the authenticator code.
class TotpCodeRequired extends TotpLoginResult {
  const TotpCodeRequired();
}

/// Rejected. [message] comes from the page's alert, or is generic. When the
/// code was wrong the flow is still waiting for a code ([OdooTotpLogin.awaitingCode]).
class TotpLoginFailed extends TotpLoginResult {
  const TotpLoginFailed(this.message);
  final String message;
}

/// Signed in; [sessionId] is the Odoo `session_id` cookie.
class TotpLoginSuccess extends TotpLoginResult {
  const TotpLoginSuccess(this.sessionId);
  final String sessionId;
}

/// Odoo web login (with optional TOTP step) as plain form requests, so the
/// shared client (Cloudflare bearer, timeouts) is used instead of a WebView.
/// The client has no cookie store, so this keeps its own small jar.
class OdooTotpLogin {
  OdooTotpLogin({
    required http.Client client,
    required String serverUrl,
    required String database,
    String? userAgent,
  }) : _client = client,
       _server = Uri.parse(serverUrl),
       _database = database,
       _userAgent = userAgent;

  static const int maxRedirects = 5;
  static const String genericFailure =
      'Invalid code or login failed. Please try again.';

  final http.Client _client;
  final Uri _server;
  final String _database;
  final String? _userAgent;

  final Map<String, String> _jar = {};
  // Request path per hop, shown on unexplained failures so a user report says
  // where Odoo sent us (no cookie values or bodies).
  final List<String> _trace = [];
  HtmlForm? _totpForm;
  Uri? _totpUrl;

  /// True while a TOTP form is held, i.e. [submitCode] can be called.
  bool get awaitingCode => _totpForm != null;

  /// Logs in with [login]/[password]; yields [TotpCodeRequired] for 2FA users.
  Future<TotpLoginResult> start(String login, String password) async {
    _jar.clear();
    _trace.clear();
    _totpForm = null;
    _totpUrl = null;
    try {
      var page = await _send(
        'GET',
        _server.replace(path: '/web/login', queryParameters: {'db': _database}),
      );
      if (page.url.path.startsWith('/web/database/')) {
        // Database selector: pick our db the way its link does.
        page = await _send(
          'GET',
          _server.replace(path: '/web', queryParameters: {'db': _database}),
        );
      }
      if (page.status >= 400) {
        return TotpLoginFailed(
          'Odoo login page not recognized (HTTP ${page.status} at ${page.url.path}).',
        );
      }
      // JSON-RPC instead of the HTML form: the form post is guarded by the
      // login captcha (Turnstile / reCAPTCHA, 422 without a browser token),
      // this route is not. It is also what Odoo's own mobile app uses.
      final auth = await _send(
        'POST',
        _server.replace(path: '/web/session/authenticate'),
        json: {
          'jsonrpc': '2.0',
          'method': 'call',
          'params': {'db': _database, 'login': login, 'password': password},
        },
      );
      Map<String, dynamic>? data;
      try {
        data = jsonDecode(auth.body) as Map<String, dynamic>;
      } catch (_) {}
      if (data == null) {
        return TotpLoginFailed(
          'Odoo rejected the request (HTTP ${auth.status} at ${auth.url.path}).',
        );
      }
      final error = data['error'];
      if (error is Map) {
        final message = (error['data'] as Map?)?['message']?.toString();
        return TotpLoginFailed(
          message == null || message == 'Access Denied'
              ? 'Wrong login/password'
              : message,
        );
      }
      final uid = (data['result'] as Map?)?['uid'];
      if (uid != null) {
        // No second factor on this account: the session is already signed in.
        final sessionId = _jar['session_id'];
        return sessionId == null || sessionId.isEmpty
            ? TotpLoginFailed(
                'Signed in, but Odoo returned no session (HTTP ${auth.status}).',
              )
            : TotpLoginSuccess(sessionId);
      }
      // uid null: password accepted, Odoo keeps the user pending the code.
      return _classify(
        await _send('GET', _server.replace(path: '/web/login/totp')),
      );
    } on _RedirectLimit catch (e) {
      return TotpLoginFailed(e.message);
    }
  }

  /// Posts [code] to the TOTP form returned by [start].
  Future<TotpLoginResult> submitCode(String code) async {
    final form = _totpForm;
    final url = _totpUrl;
    if (form == null || url == null) {
      return const TotpLoginFailed(genericFailure);
    }
    try {
      final page = await _post(form, url, form.filled({'totp_token': code}));
      return _classify(page);
    } on _RedirectLimit catch (e) {
      return TotpLoginFailed(e.message);
    }
  }

  TotpLoginResult _classify(_Page page) {
    final path = page.url.path;
    final alert = alertText(page.body);

    if (path.startsWith('/web/login/totp')) {
      final form = parseForm(page.body, field: 'totp_token');
      if (form == null) {
        return TotpLoginFailed(
          'Odoo rejected the request (HTTP ${page.status} at $path).',
        );
      }
      _totpForm = form;
      _totpUrl = page.url;
      // A fresh form with an alert is a rejected code; keep it so the user
      // can retry without restarting the whole flow.
      return alert != null ? TotpLoginFailed(alert) : const TotpCodeRequired();
    }
    _totpForm = null;
    _totpUrl = null;
    if (path.startsWith('/web/login') || path.startsWith('/web/database/')) {
      return TotpLoginFailed(
        alert ??
            'Odoo ended the login session. Please try again.\n'
                '${_trace.skip(_trace.length > 4 ? _trace.length - 4 : 0).join('\n')}',
      );
    }
    final sessionId = _jar['session_id'];
    if (page.status >= 400 || sessionId == null || sessionId.isEmpty) {
      debugPrint(
        '[OdooTotpLogin] no session: path=$path status=${page.status} '
        'hasSessionCookie=${sessionId != null && sessionId.isNotEmpty}',
      );
      return TotpLoginFailed(
        'Signed in, but Odoo returned no session (HTTP ${page.status} at $path).',
      );
    }
    return TotpLoginSuccess(sessionId);
  }

  Future<_Page> _post(HtmlForm form, Uri page, Map<String, String> fields) {
    final action = form.action.trim();
    return _send(
      'POST',
      action.isEmpty ? page : page.resolve(action),
      body: fields,
    );
  }

  /// Sends one request and follows redirects by hand (max [maxRedirects]),
  /// keeping the cookie jar up to date after every response.
  Future<_Page> _send(
    String method,
    Uri url, {
    Map<String, String>? body,
    Map<String, dynamic>? json,
  }) async {
    var m = method;
    var u = url;
    var b = body;
    for (var hops = 0; ; hops++) {
      // Odoo behind a TLS proxy without proxy_mode emits absolute http://
      // redirects to its own host; upgrade them instead of failing the login.
      if (u.host == _server.host &&
          u.scheme == 'http' &&
          _server.scheme == 'https') {
        u = u.replace(scheme: 'https', port: _server.port);
      }
      // Credentials, the cookie jar and every hop stay on the server origin
      // (form actions and redirects are server-controlled).
      if (u.scheme != _server.scheme ||
          u.host != _server.host ||
          u.port != _server.port) {
        debugPrint('[OdooTotpLogin] refused off-origin hop: $u');
        throw _RedirectLimit('Odoo redirected to another address: $u');
      }
      final request = http.Request(m, u)..followRedirects = false;
      request.headers['Accept'] = json == null
          ? 'text/html,application/xhtml+xml'
          : 'application/json';
      if (_userAgent != null) request.headers['User-Agent'] = _userAgent;
      if (_jar.isNotEmpty) {
        request.headers['Cookie'] = _jar.entries
            .map((e) => '${e.key}=${e.value}')
            .join('; ');
      }
      if (b != null) request.bodyFields = b;
      if (json != null && m == method) {
        request.headers['Content-Type'] = 'application/json';
        request.body = jsonEncode(json);
      }

      final res = await http.Response.fromStream(await _client.send(request));
      mergeSetCookies(_jar, res.headers['set-cookie']);
      // Names only, never cookie values or bodies.
      final hop =
          '$m ${u.path} ${res.statusCode}'
          '${res.headers['location'] == null ? '' : '>${res.headers['location']}'}'
          ' [${_jar.keys.join(',')}]';
      debugPrint('[OdooTotpLogin] $hop');
      _trace.add(hop.length > 90 ? '${hop.substring(0, 90)}…' : hop);

      final location = res.headers['location'];
      final redirect = const {301, 302, 303, 307, 308}.contains(res.statusCode);
      if (!redirect || location == null) {
        return _Page(u, res.statusCode, res.body);
      }
      if (hops >= maxRedirects) {
        throw _RedirectLimit('Odoo redirected too many times (last: $u).');
      }
      u = u.resolve(location);
      if (res.statusCode != 307 && res.statusCode != 308) {
        m = 'GET';
        b = null;
      }
    }
  }
}

class _Page {
  const _Page(this.url, this.status, this.body);
  final Uri url;
  final int status;
  final String body;
}

class _RedirectLimit implements Exception {
  const _RedirectLimit(this.message);
  final String message;
}
