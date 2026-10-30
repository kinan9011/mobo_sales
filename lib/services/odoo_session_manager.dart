import 'dart:convert';
import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart' show debugPrint;
import 'package:odoo_rpc/odoo_rpc.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:http/http.dart' as http;
import 'package:flutter_inappwebview/flutter_inappwebview.dart' as webview;
import '../utils/cf_host_release.dart';
import 'remote_sign_out.dart';
import 'secret_store.dart';
import 'shared_http.dart';

/// Value object that holds all data for an active Odoo user session.
class OdooSessionModel {
  final String sessionId;
  final String userLogin;
  final String password;
  final String serverUrl;
  final String database;
  final int? userId;
  final String? userName;
  final DateTime? expiresAt;
  final int? selectedCompanyId;
  final List<int> allowedCompanyIds;
  final String? serverVersion;

  OdooSessionModel({
    required this.sessionId,
    required this.userLogin,
    required this.password,
    required this.serverUrl,
    required this.database,
    this.userId,
    this.userName,
    this.expiresAt,
    this.selectedCompanyId,
    this.allowedCompanyIds = const [],
    this.serverVersion,
  });

  OdooSession get odooSession {
    return OdooSession(
      id: sessionId,
      userId: userId ?? 0,
      partnerId: 0,
      userLogin: userLogin,
      userName: userName ?? '',
      userLang: '',
      userTz: '',
      isSystem: false,
      dbName: database,
      serverVersion: serverVersion ?? '',
      companyId: selectedCompanyId ?? 0,
      allowedCompanies: allowedCompanyIds
          .map((id) => Company(id: id, name: 'Company $id'))
          .toList(),
    );
  }

  factory OdooSessionModel.fromOdooSession(
    OdooSession session,
    String userLogin,
    String password,
    String serverUrl,
    String database,
  ) {
    return OdooSessionModel(
      sessionId: session.id,
      userLogin: userLogin,
      password: password,
      serverUrl: serverUrl,
      database: database,
      userId: session.userId,
      userName: session.userName,

      expiresAt: DateTime.now().add(const Duration(hours: 24)),
      serverVersion: session.serverVersion,
    );
  }

  /// Returns a copy of this session with the specified fields replaced.
  OdooSessionModel copyWith({
    String? sessionId,
    String? userLogin,
    String? password,
    String? serverUrl,
    String? database,
    int? userId,
    String? userName,
    DateTime? expiresAt,
    int? selectedCompanyId,
    List<int>? allowedCompanyIds,
    String? serverVersion,
  }) {
    return OdooSessionModel(
      sessionId: sessionId ?? this.sessionId,
      userLogin: userLogin ?? this.userLogin,
      password: password ?? this.password,
      serverUrl: serverUrl ?? this.serverUrl,
      database: database ?? this.database,
      userId: userId ?? this.userId,
      userName: userName ?? this.userName,
      expiresAt: expiresAt ?? this.expiresAt,
      selectedCompanyId: selectedCompanyId ?? this.selectedCompanyId,
      allowedCompanyIds: allowedCompanyIds ?? this.allowedCompanyIds,
      serverVersion: serverVersion ?? this.serverVersion,
    );
  }

  /// Persists this session to `SharedPreferences`.
  Future<void> saveToPrefs() async {
    final prefs = await SharedPreferences.getInstance();

    final biometricEnabled = prefs.getBool('biometric_enabled');

    // Secrets live in secure storage, never in prefs.
    await SecretStore.instance.write('sessionId', sessionId);
    await SecretStore.instance.write('password', password);
    await prefs.remove('sessionId');
    await prefs.remove('password');
    await prefs.setString('userLogin', userLogin);
    await prefs.setString('database', database);
    await prefs.setString('serverUrl', serverUrl);
    if (userId != null) {
      await prefs.setInt('userId', userId!);
    } else {
      await prefs.remove('userId');
    }
    if (userName != null) {
      await prefs.setString('userName', userName!);
    }
    if (expiresAt != null) {
      await prefs.setString('expiresAt', expiresAt!.toIso8601String());
    }
    if (serverVersion != null) {
      await prefs.setString('serverVersion', serverVersion!);
    }
    if (selectedCompanyId != null) {
      await prefs.setInt('selected_company_id', selectedCompanyId!);
    }
    await prefs.setStringList(
      'selected_allowed_company_ids',
      allowedCompanyIds.map((e) => e.toString()).toList(),
    );
    await prefs.setBool('isLoggedIn', true);

    if (biometricEnabled != null) {
      await prefs.setBool('biometric_enabled', biometricEnabled);
    }
  }

  /// Restores a session from `SharedPreferences`, or returns `null` if none exists.
  static Future<OdooSessionModel?> fromPrefs() async {
    final prefs = await SharedPreferences.getInstance();
    final isLoggedIn = prefs.getBool('isLoggedIn') ?? false;

    if (!isLoggedIn) {
      return null;
    }

    String? sessionId;
    String? password;
    try {
      sessionId = await SecretStore.instance.read('sessionId');
      password = await SecretStore.instance.read('password');
    } catch (_) {
      return null;
    }
    final userLogin = prefs.getString('userLogin');
    final rawServerUrl = prefs.getString('serverUrl');
    final database = prefs.getString('database');
    final userId = prefs.getInt('userId');
    final userName = prefs.getString('userName');
    final expiresAtStr = prefs.getString('expiresAt');
    final serverVersion = prefs.getString('serverVersion');
    final selectedCompanyId = prefs.getInt('selected_company_id');
    final allowedCompanyIds =
        prefs
            .getStringList('selected_allowed_company_ids')
            ?.map((e) => int.tryParse(e) ?? -1)
            .where((e) => e > 0)
            .toList() ??
        [];

    if ([
      sessionId,
      userLogin,
      password,
      rawServerUrl,
      database,
    ].contains(null)) {
      return null;
    }

    String serverUrl = rawServerUrl!.trim();
    while (serverUrl.endsWith('/')) {
      serverUrl = serverUrl.substring(0, serverUrl.length - 1);
    }
    if (!serverUrl.startsWith('http://') && !serverUrl.startsWith('https://')) {
      serverUrl = 'https://$serverUrl';
    }

    final model = OdooSessionModel(
      sessionId: sessionId!,
      userLogin: userLogin!,
      password: password!,
      serverUrl: serverUrl,
      database: database!,
      userId: userId,
      userName: userName,
      expiresAt: expiresAtStr != null ? DateTime.tryParse(expiresAtStr) : null,
      selectedCompanyId: selectedCompanyId,
      allowedCompanyIds: allowedCompanyIds,
      serverVersion: serverVersion,
    );

    return model;
  }
}

/// Manages the low-level Odoo RPC client, session caching, and authentication.
class OdooSessionManager {
  /// The app-wide shared client (timeouts, Cloudflare bearer injection).
  static http.BaseClient get ioClient => SharedHttp.client;

  static const String USER_AGENT =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
  static const int _maxAttempts = 3;
  static const Duration _baseDelay = Duration(milliseconds: 500);

  static Completer<bool>? _refreshCompleter;

  static OdooClient? _cachedClient;
  static OdooSessionModel? _cachedSession;
  static DateTime? _lastAuthTime;
  static const Duration _cacheValidDuration = Duration(minutes: 5);

  static Function(OdooSessionModel)? _onSessionUpdated;
  static Function()? _onSessionCleared;

  static bool _isRetryableError(Object e) {
    if (e is SocketException) return true;
    if (e is TimeoutException) return true;
    if (e is http.ClientException) return true;

    final es = e.toString().toLowerCase();
    return es.contains('connection reset') ||
        es.contains('timed out') ||
        es.contains('connection refused');
  }

  /// Registers callbacks for session update and clear events.
  static void setSessionCallbacks({
    Function(OdooSessionModel)? onSessionUpdated,
    Function()? onSessionCleared,
  }) {
    _onSessionUpdated = onSessionUpdated;
    _onSessionCleared = onSessionCleared;
  }

  /// Returns the current session from cache or `SharedPreferences`.
  static Future<OdooSessionModel?> getCurrentSession() async {
    if (_cachedSession != null) return _cachedSession;
    _cachedSession = await OdooSessionModel.fromPrefs();
    return _cachedSession;
  }

  /// Returns an authenticated `OdooClient`, building one from the cached session if needed.
  static Future<OdooClient?> getClient() async {
    final session = await getCurrentSession();
    if (session == null) {
      return null;
    }

    if (_cachedClient != null &&
        _lastAuthTime != null &&
        DateTime.now().difference(_lastAuthTime!) < _cacheValidDuration) {
      return _cachedClient;
    }

    final client = OdooClient(
      session.serverUrl,
      httpClient: ioClient,
      sessionId: session.odooSession,
    );

    bool sessionRestored = session.sessionId.isNotEmpty;
    if (sessionRestored) {}

    try {
      if (!sessionRestored && session.sessionId.isEmpty) {
        for (int attempt = 1; attempt <= _maxAttempts; attempt++) {
          try {
            await client.authenticate(
              session.database,
              session.userLogin,
              session.password,
            );
            break;
          } catch (e) {
            if (e is FormatException && e.toString().contains('<html>')) {
              throw Exception(
                'Server returned HTML instead of JSON. Please check server URL and ensure Odoo is running.',
              );
            }

            if (attempt >= _maxAttempts || !_isRetryableError(e)) rethrow;
            final delay = _baseDelay * attempt;
            await Future.delayed(delay);
          }
        }
      } else {
        if (!sessionRestored) {
        } else {}
      }

      if (client.sessionId != null) {}

      _cachedClient = client;
      _lastAuthTime = DateTime.now();

      return client;
    } catch (e) {
      _cachedClient = null;
      _lastAuthTime = null;

      if (e.toString().contains(
        "type 'Null' is not a subtype of type 'Map<String, dynamic>'",
      )) {
        return client;
      }

      rethrow;
    }
  }

  /// Authenticates with credentials and saves the session to preferences.
  static Future<bool> loginAndSaveSession({
    required String serverUrl,
    required String database,
    required String userLogin,
    required String password,
  }) async {
    if (!serverUrl.startsWith('http://') && !serverUrl.startsWith('https://')) {
      throw Exception(
        'Invalid server URL format. Please include http:// or https://',
      );
    }

    try {
      final sessionModel = await authenticate(
        serverUrl: serverUrl,
        database: database,
        username: userLogin,
        password: password,
      );

      if (sessionModel == null) {
        return false;
      }

      await sessionModel.saveToPrefs();
      _cachedSession = sessionModel;

      if (_onSessionUpdated != null) {
        _onSessionUpdated!(sessionModel);
      }

      return true;
    } catch (e) {
      if (e is FormatException && e.toString().contains('<html>')) {
        throw Exception(
          'Server returned HTML instead of JSON. Please check server URL and ensure Odoo is running.',
        );
      }

      final errorStr = e.toString().toLowerCase();
      if (errorStr.contains('mfa') ||
          errorStr.contains('two factor') ||
          errorStr.contains('2fa') ||
          errorStr.contains('totp') ||
          errorStr.contains('verification code required')) {
        rethrow;
      }

      return false;
    }
  }

  /// Clears all session preferences and invalidates the cached client.
  ///
  /// Before that, best-effort and time-bounded: destroys the Odoo session
  /// while the Cloudflare bearer is still valid, then revokes and deletes the
  /// Cloudflare tokens of [cfHosts] (default: the current host, only when no
  /// other stored account uses it). [cfReleaseAll] wipes every host's tokens.
  /// [remote] false skips the network and only deletes tokens locally.
  static Future<void> logout({
    Iterable<String>? cfHosts,
    bool cfReleaseAll = false,
    bool remote = true,
  }) async {
    final prefs = await SharedPreferences.getInstance();

    try {
      final session = await getCurrentSession();
      final server = session == null ? null : Uri.tryParse(session.serverUrl);
      await remoteSignOut(
        client: ioClient,
        auth: SharedHttp.auth,
        odooServer: server != null && server.host.isNotEmpty ? server : null,
        sessionId: session?.sessionId,
        releaseHosts:
            cfHosts ?? _currentHostIfUnshared(prefs, session) ?? const [],
        releaseAll: cfReleaseAll,
        remote: remote,
      );
    } catch (_) {}

    const keysToRemove = <String>[
      'isLoggedIn',
      'sessionId',
      'userLogin',
      'password',
      'serverUrl',
      'database',
      'userId',
      'userName',
      'expiresAt',
      'serverVersion',
    ];
    for (final k in keysToRemove) {
      await prefs.remove(k);
    }
    try {
      await SecretStore.instance.delete('sessionId');
      await SecretStore.instance.delete('password');
    } catch (_) {}

    try {
      await webview.CookieManager.instance().deleteAllCookies().timeout(
        const Duration(seconds: 3),
      );
    } catch (e) {}

    clearClientCache();
    _cachedSession = null;

    if (_onSessionCleared != null) {
      _onSessionCleared!();
    }
  }

  /// The current session's host, unless another stored account uses it too.
  static Set<String>? _currentHostIfUnshared(
    SharedPreferences prefs,
    OdooSessionModel? session,
  ) {
    if (session == null) return null;
    final others = <Map<String, dynamic>>[];
    for (final raw in prefs.getStringList('stored_accounts') ?? <String>[]) {
      try {
        final account = Map<String, dynamic>.from(jsonDecode(raw));
        final isCurrent =
            account['userId']?.toString() == session.userId?.toString() &&
            account['serverUrl'] == session.serverUrl &&
            account['database'] == session.database;
        if (!isCurrent) others.add(account);
      } catch (_) {}
    }
    return hostsToReleaseAfterRemoval(others, {
      'serverUrl': session.serverUrl,
    }, null);
  }

  /// Invalidates the in-memory client and session cache.
  static void clearClientCache() {
    _cachedClient = null;
    _lastAuthTime = null;
    _cachedSession = null;
  }

  /// Saves [sessionModel] to preferences and resets the client cache.
  static Future<void> updateSession(OdooSessionModel sessionModel) async {
    try {
      await sessionModel.saveToPrefs();

      _cachedSession = sessionModel;

      clearClientCache();

      if (_onSessionUpdated != null) {
        _onSessionUpdated!(sessionModel);
      }
    } catch (e) {
      rethrow;
    }
  }

  /// Authenticates using an existing [sessionId] without re-entering credentials.
  static Future<bool> loginWithSessionId({
    required String serverUrl,
    required String database,
    required String userLogin,
    required String password,
    required String sessionId,
    Map<String, dynamic>? sessionInfo,
  }) async {
    try {
      String normalizedUrl = serverUrl.trim();
      if (!normalizedUrl.startsWith('http://') &&
          !normalizedUrl.startsWith('https://')) {
        normalizedUrl = 'https://$normalizedUrl';
      }
      if (normalizedUrl.endsWith('/')) {
        normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length - 1);
      }
      if (normalizedUrl.endsWith('/odoo')) {
        normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length - 5);
      }

      final Map<String, dynamic> info =
          sessionInfo ?? await getSessionInfo(normalizedUrl, sessionId);

      if (info['uid'] == null || info['uid'] is bool) {
        throw Exception('Failed to get valid session info');
      }

      final int userId = info['uid'] is int
          ? info['uid']
          : int.parse(info['uid'].toString());
      final String serverVersion = info['server_version']?.toString() ?? '17.0';

      final userInfo = await _fetchUserCompanies(
        userId,
        url: normalizedUrl,
        sessionId: sessionId,
        database: database,
      );
      int? selectedCompanyId = userInfo['company_id'];
      List<int> allowedCompanyIds =
          (userInfo['company_ids'] as List<int>?) ?? [];

      selectedCompanyId ??= info['company_id'];
      if (allowedCompanyIds.isEmpty) {
        allowedCompanyIds = [selectedCompanyId ?? 1];
      }

      final client = OdooClient(
        normalizedUrl,
        httpClient: ioClient,
        sessionId: OdooSession(
          id: sessionId,
          userId: userId,
          partnerId: 0,
          userLogin: userLogin,
          userName: info['name'] ?? userLogin,
          userLang: '',
          userTz: '',
          isSystem: false,
          dbName: database,
          serverVersion: serverVersion,
          companyId: selectedCompanyId ?? 0,
          allowedCompanies: [],
        ),
      );

      final sessionModel = OdooSessionModel(
        sessionId: sessionId,
        userLogin: userLogin,
        password: password,
        serverUrl: normalizedUrl,
        database: database,
        userId: userId,
        userName: info['name'] ?? userLogin,
        expiresAt: DateTime.now().add(const Duration(hours: 24)),
        selectedCompanyId: selectedCompanyId,
        allowedCompanyIds: allowedCompanyIds,
        serverVersion: serverVersion,
      );

      await sessionModel.saveToPrefs();
      _cachedSession = sessionModel;
      _cachedClient = client;
      _lastAuthTime = DateTime.now();

      _onSessionUpdated?.call(sessionModel);

      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool('isLoggedIn', true);

      return true;
    } catch (e) {
      debugPrint('[OdooSessionManager] loginWithSessionId failed: $e');
      return false;
    }
  }

  /// Fetches session metadata from the Odoo server for the given [sessionId].
  static Future<Map<String, dynamic>> getSessionInfo(
    String url,
    String sessionId,
  ) async {
    for (int attempt = 1; attempt <= _maxAttempts; attempt++) {
      try {
        final response = await ioClient.post(
          Uri.parse('$url/web/session/get_session_info'),
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': USER_AGENT,
            'Origin': url,
            'Referer': '$url/web',
            'Cookie': 'session_id=$sessionId',
          },
          body: jsonEncode({
            "jsonrpc": "2.0",
            "method": "call",
            "params": {},
            "id": 1,
          }),
        );

        if (response.statusCode != 200) {
          throw Exception('Failed to get session info: ${response.statusCode}');
        }

        final data = jsonDecode(response.body);
        if (data['error'] != null) {
          throw Exception(data['error']['message'] ?? 'Session info error');
        }
        return Map<String, dynamic>.from(data['result']);
      } catch (e) {
        if (attempt >= _maxAttempts || !_isRetryableError(e)) rethrow;
        await Future.delayed(_baseDelay * attempt);
      }
    }
    throw Exception('getSessionInfo failed after $_maxAttempts attempts');
  }

  /// Executes an RPC `call_kw` request authenticated by [sessionId].
  static Future<dynamic> callKwWithSession({
    required String url,
    required String sessionId,
    required Map<String, dynamic> payload,
  }) async {
    for (int attempt = 1; attempt <= _maxAttempts; attempt++) {
      try {
        final res = await ioClient.post(
          Uri.parse('$url/web/dataset/call_kw'),
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': USER_AGENT,
            'Origin': url,
            'Referer': '$url/web',
            'Cookie': 'session_id=$sessionId',
            'X-Openerp-Session-Id': sessionId,
          },
          body: jsonEncode(payload),
        );

        if (res.statusCode != 200) {
          throw Exception('RPC Session Error ${res.statusCode}: ${res.body}');
        }

        final data = jsonDecode(res.body);
        if (data['error'] != null) {
          throw Exception(data['error']['message'] ?? 'RPC Session Error');
        }
        return data['result'];
      } catch (e) {
        if (attempt >= _maxAttempts || !_isRetryableError(e)) rethrow;
        await Future.delayed(_baseDelay * attempt);
      }
    }
    throw Exception('callKwWithSession failed after $_maxAttempts attempts');
  }

  /// Parses the major version number from an Odoo [version] string.
  static int parseMajorVersion(String version) {
    try {
      final parts = version.split('.');
      if (parts.isNotEmpty) {
        return int.parse(parts[0]);
      }
    } catch (e) {}
    return 0;
  }

  /// Authenticates against Odoo and returns a populated [OdooSessionModel].
  static Future<OdooSessionModel?> authenticate({
    required String serverUrl,
    required String database,
    required String username,
    required String password,
    bool autoLoadCompanies = true,
  }) async {
    if (serverUrl.isEmpty || database.isEmpty || username.isEmpty) {
      throw Exception('Invalid login parameters');
    }

    String normalizedUrl = serverUrl.trim();
    if (!normalizedUrl.startsWith('http://') &&
        !normalizedUrl.startsWith('https://')) {
      normalizedUrl = 'https://$normalizedUrl';
    }
    if (normalizedUrl.endsWith('/')) {
      normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length - 1);
    }
    if (normalizedUrl.endsWith('/odoo')) {
      normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length - 5);
    }

    final client = OdooClient(normalizedUrl, httpClient: ioClient);

    for (int attempt = 1; attempt <= _maxAttempts; attempt++) {
      try {
        OdooSession? odooSession;
        try {
          odooSession = await client.authenticate(database, username, password);
        } catch (e) {
          if (e.toString().contains(
            "type 'Null' is not a subtype of type 'Map<String, dynamic>'",
          )) {
            try {
              final uri = Uri.parse('$normalizedUrl/web/session/authenticate');
              final response = await ioClient.post(
                uri,
                headers: {'Content-Type': 'application/json'},
                body: jsonEncode({
                  'jsonrpc': '2.0',
                  'method': 'call',
                  'params': {
                    'db': database,
                    'login': username,
                    'password': password,
                  },
                  'id': DateTime.now().millisecondsSinceEpoch,
                }),
              );

              if (response.statusCode == 200) {
                final authBody = jsonDecode(response.body);
                final result = authBody['result'];
                final error = authBody['error'];

                if (error != null) {
                  throw Exception(error['message'] ?? 'Authentication error');
                }

                if (result != null) {
                  var uid = result['uid'];
                  if (uid is bool) uid = null;

                  String? sessionId;
                  if (result['session_id'] != null) {
                    sessionId = result['session_id'];
                  } else if (response.headers['set-cookie'] != null) {
                    final cookies = response.headers['set-cookie']!;
                    final sessionMatch = RegExp(
                      r'session_id=([^;]+)',
                    ).firstMatch(cookies);
                    sessionId = sessionMatch?.group(1);
                  }

                  if (sessionId != null) {
                    if (uid == null) {
                      throw Exception('two factor authentication required');
                    }

                    odooSession = OdooSession(
                      id: sessionId,
                      userId: uid,
                      partnerId: result['partner_id'] ?? 0,
                      userLogin: result['username'] ?? username,
                      userName: result['name'] ?? '',
                      userLang: result['user_context']?['lang'] ?? 'en_US',
                      userTz: result['user_context']?['tz'] ?? 'UTC',
                      isSystem: result['is_system'] ?? false,
                      dbName: result['db'] ?? database,
                      serverVersion: result['server_version'] ?? '',
                      companyId: result['company_id'] ?? 0,
                      allowedCompanies: [],
                    );
                  } else {
                    throw Exception('No session_id found in auth response');
                  }
                } else {
                  throw Exception('Authentication returned null result');
                }
              }
            } catch (manualEx) {
              rethrow;
            }
          }

          if (odooSession == null) rethrow;
        }

        int? selectedCompanyId;
        List<int> allowedCompanyIds = [];

        if (autoLoadCompanies) {
          try {
            final userInfo = await _fetchUserCompanies(
              odooSession.userId,
              url: normalizedUrl,
              sessionId: odooSession.id,
              database: database,
            );
            selectedCompanyId = userInfo['company_id'];
            allowedCompanyIds = (userInfo['company_ids'] as List<int>?) ?? [];

            if (selectedCompanyId != null &&
                !allowedCompanyIds.contains(selectedCompanyId)) {
              allowedCompanyIds.add(selectedCompanyId);
            }
          } catch (e) {
            selectedCompanyId = odooSession.companyId;
            allowedCompanyIds = [selectedCompanyId ?? 1];
          }
        }

        final sessionData = OdooSessionModel(
          sessionId: odooSession.id,
          userLogin: username,
          password: password,
          serverUrl: normalizedUrl,
          database: database,
          userId: odooSession.userId,
          userName: odooSession.userName,
          expiresAt: DateTime.now().add(const Duration(hours: 24)),
          selectedCompanyId: selectedCompanyId,
          allowedCompanyIds: allowedCompanyIds,
          serverVersion: odooSession.serverVersion,
        );

        return sessionData;
      } catch (e) {
        if (e is FormatException && e.toString().contains('<html>')) {
          throw Exception(
            'Server returned HTML instead of JSON. Please check server URL.',
          );
        }

        if (e.toString().toLowerCase().contains('access denied') ||
            e.toString().toLowerCase().contains('wrong login/password') ||
            e.toString().toLowerCase().contains('invalid database')) {
          rethrow;
        }

        if (attempt < _maxAttempts && _isRetryableError(e)) {
          final delay = _baseDelay * attempt;
          await Future.delayed(delay);
          continue;
        }

        rethrow;
      }
    }
    throw Exception('Authentication failed after $_maxAttempts attempts');
  }

  /// Executes an RPC call with the current company context injected into kwargs.
  static Future<dynamic> callKwWithCompany(Map<String, dynamic> payload) async {
    final session = await getCurrentSession();
    if (session == null) {
      throw StateError('No Odoo session available. Please login.');
    }

    final kwargs = Map<String, dynamic>.from(payload['kwargs'] ?? {});
    final context = Map<String, dynamic>.from(kwargs['context'] ?? {});

    if (session.allowedCompanyIds.isNotEmpty) {
      context['allowed_company_ids'] = session.allowedCompanyIds;
    }

    if (session.selectedCompanyId != null && session.selectedCompanyId != 0) {
      context['company_id'] = session.selectedCompanyId;
    }

    context['db'] = session.database;

    kwargs['context'] = context;
    final newPayload = Map<String, dynamic>.from(payload);
    newPayload['kwargs'] = kwargs;

    Future<http.Response> post() async {
      final current = await getCurrentSession();
      final effective = current ?? session;
      final primaryUri = Uri.parse(
        '${effective.serverUrl}/web/dataset/call_kw',
      );
      final fallbackUri = Uri.parse(
        '${effective.serverUrl}/odoo/web/dataset/call_kw',
      );

      for (int attempt = 1; attempt <= _maxAttempts; attempt++) {
        try {
          http.Response response = await ioClient.post(
            primaryUri,
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'X-Requested-With': 'XMLHttpRequest',
              'User-Agent': USER_AGENT,
              'Origin': effective.serverUrl,
              'Referer': '${effective.serverUrl}/web',
              'Cookie': 'session_id=${effective.sessionId}',
              'X-Openerp-Session-Id': effective.sessionId,
            },
            body: jsonEncode({
              'jsonrpc': '2.0',
              'method': 'call',
              'params': newPayload,
              'id': DateTime.now().millisecondsSinceEpoch,
            }),
          );
          if (response.statusCode == 404) {
            response = await ioClient.post(
              fallbackUri,
              headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'User-Agent': USER_AGENT,
                'Origin': effective.serverUrl,
                'Referer': '${effective.serverUrl}/odoo/web',
                'Cookie': 'session_id=${effective.sessionId}',
                'X-Openerp-Session-Id': effective.sessionId,
              },
              body: jsonEncode({
                'jsonrpc': '2.0',
                'method': 'call',
                'params': newPayload,
                'id': DateTime.now().millisecondsSinceEpoch,
              }),
            );
          }
          return response;
        } catch (e) {
          if (attempt >= _maxAttempts || !_isRetryableError(e)) rethrow;
          await Future.delayed(_baseDelay * attempt);
        }
      }
      throw Exception(
        'RPC callKwWithCompany failed after $_maxAttempts attempts',
      );
    }

    http.Response response = await post();
    if (response.statusCode != 200) {
      throw Exception(
        '${response.statusCode}: ${response.reasonPhrase} - ${response.body}',
      );
    }

    final data = jsonDecode(response.body);
    if (data['error'] != null) {
      final message = data['error']['message']?.toString() ?? 'RPC Error';
      final lower = message.toLowerCase();
      if (lower.contains('session expired') ||
          lower.contains('session_expired')) {
        try {
          await getSessionInfo(session.serverUrl, session.sessionId);
          response = await post();
          if (response.statusCode != 200) {
            throw Exception('${response.statusCode}: ${response.reasonPhrase}');
          }
          final retryData = jsonDecode(response.body);
          if (retryData.containsKey('error')) {
            final error = retryData['error'];
            final msg = error['message']?.toString() ?? 'RPC Error';
            final dataMsg =
                error['data']?['message']?.toString() ??
                error['data']?.toString() ??
                '';
            throw Exception('$msg${dataMsg.isNotEmpty ? ': $dataMsg' : ''}');
          }
          return retryData['result'];
        } catch (_) {
          try {
            final refreshed = await refreshSession();
            if (refreshed) {
              response = await post();
              if (response.statusCode != 200) {
                throw Exception(
                  '${response.statusCode}: ${response.reasonPhrase}',
                );
              }
              final retryData = jsonDecode(response.body);
              if (retryData.containsKey('error')) {
                final error = retryData['error'];
                final msg = error['message']?.toString() ?? 'RPC Error';
                final dataMsg =
                    error['data']?['message']?.toString() ??
                    error['data']?.toString() ??
                    '';
                throw Exception(
                  '$msg${dataMsg.isNotEmpty ? ': $dataMsg' : ''}',
                );
              }
              return retryData['result'];
            }
          } catch (_) {}
        }
      }
      // Surface the detailed server message (Odoo nests the real cause under
      // error.data.message); the top-level message is the generic
      // "Odoo Server Error", which hides what actually went wrong.
      final dataMsg = data['error']['data']?['message']?.toString() ?? '';
      throw Exception('$message${dataMsg.isNotEmpty ? ': $dataMsg' : ''}');
    }
    return data['result'];
  }

  /// Executes a safe RPC call with company context injected (alias for [callKwWithCompany]).
  static Future<dynamic> safeCallKw(Map<String, dynamic> payload) {
    return callKwWithCompany(payload);
  }

  static Future<dynamic> safeCallKwWithoutCompany(
    Map<String, dynamic> payload,
  ) async {
    final session = await getCurrentSession();
    if (session == null) {
      throw StateError('No Odoo session available. Please login.');
    }

    Future<http.Response> post() async {
      final current = await getCurrentSession();
      final effective = current ?? session;
      final primaryUri = Uri.parse(
        '${effective.serverUrl}/web/dataset/call_kw',
      );
      final fallbackUri = Uri.parse(
        '${effective.serverUrl}/odoo/web/dataset/call_kw',
      );

      for (int attempt = 1; attempt <= _maxAttempts; attempt++) {
        try {
          http.Response response = await ioClient.post(
            primaryUri,
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'X-Requested-With': 'XMLHttpRequest',
              'User-Agent': USER_AGENT,
              'Origin': effective.serverUrl,
              'Referer': '${effective.serverUrl}/web',
              'Cookie': 'session_id=${effective.sessionId}',
              'X-Openerp-Session-Id': effective.sessionId,
            },
            body: jsonEncode({
              'jsonrpc': '2.0',
              'method': 'call',
              'params': payload,
              'id': DateTime.now().millisecondsSinceEpoch,
            }),
          );
          if (response.statusCode == 404) {
            response = await ioClient.post(
              fallbackUri,
              headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'User-Agent': USER_AGENT,
                'Origin': effective.serverUrl,
                'Referer': '${effective.serverUrl}/odoo/web',
                'Cookie': 'session_id=${effective.sessionId}',
                'X-Openerp-Session-Id': effective.sessionId,
              },
              body: jsonEncode({
                'jsonrpc': '2.0',
                'method': 'call',
                'params': payload,
                'id': DateTime.now().millisecondsSinceEpoch,
              }),
            );
          }
          return response;
        } catch (e) {
          if (attempt >= _maxAttempts || !_isRetryableError(e)) rethrow;
          await Future.delayed(_baseDelay * attempt);
        }
      }
      throw Exception(
        'RPC safeCallKwWithoutCompany failed after $_maxAttempts attempts',
      );
    }

    http.Response response = await post();
    if (response.statusCode != 200) {
      throw Exception(
        'RPC HTTP ${response.statusCode}: ${response.reasonPhrase} - ${response.body}',
      );
    }

    final data = jsonDecode(response.body);
    if (data.containsKey('error')) {
      final error = data['error'];
      final message = error['message']?.toString() ?? 'RPC Error';
      if (message.toLowerCase().contains('session expired')) {
        final refreshed = await refreshSession();
        if (refreshed) {
          response = await post();
          final retryData = jsonDecode(response.body);
          if (retryData.containsKey('error')) {
            final retryError = retryData['error'];
            final retryMsg = retryError['message']?.toString() ?? 'RPC Error';
            final retryDataMsg =
                retryError['data']?['message']?.toString() ??
                retryError['data']?.toString() ??
                '';
            throw Exception(
              '$retryMsg${retryDataMsg.isNotEmpty ? ': $retryDataMsg' : ''}',
            );
          }
          return retryData['result'];
        }
      }
      final dataMsg =
          error['data']?['message']?.toString() ??
          error['data']?.toString() ??
          '';
      throw Exception('$message${dataMsg.isNotEmpty ? ': $dataMsg' : ''}');
    }
    return data['result'];
  }

  /// Updates the active company selection in the session and persists the change.
  static Future<void> updateCompanySelection({
    required int companyId,
    required List<int> allowedCompanyIds,
  }) async {
    final session = await getCurrentSession();
    if (session == null) return;

    final updatedSession = session.copyWith(
      selectedCompanyId: companyId,
      allowedCompanyIds: allowedCompanyIds,
    );

    await updatedSession.saveToPrefs();
    _cachedSession = updatedSession;
    _onSessionUpdated?.call(updatedSession);
  }

  static Future<bool> restoreSession({required int companyId}) async {
    final session = await getCurrentSession();
    if (session == null) return false;

    await refreshSession();
    return true;
  }

  static Future<List<Map<String, dynamic>>> getAllowedCompaniesList() async {
    final session = await getCurrentSession();
    if (session == null) return [];

    int effectiveUserId = session.userId ?? 0;

    if (effectiveUserId == 0) {
      try {
        final info = await getSessionInfo(session.serverUrl, session.sessionId);
        if (info['uid'] != null) {
          final recoveredId = info['uid'] is int
              ? info['uid']
              : int.tryParse(info['uid'].toString()) ?? 0;
          if (recoveredId > 0) {
            effectiveUserId = recoveredId;

            await updateSession(session.copyWith(userId: effectiveUserId));
          }
        }
      } catch (e) {}
    }

    final info = await _fetchUserCompanies(effectiveUserId);
    final ids = (info['company_ids'] as List<int>? ?? []);
    if (ids.isEmpty) return [];

    final companiesRes = await safeCallKwWithoutCompany({
      'model': 'res.company',
      'method': 'search_read',
      'args': [
        [
          ['id', 'in', ids],
        ],
      ],
      'kwargs': {
        'fields': ['id', 'name'],
        'order': 'name asc',
      },
    });

    if (companiesRes is List) {
      return companiesRes.cast<Map<String, dynamic>>();
    }
    return [];
  }

  static Future<Map<String, dynamic>> _fetchUserCompanies(
    int userId, {
    String? url,
    String? sessionId,
    String? database,
  }) async {
    try {
      dynamic result;
      if (url != null && sessionId != null) {
        result = await callKwWithSession(
          url: url,
          sessionId: sessionId,
          payload: {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
              'db': database,
              'model': 'res.users',
              'method': 'read',
              'args': [
                [userId],
                ['company_id', 'company_ids'],
              ],
              'kwargs': {},
            },
            'id': DateTime.now().millisecondsSinceEpoch,
          },
        );
      } else {
        result = await safeCallKwWithoutCompany({
          'model': 'res.users',
          'method': 'read',
          'args': [
            [userId],
            ['company_id', 'company_ids'],
          ],
          'kwargs': {},
        });
      }

      if (result is List && result.isNotEmpty) {
        final userData = result[0];

        int? companyId;
        if (userData['company_id'] is int) {
          companyId = userData['company_id'];
        } else if (userData['company_id'] is List &&
            userData['company_id'].isNotEmpty) {
          companyId = userData['company_id'][0];
        }

        List<int> companyIds = [];
        if (userData['company_ids'] is List) {
          companyIds = (userData['company_ids'] as List)
              .map((e) => e is int ? e : null)
              .whereType<int>()
              .toList();
        }

        return {'company_id': companyId, 'company_ids': companyIds};
      }

      return {};
    } catch (e) {
      return {};
    }
  }

  static Future<bool> refreshSession() async {
    if (_refreshCompleter != null) {
      return _refreshCompleter!.future;
    }

    _refreshCompleter = Completer<bool>();

    try {
      final session = await getCurrentSession();
      if (session == null) {
        _refreshCompleter?.complete(false);
        _refreshCompleter = null;
        return false;
      }

      try {
        final info = await getSessionInfo(session.serverUrl, session.sessionId);
        if (info['uid'] != null &&
            (info['uid'] is int || info['uid'] is String)) {
          _lastAuthTime = DateTime.now();
          _refreshCompleter?.complete(true);
          _refreshCompleter = null;
          return true;
        }
      } catch (e) {}

      final newSession = await authenticate(
        serverUrl: session.serverUrl,
        database: session.database,
        username: session.userLogin,
        password: session.password,
      );

      if (newSession != null) {
        OdooSessionModel updatedSession = newSession;
        if (session.selectedCompanyId != null &&
            newSession.allowedCompanyIds.contains(session.selectedCompanyId)) {
          updatedSession = newSession.copyWith(
            selectedCompanyId: session.selectedCompanyId,
          );
        }
        await updatedSession.saveToPrefs();
        _cachedSession = updatedSession;
        _onSessionUpdated?.call(updatedSession);

        _refreshCompleter?.complete(true);
        _refreshCompleter = null;
        return true;
      }

      _refreshCompleter?.complete(false);
      _refreshCompleter = null;
      return false;
    } catch (e) {
      _refreshCompleter?.complete(false);
      _refreshCompleter = null;
      return false;
    }
  }

  static Future<OdooClient?> getClientEnsured() async {
    return getClient();
  }

  /// Headers for fetching an authenticated Odoo resource at [url] (images,
  /// attachments): session cookie plus, when the host has Cloudflare Access
  /// tokens, `Authorization: Bearer`. Synchronous for widgets such as
  /// `CachedNetworkImage`: the bearer comes from the shared client's in-memory
  /// token cache, which a request to the host fills; on a cold or stale cache
  /// a refresh is started so the next build carries it.
  static Map<String, String> authHeaders(String url, {String? sessionId}) {
    final sid = sessionId ?? _cachedSession?.sessionId;
    final host = _bearerHost(url);
    final access = SharedHttp.client.cachedAuthHeader(host);
    if (access.isEmpty && host.isNotEmpty) {
      SharedHttp.client.warm(host);
    }
    return _buildAuthHeaders(sid, access);
  }

  /// Same as [authHeaders] but awaits a token refresh when one is needed.
  static Future<Map<String, String>> authHeadersAsync(
    String url, {
    String? sessionId,
  }) async {
    final sid = sessionId ?? _cachedSession?.sessionId;
    final host = _bearerHost(url);
    final access = host.isEmpty
        ? const <String, String>{}
        : await SharedHttp.client.authHeaderFor(host);
    return _buildAuthHeaders(sid, access);
  }

  /// Only the Access credential, for requests where the Odoo cookie must not
  /// be sent (WebView initial requests). Empty when the host has no fresh token.
  static Map<String, String> bearerHeaders(String url) {
    final host = _bearerHost(url);
    final access = SharedHttp.client.cachedAuthHeader(host);
    if (access.isEmpty && host.isNotEmpty) {
      SharedHttp.client.warm(host);
    }
    return access;
  }

  /// Host whose bearer may be attached to [url]; empty unless it is https.
  static String _bearerHost(String url) {
    final uri = Uri.tryParse(url);
    return uri != null && uri.scheme == 'https' ? uri.host : '';
  }

  // Cookie only: custom headers such as X-Openerp-Session-Id are not dropped
  // on cross-origin redirects (Odoo redirects url attachments elsewhere).
  static Map<String, String> _buildAuthHeaders(
    String? sid,
    Map<String, String> access,
  ) => {
    if (sid != null && sid.isNotEmpty) 'Cookie': 'session_id=$sid',
    ...access,
  };

  static Future<http.Response> makeAuthenticatedRequest(
    String url, {
    Map<String, String>? headers,
    Object? body,
    Duration? timeout,
    int maxRetries = 3,
  }) async {
    final session = await getCurrentSession();
    if (session == null) {
      throw StateError('No active session');
    }

    await getClientEnsured();

    final uri = Uri.parse(url);
    final requestHeaders = {
      ...await authHeadersAsync(url, sessionId: session.sessionId),
      ...?headers,
    };
    final requestTimeout = timeout ?? const Duration(seconds: 30);

    Exception? lastError;

    for (int attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        // The shared client's default 60s cap must not cut long fetches
        // (e.g. PDF rendering) short of the caller's own timeout.
        return await SharedHttp.withTimeout(
          requestTimeout,
          () => ioClient
              .get(uri, headers: requestHeaders)
              .timeout(requestTimeout),
        );
      } catch (e) {
        lastError = e is Exception ? e : Exception(e.toString());
        if (attempt < maxRetries && _isRetryableError(e)) {
          await Future.delayed(_baseDelay * attempt);
          continue;
        }
        rethrow;
      }
    }

    throw lastError ?? Exception('Request failed');
  }
}
