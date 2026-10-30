import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobo_sales/services/secret_store.dart';
import 'package:mobo_sales/services/secrets_migration.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _FailingStorage extends FlutterSecureStorage {
  const _FailingStorage();

  @override
  Future<void> write({
    required String key,
    required String? value,
    AppleOptions? iOptions,
    AndroidOptions? aOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    AppleOptions? mOptions,
    WindowsOptions? wOptions,
  }) async => throw Exception('keystore unavailable');
}

Map<String, Object> _seed() => {
  'isLoggedIn': true,
  'sessionId': 'sid-main',
  'password': 'pw-main',
  'userLogin': 'ann@example.com',
  'serverUrl': 'https://a.example',
  'database': 'db',
  'password_7_db': 'pw-by-id',
  'password_ann@example.com_db': 'pw-by-login',
  'stored_accounts': [
    jsonEncode({
      'userId': '7',
      'serverUrl': 'https://a.example',
      'database': 'db',
      'name': 'Ann',
      'password': 'pw-acc7',
      'sessionId': 'sid-acc7',
    }),
    jsonEncode({
      'userId': '8',
      'serverUrl': 'https://b.example',
      'database': 'db2',
      'name': 'Bob',
      'password': 'pw-acc8',
      'sessionId': 'sid-acc8',
    }),
  ],
};

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues(_seed());
  });

  test('moves secrets to secure storage and strips prefs', () async {
    final prefs = await SharedPreferences.getInstance();
    final store = SecretStore();

    await migrateSecretsToSecureStorage(prefs: prefs, store: store);

    expect(await store.read('sessionId'), 'sid-main');
    expect(await store.read('password'), 'pw-main');
    expect(await store.read('password_7_db'), 'pw-by-id');
    expect(await store.read('password_ann@example.com_db'), 'pw-by-login');
    final secrets = await store.readAccountSecrets();
    expect(secrets['7_https://a.example_db'], {
      'password': 'pw-acc7',
      'sessionId': 'sid-acc7',
    });
    expect(secrets['8_https://b.example_db2'], {
      'password': 'pw-acc8',
      'sessionId': 'sid-acc8',
    });

    expect(prefs.containsKey('sessionId'), isFalse);
    expect(prefs.containsKey('password'), isFalse);
    expect(prefs.getKeys().where((k) => k.startsWith('password_')), isEmpty);
    final accounts = prefs.getStringList('stored_accounts')!;
    expect(accounts, hasLength(2));
    for (final json in accounts) {
      final a = jsonDecode(json) as Map<String, dynamic>;
      expect(a.containsKey('password'), isFalse);
      expect(a.containsKey('sessionId'), isFalse);
    }
    expect(jsonDecode(accounts[0])['name'], 'Ann');
    expect(prefs.getString('userLogin'), 'ann@example.com');
    expect(prefs.getString('serverUrl'), 'https://a.example');
    expect(prefs.getBool(secretsMigratedFlag), isTrue);
  });

  test('second run is a no-op', () async {
    final prefs = await SharedPreferences.getInstance();
    final store = SecretStore();
    await migrateSecretsToSecureStorage(prefs: prefs, store: store);

    // A secret written after migration must not be touched or re-imported.
    await store.write('password', 'rotated');
    await prefs.setString('password', 'stale-plaintext');
    await migrateSecretsToSecureStorage(prefs: prefs, store: store);

    expect(await store.read('password'), 'rotated');
    expect(prefs.getString('password'), 'stale-plaintext');
  });

  test('keeps old values when the secure write throws', () async {
    final prefs = await SharedPreferences.getInstance();
    final store = SecretStore(const _FailingStorage());

    await migrateSecretsToSecureStorage(prefs: prefs, store: store);

    expect(prefs.getString('password'), 'pw-main');
    expect(prefs.getString('sessionId'), 'sid-main');
    expect(prefs.getString('password_7_db'), 'pw-by-id');
    expect(prefs.getStringList('stored_accounts'), _seed()['stored_accounts']);
    expect(prefs.getBool(secretsMigratedFlag), isNull);

    // Storage recovers: next start migrates.
    await migrateSecretsToSecureStorage(prefs: prefs, store: SecretStore());
    expect(prefs.containsKey('password'), isFalse);
    expect(prefs.getBool(secretsMigratedFlag), isTrue);
  });

  test('rerun after the flag is lost keeps the secure secrets', () async {
    final prefs = await SharedPreferences.getInstance();
    final store = SecretStore();
    await migrateSecretsToSecureStorage(prefs: prefs, store: store);

    // Settings > Clear cache removes every pref it does not preserve,
    // including the migration flag.
    await prefs.remove(secretsMigratedFlag);
    await migrateSecretsToSecureStorage(prefs: prefs, store: store);

    expect(await store.read('sessionId'), 'sid-main');
    expect(await store.read('password'), 'pw-main');
    expect(await store.read('password_7_db'), 'pw-by-id');
    expect((await store.readAccountSecrets()).keys, hasLength(2));
  });
}
