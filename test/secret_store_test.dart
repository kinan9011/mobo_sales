import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobo_sales/services/secret_store.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late SecretStore store;

  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    store = SecretStore();
  });

  test('round trip, overwrite and delete', () async {
    expect(await store.read('password'), isNull);
    await store.write('password', 'pw1');
    expect(await store.read('password'), 'pw1');
    await store.write('password', 'pw2');
    expect(await store.read('password'), 'pw2');
    await store.delete('password');
    expect(await store.read('password'), isNull);
  });

  test('empty or null value deletes the entry', () async {
    await store.write('sessionId', 'abc');
    await store.write('sessionId', '');
    expect(await store.read('sessionId'), isNull);
    await store.write('sessionId', 'abc');
    await store.write('sessionId', null);
    expect(await store.read('sessionId'), isNull);
  });

  test(
    'deleteWhere removes only the prefix and keeps other namespaces',
    () async {
      await store.write('password_1_db', 'a');
      await store.write('password_bob_db', 'b');
      await store.write('password', 'top');
      await const FlutterSecureStorage().write(
        key: 'cf_access.x',
        value: 'tok',
      );
      await store.deleteWhere('password_');
      expect(await store.read('password_1_db'), isNull);
      expect(await store.read('password_bob_db'), isNull);
      expect(await store.read('password'), 'top');
      expect(
        await const FlutterSecureStorage().read(key: 'cf_access.x'),
        'tok',
      );
    },
  );

  test(
    'account secrets split out, round trip and corrupt entry heals',
    () async {
      final accounts = [
        {
          'userId': '7',
          'serverUrl': 'https://a.example',
          'database': 'db',
          'name': 'Ann',
          'password': 'pw',
          'sessionId': 'sid',
        },
        {
          'userId': '8',
          'serverUrl': 'https://a.example',
          'database': 'db',
          'password': '',
          'sessionId': 'sid2',
        },
      ];
      final split = splitAccountSecrets(accounts);
      expect(split.accounts[0].containsKey('password'), isFalse);
      expect(split.accounts[0].containsKey('sessionId'), isFalse);
      expect(split.accounts[0]['name'], 'Ann');
      expect(accounts[0]['password'], 'pw'); // input untouched
      expect(split.secrets['7_https://a.example_db'], {
        'password': 'pw',
        'sessionId': 'sid',
      });
      expect(split.secrets['8_https://a.example_db'], {'sessionId': 'sid2'});

      await store.writeAccountSecrets(split.secrets);
      expect(await store.readAccountSecrets(), split.secrets);

      await store.write(SecretStore.accountsKey, 'not json');
      expect(await store.readAccountSecrets(), isEmpty);
    },
  );
}
