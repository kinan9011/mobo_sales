import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'secret_store.dart';

const String secretsMigratedFlag = 'secrets_migrated_v1';

/// One-time move of passwords and session IDs from plain-text prefs into
/// [SecretStore]. Must run before the session is first read. The old values
/// are deleted only after every secure write succeeded; on any failure
/// nothing is removed and the migration is retried on the next start.
Future<void> migrateSecretsToSecureStorage({
  SharedPreferences? prefs,
  SecretStore? store,
}) async {
  try {
    prefs ??= await SharedPreferences.getInstance();
    store ??= SecretStore.instance;
    if (prefs.getBool(secretsMigratedFlag) ?? false) return;

    final sessionId = prefs.getString('sessionId');
    final password = prefs.getString('password');
    final passwordKeys = prefs
        .getKeys()
        .where((k) => k.startsWith('password_'))
        .toList();

    final accountLists = <String, List<Map<String, dynamic>>>{};
    final secrets = await store.readAccountSecrets();
    for (final listKey in const ['stored_accounts', 'stored_accounts_backup']) {
      final raw = prefs.getStringList(listKey);
      if (raw == null) continue;
      final accounts = <Map<String, dynamic>>[];
      for (final json in raw) {
        try {
          accounts.add(Map<String, dynamic>.from(jsonDecode(json)));
        } catch (_) {
          // Unreadable entries are dropped, as _loadStoredAccounts does.
        }
      }
      final split = splitAccountSecrets(accounts);
      split.secrets.forEach((k, v) => secrets[k] = {...?secrets[k], ...v});
      accountLists[listKey] = split.accounts;
    }

    // Every secure write first; any throw leaves prefs untouched.
    // A null pref (e.g. flag lost to "Clear cache" after a first run) must
    // not overwrite the secure value: write() deletes on null.
    if (sessionId != null) await store.write('sessionId', sessionId);
    if (password != null) await store.write('password', password);
    for (final key in passwordKeys) {
      await store.write(key, prefs.getString(key));
    }
    if (secrets.isNotEmpty) await store.writeAccountSecrets(secrets);

    await prefs.remove('sessionId');
    await prefs.remove('password');
    for (final key in passwordKeys) {
      await prefs.remove(key);
    }
    for (final entry in accountLists.entries) {
      await prefs.setStringList(
        entry.key,
        entry.value.map(jsonEncode).toList(),
      );
    }
    await prefs.setBool(secretsMigratedFlag, true);
  } catch (_) {
    // Old values stay in place; retried on next launch.
  }
}
