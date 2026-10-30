import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Keychain/Keystore-backed home for passwords and Odoo session IDs, which
/// must never sit in plain-text `SharedPreferences`. Keys are namespaced so
/// they cannot clash with the Cloudflare token entries (`cf_access.`).
class SecretStore {
  SecretStore([FlutterSecureStorage? storage])
    : _storage = storage ?? const FlutterSecureStorage();

  static const String keyPrefix = 'secret.';

  /// Secure entry holding `{accountKey: {password, sessionId}}` for every
  /// stored account.
  static const String accountsKey = 'stored_accounts';

  /// App-wide instance; tests swap it for one over a mock storage.
  static SecretStore instance = SecretStore();

  final FlutterSecureStorage _storage;

  Future<String?> read(String key) => _storage.read(key: '$keyPrefix$key');

  /// Stores [value]; a null or empty value deletes the entry.
  Future<void> write(String key, String? value) async {
    if (value == null || value.isEmpty) {
      await delete(key);
      return;
    }
    await _storage.write(key: '$keyPrefix$key', value: value);
  }

  Future<void> delete(String key) => _storage.delete(key: '$keyPrefix$key');

  /// Deletes every entry whose (un-prefixed) key starts with [prefix].
  Future<void> deleteWhere(String prefix) async {
    final all = await _storage.readAll();
    for (final key in all.keys.toList()) {
      if (key.startsWith('$keyPrefix$prefix')) {
        await _storage.delete(key: key);
      }
    }
  }

  /// Per-account secrets, or `{}` when none are stored or the entry is corrupt.
  Future<Map<String, Map<String, String>>> readAccountSecrets() async {
    final raw = await read(accountsKey);
    if (raw == null || raw.isEmpty) return {};
    try {
      final decoded = jsonDecode(raw) as Map<String, dynamic>;
      return decoded.map(
        (k, v) => MapEntry(
          k,
          (v as Map).map((a, b) => MapEntry(a.toString(), b.toString())),
        ),
      );
    } catch (_) {
      return {};
    }
  }

  Future<void> writeAccountSecrets(
    Map<String, Map<String, String>> secrets,
  ) async {
    await write(accountsKey, secrets.isEmpty ? null : jsonEncode(secrets));
  }
}

/// Identity of a stored account entry, as used to key its secrets.
String accountSecretKey(Map<String, dynamic> account) {
  final userId = account['userId'] ?? account['id'];
  final serverUrl = account['serverUrl'] ?? account['url'];
  return '${userId}_${serverUrl}_${account['database']}';
}

/// Splits [accounts] into copies without `password`/`sessionId` (safe for
/// prefs) and the removed values keyed by [accountSecretKey].
({
  List<Map<String, dynamic>> accounts,
  Map<String, Map<String, String>> secrets,
})
splitAccountSecrets(List<Map<String, dynamic>> accounts) {
  final stripped = <Map<String, dynamic>>[];
  final secrets = <String, Map<String, String>>{};
  for (final account in accounts) {
    final copy = Map<String, dynamic>.from(account);
    final password = copy.remove('password')?.toString() ?? '';
    final sessionId = copy.remove('sessionId')?.toString() ?? '';
    if (password.isNotEmpty || sessionId.isNotEmpty) {
      secrets[accountSecretKey(account)] = {
        if (password.isNotEmpty) 'password': password,
        if (sessionId.isNotEmpty) 'sessionId': sessionId,
      };
    }
    stripped.add(copy);
  }
  return (accounts: stripped, secrets: secrets);
}
