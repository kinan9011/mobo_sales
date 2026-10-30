/// Server host of a stored account map (`serverUrl`, falling back to `url`),
/// lower-cased. Null when it has none.
String? accountHost(Map<String, dynamic> account) {
  for (final key in const ['serverUrl', 'url']) {
    final raw = account[key]?.toString().trim() ?? '';
    if (raw.isEmpty) continue;
    final host = Uri.tryParse(raw)?.host ?? '';
    if (host.isNotEmpty) return host.toLowerCase();
  }
  return null;
}

/// Hosts whose Cloudflare token set may be dropped after [removed] left the
/// stored accounts: its host, unless a remaining account or the active
/// session still uses it. [remaining] must not contain [removed].
Set<String> hostsToReleaseAfterRemoval(
  List<Map<String, dynamic>> remaining,
  Map<String, dynamic> removed,
  String? activeHost,
) {
  final host = accountHost(removed);
  if (host == null) return {};
  if (activeHost != null && activeHost.toLowerCase() == host) return {};
  if (remaining.any((a) => accountHost(a) == host)) return {};
  return {host};
}
