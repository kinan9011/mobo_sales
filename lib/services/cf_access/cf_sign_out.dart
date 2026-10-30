import 'cf_access_store.dart';

/// Cloudflare Access logout page for the team that issued [tokens], derived
/// from the token endpoint host. Null when that host cannot be determined.
Uri? cfAccessLogoutUrl(CfTokenSet tokens) {
  final host = Uri.tryParse(tokens.tokenEndpoint)?.host ?? '';
  if (host.isEmpty) return null;
  return Uri(scheme: 'https', host: host, path: '/cdn-cgi/access/logout');
}
