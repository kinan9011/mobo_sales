import '../services/odoo_session_manager.dart';

/// Odoo auth headers for [url] when it is on [session]'s Odoo server; null
/// for any other host so the session cookie never leaves the Odoo origin.
///
/// Kept apart from `odoo_image_headers.dart` so it can be unit-tested without
/// pulling in `SessionService` (and with it the whole app).
Map<String, String>? odooHostHeaders(String url, OdooSessionModel? session) {
  final server = Uri.tryParse(session?.serverUrl ?? '');
  final target = Uri.tryParse(url);
  if (server == null ||
      target == null ||
      server.host.isEmpty ||
      target.host != server.host ||
      target.scheme != server.scheme) {
    return null;
  }
  return OdooSessionManager.authHeaders(url, sessionId: session!.sessionId);
}
