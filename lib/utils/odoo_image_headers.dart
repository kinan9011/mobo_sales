import '../services/session_service.dart';
import 'odoo_host_headers.dart';

/// [odooHostHeaders] for the current session: headers for images on the Odoo
/// server, null for external URLs (placeholders, gravatar, ...).
Map<String, String>? odooImageHeaders(String url) =>
    odooHostHeaders(url, SessionService.instance.currentSession);
