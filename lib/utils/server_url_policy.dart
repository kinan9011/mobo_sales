/// Shown when the user types a plain-HTTP server address.
const String httpsOnlyMessage =
    'Only HTTPS servers are supported. Please use an https:// address.';

/// Shown when the server certificate is rejected during the TLS handshake.
const String tlsFailureMessage =
    "Secure connection failed: the server's SSL certificate is not trusted "
    '(self-signed, expired or issued for another host). Ask your '
    'administrator for a valid certificate.';

/// Hosts that may stay on plain HTTP so local development keeps working.
/// Must match the cleartext domain-config in `network_security_config.xml`.
const Set<String> _cleartextHosts = {'localhost', '127.0.0.1', '10.0.2.2'};

/// Returns [httpsOnlyMessage] when [url] explicitly uses the plain-HTTP
/// scheme (except for local development hosts), otherwise `null`. A URL with
/// no scheme is fine: callers add `https://` themselves.
String? insecureServerUrlError(String url) {
  final trimmed = url.trim();
  if (!trimmed.toLowerCase().startsWith('http://')) return null;
  final host = Uri.tryParse(trimmed)?.host.toLowerCase() ?? '';
  return _cleartextHosts.contains(host) ? null : httpsOnlyMessage;
}

/// Returns [tlsFailureMessage] when [error] is a TLS/certificate failure
/// (`HandshakeException`, `CERTIFICATE_VERIFY_FAILED`), otherwise `null`.
/// Matches on text so it needs no `dart:io` import.
String? tlsErrorMessage(Object error) {
  final text = error.toString().toLowerCase();
  final isTls =
      text.contains('handshakeexception') ||
      text.contains('tlsexception') ||
      text.contains('certificate_verify_failed') ||
      text.contains('handshake error') ||
      text.contains('bad certificate');
  return isTls ? tlsFailureMessage : null;
}
