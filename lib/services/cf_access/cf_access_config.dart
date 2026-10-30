/// Cloudflare Access OAuth callback location.
///
/// Placeholder host. When changing it, update the same host/path in
/// AndroidManifest.xml, ios/Runner/Runner.entitlements and deploy/auth-callback/.
class CfAccessConfig {
  const CfAccessConfig._();

  static const String callbackHost = 'auth.swovo.de';
  static const String callbackPath = '/oauth/callback';

  static String get callbackUrl => 'https://$callbackHost$callbackPath';
}
