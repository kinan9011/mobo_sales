import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobo_sales/utils/server_url_policy.dart';

void main() {
  group('insecureServerUrlError', () {
    test('plain http is rejected with the https-only message', () {
      expect(
        insecureServerUrlError('http://odoo.example.com'),
        httpsOnlyMessage,
      );
      expect(
        insecureServerUrlError('  HTTP://odoo.example.com:8069 '),
        httpsOnlyMessage,
      );
      expect(
        insecureServerUrlError('http://192.168.1.20:8069'),
        httpsOnlyMessage,
      );
    });

    test('https and scheme-less input pass', () {
      expect(insecureServerUrlError('https://odoo.example.com'), isNull);
      expect(insecureServerUrlError('odoo.example.com'), isNull);
      expect(insecureServerUrlError(''), isNull);
    });

    test('local development hosts may stay on http', () {
      expect(insecureServerUrlError('http://localhost:8069'), isNull);
      expect(insecureServerUrlError('http://10.0.2.2:8069'), isNull);
      expect(insecureServerUrlError('http://127.0.0.1:8069'), isNull);
    });

    test('lookalike hosts are still rejected', () {
      expect(
        insecureServerUrlError('http://localhost.evil.com'),
        httpsOnlyMessage,
      );
    });
  });

  group('tlsErrorMessage', () {
    test('maps handshake and certificate failures', () {
      expect(
        tlsErrorMessage(const HandshakeException('Handshake error in client')),
        tlsFailureMessage,
      );
      expect(
        tlsErrorMessage(
          const TlsException(
            'CERTIFICATE_VERIFY_FAILED: self signed certificate',
          ),
        ),
        tlsFailureMessage,
      );
      expect(
        tlsErrorMessage('HandshakeException: ... CERTIFICATE_VERIFY_FAILED'),
        tlsFailureMessage,
      );
    });

    test('leaves other errors alone', () {
      expect(
        tlsErrorMessage(const SocketException('Connection refused')),
        isNull,
      );
      expect(tlsErrorMessage('timeout'), isNull);
    });
  });
}
