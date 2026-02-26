import 'dart:io';

import 'package:pdf_plus/src/pki/pki_jks_utils.dart';
import 'package:test/test.dart';

void main() {
  group('parseJksCertificates', () {
    test('retorna certificados do JKS e marca verified conforme flag', () {
      final file = File(
        'test/assets/truststore/keystore_icp_brasil/keystore_ICP_Brasil.jks',
      );
      if (!file.existsSync()) {
        return;
      }

      final bytes = file.readAsBytesSync();

      final noVerify = parseJksCertificates(bytes, verifyIntegrity: false);
      expect(noVerify.certificates, isNotEmpty);
      expect(noVerify.verified, isFalse);

      final verify = parseJksCertificates(
        bytes,
        password: '12345678',
        verifyIntegrity: true,
      );
      expect(verify.certificates, isNotEmpty);
      expect(verify.verified, isTrue);
    });
  });
}
