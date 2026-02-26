import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/rsa_keys.dart';
import 'package:pdf_plus/src/pki/pki_pem_utils.dart';
import 'package:test/test.dart';

void main() {
  group('PkiPemUtils', () {
    test('certificateDerToPem e bundle de cadeia funcionam', () {
      final derA = Uint8List.fromList(List<int>.generate(80, (i) => i));
      final derB = Uint8List.fromList(List<int>.generate(96, (i) => 255 - i));

      final pem = PkiPemUtils.certificateDerToPem(derA);
      expect(pem, contains('-----BEGIN CERTIFICATE-----'));
      expect(pem, contains(base64.encode(derA).substring(0, 10)));
      expect(pem, contains('-----END CERTIFICATE-----'));

      final chain = PkiPemUtils.certificateChainDerToPem([derA, derB]);
      expect(chain, hasLength(2));
      expect(chain[0], contains('BEGIN CERTIFICATE'));
      expect(chain[1], contains('BEGIN CERTIFICATE'));

      final bundle = PkiPemUtils.certificateChainDerToPemBundle([derA, derB]);
      expect(
        RegExp('-----BEGIN CERTIFICATE-----').allMatches(bundle).length,
        2,
      );
    });

    test('rsaPrivateKeyToPem gera PEM PKCS#1 quando CRT completo', () {
      // Parâmetros pequenos apenas para testar serialização ASN.1.
      final key = RSAPrivateKey(
        BigInt.from(3233), // 61 * 53
        BigInt.from(2753),
        BigInt.from(61),
        BigInt.from(53),
      );

      final pem = PkiPemUtils.rsaPrivateKeyToPem(key);
      expect(pem, startsWith('-----BEGIN RSA PRIVATE KEY-----'));
      expect(pem, contains('-----END RSA PRIVATE KEY-----'));
    });

    test('rsaPrivateKeyToPem falha sem parâmetros CRT', () {
      final incomplete = RSAPrivateKey(BigInt.from(3233), BigInt.from(2753));
      expect(
        () => PkiPemUtils.rsaPrivateKeyToPem(incomplete),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
