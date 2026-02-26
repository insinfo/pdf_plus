import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  group('PdfModernSigners', () {
    test('PdfEcdsaPkcs8Signer expõe OIDs esperados', () {
      final signer = PdfEcdsaPkcs8Signer(
        pkcs8PrivateKey: Uint8List(0),
        namedCurve: 'P-256',
        certificates: <Uint8List>[Uint8List.fromList(<int>[1])],
      );
      expect(signer.digestAlgorithmOid, PdfSignatureAlgorithms.sha256);
      expect(
        signer.signatureAlgorithmOid,
        PdfSignatureAlgorithms.ecdsaWithSha256,
      );
    });

    test('PdfEd25519Pkcs8Signer expõe OID de assinatura Ed25519', () {
      final signer = PdfEd25519Pkcs8Signer(
        pkcs8PrivateKey: Uint8List(0),
        certificates: <Uint8List>[Uint8List.fromList(<int>[1])],
      );
      expect(signer.signatureAlgorithmOid, PdfSignatureAlgorithms.ed25519);
    });

    test('signDigest em signers modernos lança UnsupportedError', () async {
      final ecdsa = PdfEcdsaPkcs8Signer(
        pkcs8PrivateKey: Uint8List(0),
        namedCurve: 'P-256',
        certificates: <Uint8List>[Uint8List.fromList(<int>[1])],
      );
      final ed25519 = PdfEd25519Pkcs8Signer(
        pkcs8PrivateKey: Uint8List(0),
        certificates: <Uint8List>[Uint8List.fromList(<int>[1])],
      );

      expect(() => ecdsa.signDigest(Uint8List(32)), throwsUnsupportedError);
      expect(
        () => ed25519.signDigest(Uint8List(32)),
        throwsUnsupportedError,
      );
    });
  });
}
