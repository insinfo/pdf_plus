import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  test('signer certificate info is present in validation report', () async {
    final File file = File('test/assets/pdfs/2 ass leonardo e mauricio.pdf');
    expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

    final Uint8List bytes = file.readAsBytesSync();

    final PdfSignatureValidationReport report =
        await PdfSignatureValidator().validateAllSignatures(
      bytes,
      includeCertificates: true,
      includeSignatureFields: true,
      fetchCrls: false,
    );

    expect(report.signatures, isNotEmpty);

    for (final sig in report.signatures) {
      final signer = sig.signerCertificate;
      expect(signer, isNotNull);
      expect(signer!.subject, isNotNull);
      expect(signer.issuer, isNotNull);
      expect(signer.serial, isNotNull);
      expect(signer.notBefore, isNotNull);
      expect(signer.notAfter, isNotNull);
      expect(signer.notBefore!.isBefore(signer.notAfter!), isTrue);
    }
  });
}
