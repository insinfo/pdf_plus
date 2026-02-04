import 'dart:io';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  test('extract certificates info from CMS', () async {
    final bytes = File('test/assets/pdfs/sample_govbr_signature_assinado.pdf')
        .readAsBytesSync();
    final report = await PdfSignatureValidator().validateAllSignatures(
      bytes,
      includeCertificates: true,
    );

    expect(report.signatures.isNotEmpty, isTrue);
    final sig = report.signatures.first;
    expect(sig.certificates, isNotNull);
    expect(sig.certificates, isA<List<PdfSignatureCertificateInfo>>());
  });
}
