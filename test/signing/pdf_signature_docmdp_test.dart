import 'dart:io';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  test('valida DocMDP em PDF certificado (P=2)', () async {
    final file = File('test/assets/pdfs/generated_doc_mdp_allow_signatures.pdf');
    expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

    final bytes = file.readAsBytesSync();
    final report = await PdfSignatureValidator().validateAllSignatures(
      bytes,
      fetchCrls: false,
    );

    expect(report.signatures.length, 1);
    final sig = report.signatures.first;
    expect(sig.docMdp.isCertificationSignature, isTrue);
    expect(sig.docMdp.permissionP, 2);
  });
}
