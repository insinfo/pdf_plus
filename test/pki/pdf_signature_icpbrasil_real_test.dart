import 'dart:io';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

import 'pki_asset_loader.dart';

void main() {
  test('ICP-Brasil signatures info from "2 ass leonardo e mauricio.pdf"', () async {
    final file = File('test/assets/pdfs/2 ass leonardo e mauricio.pdf');
    expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

    final bytes = file.readAsBytesSync();
    final report = await PdfSignatureValidator().validateAllSignatures(
      bytes,
      trustedRootsProvider: AssetTrustedRootsProvider(
        AssetTrustedRootsProvider.loadDefaultRoots(),
      ),
      includeCertificates: true,
      includeSignatureFields: true,
      fetchCrls: false,
    );

    expect(report.signatures.length, 2);

    // Leonardo (Gov.br) - policy may be absent.
    final leonardo = report.signatures
        .firstWhere((s) => (s.signerCertificate?.subject ?? '')
            .toLowerCase()
            .contains('leonardo'));
    expect(leonardo.signatureField?.subFilter, isNotNull);
    expect(leonardo.signatureField?.byteRange?.length, 4);
    expect(leonardo.signingTime ?? leonardo.signatureField?.signingTimeRaw, isNotNull);
    expect(leonardo.signaturePolicyOid, isNull);
    expect(leonardo.signedAttrsReport?.missingRequiredOids, isEmpty);

    // Mauricio (ICP-Brasil) - policy OID present in report.
    final mauricio = report.signatures
        .firstWhere((s) => (s.signerCertificate?.subject ?? '')
            .toLowerCase()
            .contains('mauricio'));
    final ids = mauricio.signerCertificate?.icpBrasilIds;
    expect(ids, isNotNull);
    expect(ids!.cpf, '02094890732');
    expect(mauricio.signaturePolicyOid, '2.16.76.1.7.1.1.2.3');
    expect(mauricio.signedAttrsReport?.missingRequiredOids, isEmpty);
  });
}
