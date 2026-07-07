import 'dart:io';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

import 'pki_asset_loader.dart';

void main() {
  test('validates VISTO 24822 ICP-Brasil signature', () async {
    final pdfFile =
        Directory('test/assets/pdfs').listSync().whereType<File>().firstWhere(
              (file) => file.path
                  .split(Platform.pathSeparator)
                  .last
                  .startsWith('VISTO 24822-2026 PL 055'),
            );

    final bytes = pdfFile.readAsBytesSync();
    final report = await PdfSignatureValidator().validateAllSignatures(
      bytes,
      trustedRootsProvider: AssetTrustedRootsProvider(
        AssetTrustedRootsProvider.loadDefaultRoots(),
      ),
      includeCertificates: true,
      includeSignatureFields: true,
    );

    expect(report.signatures, hasLength(1));
    final signature = report.signatures.single;
    expect(signature.intact, isTrue);
    expect(signature.digestValid, isTrue);
    expect(signature.cmsValid, isTrue);
    expect(signature.chainTrusted, isNot(false));
  });
}
