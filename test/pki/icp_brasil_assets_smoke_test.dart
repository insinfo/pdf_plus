import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart' as pdf;
import 'package:test/test.dart';

import 'pki_asset_loader.dart';

void main() {
  test('ICP-Brasil assets smoke validation', () async {
    final File file =
        File('test/assets/pdfs/sample_govbr_signature_assinado.pdf');
    expect(file.existsSync(), isTrue,
        reason: 'Arquivo não encontrado: ${file.path}');

    final roots = AssetTrustedRootsProvider.loadDefaultRoots();
    expect(roots, isNotEmpty, reason: 'Truststore assets not loaded.');

    final policies = PolicyAssetsLoader().loadPolicies();
    expect(policies, isNotEmpty, reason: 'Policy assets not loaded.');

    final Uint8List bytes = file.readAsBytesSync();
    final pdf.PdfSignatureValidationReport report =
        await pdf.PdfSignatureValidator().validateAllSignatures(
      bytes,
      trustedRootsProvider: AssetTrustedRootsProvider(roots),
      fetchCrls: false,
      fetchOcsp: false,
    );

    expect(report.signatures, isNotEmpty);
  });
}
