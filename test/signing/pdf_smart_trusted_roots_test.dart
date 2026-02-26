import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pki.dart';
import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  const pdfSingleSig = 'test/assets/pdfs/sample_token_icpbrasil_assinado.pdf';
  const pdfMultiSig = 'test/assets/pdfs/3 ass leonardo e stefan e mauricio.pdf';
  const bksIcp = 'test/assets/truststore/icp_brasil/cadeiasicpbrasil.bks';
  const bksGov = 'test/assets/truststore/gov.br/cadeia_govbr_unica.bks';
  const bksPass = 'serprosigner';

  Future<List<int>> _readBytes(String path) async {
    final file = File(path);
    if (!file.existsSync()) {
      throw StateError('Missing test file: $path');
    }
    return file.readAsBytes();
  }

  Future<PdfTrustedRootsIndex> _buildIndex() async {
    final loaderIcp = IcpBrasilCertificateLoader(
      bksPath: bksIcp,
      bksPassword: bksPass,
    );
    final loaderGov = IcpBrasilCertificateLoader(
      bksPath: bksGov,
      bksPassword: bksPass,
    );

    final icpRoots = await loaderIcp.loadFromBks(tryDecryptKeys: false);
    final govRoots = await loaderGov.loadFromBks(tryDecryptKeys: false);

    return PdfTrustedRootsIndex.build([
      PdfTrustedRootsSource(
        id: 'icp_brasil',
        provider: PdfInMemoryTrustedRootsProvider(icpRoots),
      ),
      PdfTrustedRootsSource(
        id: 'gov_br',
        provider: PdfInMemoryTrustedRootsProvider(govRoots),
      ),
    ]);
  }

  test('selector chooses ICP-Brasil chain for single-signature sample', () async {
    final required = [pdfSingleSig, bksIcp, bksGov];
    if (required.any((p) => !File(p).existsSync())) {
      print('Skipping smart roots selector test: required files not found.');
      return;
    }

    final index = await _buildIndex();
    final selector = PdfSmartTrustedRootsSelector(index);
    final pdfBytes = await _readBytes(pdfSingleSig);

    final selection = await selector.selectForPdf(
      Uint8List.fromList(pdfBytes),
    );
    expect(selection.selectedSourceIds, isNotEmpty);
    expect(selection.selectedSourceIds, contains('icp_brasil'));
  });

  test('selector chooses both chains for multi-signature sample', () async {
    final required = [pdfMultiSig, bksIcp, bksGov];
    if (required.any((p) => !File(p).existsSync())) {
      print('Skipping smart roots selector test: required files not found.');
      return;
    }

    final index = await _buildIndex();
    final selector = PdfSmartTrustedRootsSelector(index);
    final pdfBytes = await _readBytes(pdfMultiSig);

    final selection = await selector.selectForPdf(
      Uint8List.fromList(pdfBytes),
    );
    expect(selection.selectedSourceIds, contains('icp_brasil'));
    expect(selection.selectedSourceIds, contains('gov_br'));
  });

  test('smart validator validates all signatures with selected roots', () async {
    final required = [pdfMultiSig, bksIcp, bksGov];
    if (required.any((p) => !File(p).existsSync())) {
      print('Skipping smart validator test: required files not found.');
      return;
    }

    final index = await _buildIndex();
    final selector = PdfSmartTrustedRootsSelector(index);
    final validator = PdfSmartSignatureValidator();
    final pdfBytes = await _readBytes(pdfMultiSig);

    final result = await validator.validateAllSignatures(
      Uint8List.fromList(pdfBytes),
      rootsSelector: selector,
      includeCertificates: false,
      includeSignatureFields: true,
    );

    final validCount = result.report.signatures
        .where((s) => s.cmsValid && s.digestValid && s.intact && s.chainTrusted != false)
        .length;
    expect(result.report.signatures.length, greaterThanOrEqualTo(1));
    expect(validCount, result.report.signatures.length);
  });
}
