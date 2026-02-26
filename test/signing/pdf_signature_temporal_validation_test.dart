import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pki.dart';
import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  const pdfPath = 'test/assets/pdfs/sample_token_icpbrasil_assinado.pdf';
  const jksPath =
      'test/assets/truststore/keystore_icp_brasil/keystore_ICP_Brasil.jks';

  Future<List<Uint8List>> _loadRoots() async {
    final loader = IcpBrasilCertificateLoader(
      jksPath: jksPath,
      jksPassword: '12345678',
    );
    return loader.loadFromJks(verifyIntegrity: true);
  }

  test('temporal validation disabled keeps signature approved', () async {
    if (!File(pdfPath).existsSync() || !File(jksPath).existsSync()) {
      print('Skipping temporal validation test: assets not found.');
      return;
    }

    final pdfBytes = Uint8List.fromList(File(pdfPath).readAsBytesSync());
    final roots = await _loadRoots();

    final report = await PdfSignatureValidator().validateAllSignatures(
      pdfBytes,
      trustedRootsProvider: PdfInMemoryTrustedRootsProvider(roots),
      includeCertificates: true,
    );

    expect(report.signatures, isNotEmpty);
    expect(
      report.signatures.first.validationStatus,
      PdfSignatureValidationStatus.approved,
    );
  });

  test(
      'temporal validation by validation-time marks expired cert as indeterminate',
      () async {
    if (!File(pdfPath).existsSync() || !File(jksPath).existsSync()) {
      print('Skipping temporal validation test: assets not found.');
      return;
    }

    final pdfBytes = Uint8List.fromList(File(pdfPath).readAsBytesSync());
    final roots = await _loadRoots();

    final report = await PdfSignatureValidator().validateAllSignatures(
      pdfBytes,
      trustedRootsProvider: PdfInMemoryTrustedRootsProvider(roots),
      includeCertificates: true,
      validateTemporal: true,
      validationTime: DateTime.utc(2026, 2, 26),
      temporalUseSigningTime: false,
      temporalExpiredNeedsLtv: true,
    );

    expect(report.signatures, isNotEmpty);
    expect(
      report.signatures.first.validationStatus,
      PdfSignatureValidationStatus.indeterminate,
    );
  });

  test('temporal validation by signing-time keeps this sample approved',
      () async {
    if (!File(pdfPath).existsSync() || !File(jksPath).existsSync()) {
      print('Skipping temporal validation test: assets not found.');
      return;
    }

    final pdfBytes = Uint8List.fromList(File(pdfPath).readAsBytesSync());
    final roots = await _loadRoots();

    final report = await PdfSignatureValidator().validateAllSignatures(
      pdfBytes,
      trustedRootsProvider: PdfInMemoryTrustedRootsProvider(roots),
      includeCertificates: true,
      validateTemporal: true,
      temporalUseSigningTime: true,
    );

    expect(report.signatures, isNotEmpty);
    expect(
      report.signatures.first.validationStatus,
      PdfSignatureValidationStatus.approved,
    );
  });
}
