import 'dart:io';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

import 'pki_asset_loader.dart';

const bool _verbose = bool.fromEnvironment('DART_PDF_TEST_VERBOSE');

void main() {
  final roots = AssetTrustedRootsProvider.loadDefaultRoots();
  final trustedProvider = AssetTrustedRootsProvider(roots);

  test('Validate "2 ass leonardo e mauricio.pdf"', () async {
    final file = File('test/assets/pdfs/2 ass leonardo e mauricio.pdf');
    expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

    final bytes = file.readAsBytesSync();
    final report = await PdfSignatureValidator().validateAllSignatures(
      bytes,
      trustedRootsProvider: trustedProvider,
      fetchCrls: false,
      includeCertificates: true,
    );

    expect(report.signatures.length, equals(2));

    var foundLeonardo = false;
    var foundMauricio = false;

    for (final sig in report.signatures) {
      expect(sig.intact, isTrue);
      if (_verbose && !sig.cmsValid) {
        // ignore: avoid_print
        print('CMS inválido para assinatura ${sig.signatureIndex}');
      }
      if (_verbose && sig.chainTrusted != true) {
        // ignore: avoid_print
        print('Chain not trusted: ${sig.chainErrors}');
      }

      final signerCert = _pickSignerCert(sig);
      expect(signerCert, isNotNull);
      final subjectStr = (signerCert!.subject ?? '').toLowerCase();
      final issuerStr = (signerCert.issuer ?? '').toLowerCase();

      if (_verbose) {
        // ignore: avoid_print
        print('Signer: $subjectStr');
        // ignore: avoid_print
        print('Issuer: $issuerStr');
      }

      if (subjectStr.contains('leonardo')) {
        foundLeonardo = true;
        expect(issuerStr, contains('gov-br'));
      } else if (subjectStr.contains('mauricio')) {
        foundMauricio = true;
        expect(issuerStr, contains('serpro'));
      }
    }

    expect(foundLeonardo, isTrue, reason: 'Leonardo signature not found');
    expect(foundMauricio, isTrue, reason: 'Mauricio signature not found');
  });

  test('Validate "3 ass leonardo e stefan e mauricio.pdf"', () async {
    final file = File('test/assets/pdfs/3 ass leonardo e stefan e mauricio.pdf');
    expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

    final bytes = file.readAsBytesSync();
    final report = await PdfSignatureValidator().validateAllSignatures(
      bytes,
      trustedRootsProvider: trustedProvider,
      fetchCrls: false,
      includeCertificates: true,
    );

    expect(report.signatures.length, equals(3));

    var foundLeonardo = false;
    var foundStefan = false;
    var foundMauricio = false;

    for (final sig in report.signatures) {
      expect(sig.intact, isTrue);
      if (_verbose && !sig.cmsValid) {
        // ignore: avoid_print
        print('CMS inválido para assinatura ${sig.signatureIndex}');
      }
      if (_verbose && sig.chainTrusted != true) {
        // ignore: avoid_print
        print('Chain not trusted: ${sig.chainErrors}');
      }

      final signerCert = _pickSignerCert(sig);
      expect(signerCert, isNotNull);
      final subjectStr = (signerCert!.subject ?? '').toLowerCase();
      final issuerStr = (signerCert.issuer ?? '').toLowerCase();

      if (_verbose) {
        // ignore: avoid_print
        print('Signer: $subjectStr');
        // ignore: avoid_print
        print('Issuer: $issuerStr');
      }

      if (subjectStr.contains('leonardo')) {
        foundLeonardo = true;
        expect(issuerStr, contains('gov-br'));
      } else if (subjectStr.contains('stefan')) {
        foundStefan = true;
      } else if (subjectStr.contains('mauricio')) {
        foundMauricio = true;
        expect(issuerStr, contains('serpro'));
      }
    }

    expect(foundLeonardo, isTrue, reason: 'Leonardo signature not found');
    expect(foundStefan, isTrue, reason: 'Stefan signature not found');
    expect(foundMauricio, isTrue, reason: 'Mauricio signature not found');
  });

  test('Validate "serpro_Maurício_Soares_dos_Anjos.pdf"', () async {
    final file =
        File('test/assets/pdfs/serpro_Maurício_Soares_dos_Anjos.pdf');
    expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

    final bytes = file.readAsBytesSync();
    final report = await PdfSignatureValidator().validateAllSignatures(
      bytes,
      trustedRootsProvider: trustedProvider,
      fetchCrls: false,
      includeCertificates: true,
    );

    expect(report.signatures, isNotEmpty);

    for (final sig in report.signatures) {
      expect(sig.intact, isTrue);
      if (_verbose && !sig.cmsValid) {
        // ignore: avoid_print
        print('CMS inválido para assinatura ${sig.signatureIndex}');
      }
      if (_verbose && sig.chainTrusted != true) {
        // ignore: avoid_print
        print('Chain not trusted: ${sig.chainErrors}');
      }

      final signerCert = _pickSignerCert(sig);
      if (_verbose && signerCert != null) {
        // ignore: avoid_print
        print('Signer: ${signerCert.subject?.toLowerCase()}');
        // ignore: avoid_print
        print('Issuer: ${signerCert.issuer?.toLowerCase()}');
      }
    }
  });

  test('Validate "sample_token_icpbrasil_assinado.pdf"', () async {
    final file = File('test/assets/pdfs/sample_token_icpbrasil_assinado.pdf');
    expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

    final bytes = file.readAsBytesSync();
    final report = await PdfSignatureValidator().validateAllSignatures(
      bytes,
      trustedRootsProvider: trustedProvider,
      fetchCrls: false,
      includeCertificates: true,
    );

    expect(report.signatures, isNotEmpty);
    for (final sig in report.signatures) {
      expect(sig.intact, isTrue);
      if (_verbose && !sig.cmsValid) {
        // ignore: avoid_print
        print('CMS inválido para assinatura ${sig.signatureIndex}');
      }
      if (_verbose && sig.chainTrusted != true) {
        // ignore: avoid_print
        print('Chain not trusted: ${sig.chainErrors}');
      }
    }
  });
}

PdfSignatureCertificateInfo? _pickSignerCert(PdfSignatureInfoReport sig) {
  if (sig.signerCertificate != null) return sig.signerCertificate;
  final list = sig.certificates ?? const <PdfSignatureCertificateInfo>[];
  for (final cert in list) {
    if ((cert.subject ?? '').isNotEmpty) return cert;
  }
  return null;
}
