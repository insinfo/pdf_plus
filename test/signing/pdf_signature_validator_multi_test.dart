import 'dart:io';
// ignore_for_file: deprecated_member_use_from_same_package

import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart' as core;
import 'package:pdf_plus/signing.dart' as pdf;
import 'package:test/test.dart';

void main() {
  test(
    'PdfSignatureValidator validates multiple incremental signatures',
    () async {
      if (!_hasOpenSsl()) return;

      final Directory testDir =
          await Directory.systemTemp.createTemp('pdf_plus_sig_val_');
      try {
        final String keyPath = '${testDir.path}/user_key.pem';
        final String certPath = '${testDir.path}/user_cert.pem';

        await _runCmd('openssl', [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-keyout',
          keyPath,
          '-out',
          certPath,
          '-days',
          '365',
          '-nodes',
          '-subj',
          '/CN=PdfPlus Multi',
          '-addext',
          'keyUsage=digitalSignature'
        ]);

        final core.PdfDocument doc = core.PdfDocument();
        final page = core.PdfPage(doc);
        final g = page.getGraphics();
        g.drawString(
          core.PdfFont.helvetica(doc),
          12,
          'Hello, World! multi-signature test.',
          50,
          750,
        );
        final Uint8List unsignedPdf = Uint8List.fromList(await doc.save());

        final Uint8List signedOnce = await _externallySignWithOpenSsl(
          pdfBytes: unsignedPdf,
          fieldName: 'Sig1',
          keyPath: keyPath,
          certPath: certPath,
          workDir: testDir,
        );

        final Uint8List signedTwice = await _externallySignWithOpenSsl(
          pdfBytes: signedOnce,
          fieldName: 'Sig2',
          keyPath: keyPath,
          certPath: certPath,
          workDir: testDir,
        );

        final String certPem = File(certPath).readAsStringSync();
        final pdf.PdfSignatureValidationReport report =
            await pdf.PdfSignatureValidator().validateAllSignatures(
          signedTwice,
          trustedRootsPem: <String>[certPem],
        );

        expect(report.signatures.length, 2);

        for (final pdf.PdfSignatureInfoReport item in report.signatures) {
          expect(item.cmsValid, isTrue,
              reason: 'CMS signature must be valid');
          expect(item.digestValid, isTrue,
              reason: 'ByteRange digest must match');
          expect(item.intact, isTrue, reason: 'Document must be intact');
          expect(item.certValid, isTrue,
              reason: 'Chain trust should validate');
        }
      } finally {
        await testDir.delete(recursive: true);
      }
    },
    timeout: const Timeout(Duration(minutes: 3)),
    skip: _hasOpenSsl() ? false : 'openssl not available',
  );
}

Future<Uint8List> _externallySignWithOpenSsl({
  required Uint8List pdfBytes,
  required String fieldName,
  required String keyPath,
  required String certPath,
  required Directory workDir,
}) async {
  final pdf.PdfExternalSigningPrepared prepared =
      await pdf.PdfExternalSigning.preparePdf(
    inputBytes: Uint8List.fromList(pdfBytes),
    pageNumber: 1,
    bounds: core.PdfRect.fromLTWH(100, 100, 200, 50),
    fieldName: fieldName,
    signature: pdf.PdfSignatureConfig()
      ..contactInfo = 'Unit test'
      ..reason = 'Multi-signature test',
  );

  final Uint8List preparedBytes = prepared.preparedPdfBytes;
  final List<int> ranges = prepared.byteRange;

  final int start1 = ranges[0];
  final int len1 = ranges[1];
  final int start2 = ranges[2];
  final int len2 = ranges[3];

  final List<int> part1 = preparedBytes.sublist(start1, start1 + len1);
  final List<int> part2 = preparedBytes.sublist(start2, start2 + len2);

  final String dataToSignPath = '${workDir.path}/data_to_sign_$fieldName.bin';
  final IOSink dataSink = File(dataToSignPath).openWrite();
  dataSink.add(part1);
  dataSink.add(part2);
  await dataSink.close();

  final String p7sPath = '${workDir.path}/signature_$fieldName.p7s';

  await _runCmd('openssl', [
    'smime',
    '-sign',
    '-binary',
    '-in',
    dataToSignPath.replaceAll('/', Platform.pathSeparator),
    '-signer',
    certPath.replaceAll('/', Platform.pathSeparator),
    '-inkey',
    keyPath.replaceAll('/', Platform.pathSeparator),
    '-out',
    p7sPath.replaceAll('/', Platform.pathSeparator),
    '-outform',
    'DER'
  ]);

  final Uint8List cmsDer = File(p7sPath).readAsBytesSync();

  return pdf.PdfExternalSigning.embedSignature(
    preparedPdfBytes: preparedBytes,
    pkcs7Bytes: cmsDer,
  );
}

bool _hasOpenSsl() {
  try {
    final ProcessResult result =
        Process.runSync('openssl', const <String>['version']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

Future<void> _runCmd(String exe, List<String> args) async {
  final result = await Process.run(exe, args, runInShell: true);
  if (result.exitCode != 0) {
    throw StateError(
      "Falha ao executar $exe ${args.join(' ')}\n${result.stdout}\n${result.stderr}",
    );
  }
}
