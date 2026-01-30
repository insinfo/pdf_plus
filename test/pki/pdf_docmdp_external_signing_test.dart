import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart' as core;
import 'package:pdf_plus/signing.dart' as pdf;
import 'package:test/test.dart';

void main() {
  test(
    'DocMDP permission is reported for first signature',
    () async {
      if (!_hasOpenSsl()) return;

      final Directory testDir =
          await Directory.systemTemp.createTemp('pdf_plus_docmdp_');
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
          '/CN=PdfPlus DocMDP',
          '-addext',
          'keyUsage=digitalSignature'
        ]);

        final core.PdfDocument doc = core.PdfDocument();
        final page = core.PdfPage(doc);
        final g = page.getGraphics();
        g.drawString(
          core.PdfFont.helvetica(doc),
          12,
          'DocMDP test',
          50,
          750,
        );
        final Uint8List unsignedPdf = Uint8List.fromList(await doc.save());

        final pdf.PdfSignatureConfig config = pdf.PdfSignatureConfig()
          ..contactInfo = 'Unit test'
          ..reason = 'DocMDP test'
          ..docMdpPermissionP = 2;

        final pdf.PdfExternalSigningPrepared prepared =
            await pdf.PdfExternalSigning.preparePdf(
          inputBytes: unsignedPdf,
          pageNumber: 1,
          bounds: core.PdfRect.fromLTWH(100, 100, 200, 50),
          fieldName: 'Sig1',
          signature: config,
        );

        final Uint8List digest = base64.decode(prepared.hashBase64);
        final String privateKeyPem = File(keyPath).readAsStringSync();
        final String certificatePem = File(certPath).readAsStringSync();

        final Uint8List cmsDer = pdf.PdfCmsSigner.signDetachedSha256RsaFromPem(
          contentDigest: Uint8List.fromList(digest),
          privateKeyPem: privateKeyPem,
          certificatePem: certificatePem,
        );

        final Uint8List signedPdf = pdf.PdfExternalSigning.embedSignature(
          preparedPdfBytes: prepared.preparedPdfBytes,
          pkcs7Bytes: cmsDer,
        );

        final pdf.PdfSignatureValidationReport report =
            await pdf.PdfSignatureValidator().validateAllSignatures(
          signedPdf,
          trustedRootsPem: <String>[certificatePem],
        );

        expect(report.signatures.length, 1);
        final sig = report.signatures.single;
        expect(sig.docMdp.isCertificationSignature, isTrue);
        expect(sig.docMdp.permissionP, 2);
      } finally {
        await testDir.delete(recursive: true);
      }
    },
    timeout: const Timeout(Duration(minutes: 3)),
    skip: _hasOpenSsl() ? false : 'openssl not available',
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
