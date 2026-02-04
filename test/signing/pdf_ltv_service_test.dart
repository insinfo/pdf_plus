import 'dart:convert';
import 'dart:io';
// ignore_for_file: deprecated_member_use_from_same_package

import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart' as core;
import 'package:pdf_plus/signing.dart' as pdf;
import 'package:test/test.dart';

void main() {
  test(
    'PdfLtvService adds DSS to signed PDF',
    () async {
      if (!_hasOpenSsl()) return;

      final Directory testDir =
          await Directory.systemTemp.createTemp('pdf_plus_ltv_');
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
          '/CN=PdfPlus LTV',
          '-addext',
          'keyUsage=digitalSignature'
        ]);

        final core.PdfDocument doc = core.PdfDocument();
        final page = core.PdfPage(doc);
        final g = page.getGraphics();
        g.drawString(
          core.PdfFont.helvetica(doc),
          12,
          'LTV test',
          50,
          750,
        );
        final Uint8List unsignedPdf = Uint8List.fromList(await doc.save());

        final pdf.PdfExternalSigningPrepared prepared =
            await pdf.PdfExternalSigning.preparePdf(
          inputBytes: unsignedPdf,
          pageNumber: 1,
          bounds: core.PdfRect.fromLTWH(100, 100, 200, 50),
          fieldName: 'Sig1',
          signature: pdf.PdfSignatureConfig()
            ..contactInfo = 'Unit test'
            ..reason = 'LTV test',
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

        final Uint8List certDer = _pemToDer(certificatePem);
        final pdf.PdfLtvService ltv = pdf.PdfLtvService();
        final result = await ltv.applyLtv(
          pdfBytes: signedPdf,
          certs: <Uint8List>[certDer],
        );

        expect(result.applied, isTrue);
        expect(_containsAscii(result.bytes, '/DSS'), isTrue);
        expect(_containsAscii(result.bytes, '/Certs'), isTrue);

        final pdf.PdfSignatureValidationReport report =
            await pdf.PdfSignatureValidator().validateAllSignatures(
          result.bytes,
          trustedRootsPem: <String>[certificatePem],
        );
        expect(report.signatures.length, 1);
        expect(report.signatures.single.intact, isTrue);
      } finally {
        await testDir.delete(recursive: true);
      }
    },
    timeout: const Timeout(Duration(minutes: 3)),
    skip: _hasOpenSsl() ? false : 'openssl not available',
  );
}

bool _containsAscii(Uint8List bytes, String token) {
  final List<int> pattern = ascii.encode(token);
  if (pattern.isEmpty || bytes.length < pattern.length) return false;
  for (int i = 0; i <= bytes.length - pattern.length; i++) {
    bool match = true;
    for (int j = 0; j < pattern.length; j++) {
      if (bytes[i + j] != pattern[j]) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}

Uint8List _pemToDer(String pem) {
  final String body = pem
      .replaceAll('-----BEGIN CERTIFICATE-----', '')
      .replaceAll('-----END CERTIFICATE-----', '')
      .replaceAll(RegExp(r'\s+'), '');
  return Uint8List.fromList(base64.decode(body));
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
