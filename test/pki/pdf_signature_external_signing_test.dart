import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart' as core;
import 'package:pdf_plus/signing.dart' as pdf;
import 'package:test/test.dart';

void main() {
  test('external signing + validator works with trustedRootsPem', () async {
    if (!_hasOpenSsl()) return;

    final Directory testDir =
        await Directory.systemTemp.createTemp('pdf_plus_ext_sig_');
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
        '/CN=PdfPlus Signer',
        '-addext',
        'keyUsage=digitalSignature'
      ]);

      final doc = core.PdfDocument();
      final page = core.PdfPage(doc);
      final g = page.getGraphics();
      g.drawString(
        core.PdfFont.helvetica(doc),
        12,
        'Hello signature',
        50,
        750,
      );
      final Uint8List unsignedPdf = Uint8List.fromList(await doc.save());

      final prepared = await pdf.PdfExternalSigning.preparePdf(
        inputBytes: unsignedPdf,
        pageNumber: 1,
        bounds: core.PdfRect.fromLTWH(100, 100, 200, 50),
        fieldName: 'Sig1',
        signature: pdf.PdfSignatureConfig()
          ..contactInfo = 'Unit test'
          ..reason = 'External signature test',
      );

      final digest = base64.decode(prepared.hashBase64);
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

      final report = await pdf.PdfSignatureValidator().validateAllSignatures(
        signedPdf,
        trustedRootsPem: <String>[certificatePem],
        fetchCrls: false,
        fetchOcsp: false,
      );

      expect(report.signatures.length, 1);
      final sig = report.signatures.single;
      expect(sig.cmsValid, isTrue);
      expect(sig.digestValid, isTrue);
      expect(sig.intact, isTrue);
      expect(sig.certValid, isTrue);
    } finally {
      await testDir.delete(recursive: true);
    }
  });

  test('external signing + TrustedRootsProvider (DER) works', () async {
    if (!_hasOpenSsl()) return;

    final Directory testDir =
        await Directory.systemTemp.createTemp('pdf_plus_ext_sig_roots_');
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
        '/CN=PdfPlus Roots',
        '-addext',
        'keyUsage=digitalSignature'
      ]);

      final doc = core.PdfDocument();
      final page = core.PdfPage(doc);
      final g = page.getGraphics();
      g.drawString(
        core.PdfFont.helvetica(doc),
        12,
        'Hello trusted roots',
        50,
        750,
      );
      final Uint8List unsignedPdf = Uint8List.fromList(await doc.save());

      final prepared = await pdf.PdfExternalSigning.preparePdf(
        inputBytes: unsignedPdf,
        pageNumber: 1,
        bounds: core.PdfRect.fromLTWH(100, 100, 200, 50),
        fieldName: 'Sig1',
        signature: pdf.PdfSignatureConfig(),
      );

      final digest = base64.decode(prepared.hashBase64);
      final String privateKeyPem = File(keyPath).readAsStringSync();
      final String certificatePem = File(certPath).readAsStringSync();
      final Uint8List certDer = _pemToDer(certificatePem);

      final Uint8List cmsDer = pdf.PdfCmsSigner.signDetachedSha256RsaFromPem(
        contentDigest: Uint8List.fromList(digest),
        privateKeyPem: privateKeyPem,
        certificatePem: certificatePem,
      );

      final Uint8List signedPdf = pdf.PdfExternalSigning.embedSignature(
        preparedPdfBytes: prepared.preparedPdfBytes,
        pkcs7Bytes: cmsDer,
      );

      final report = await pdf.PdfSignatureValidator().validateAllSignatures(
        signedPdf,
        trustedRootsProvider: _StaticTrustedRootsProvider([certDer]),
      );

      expect(report.signatures.length, 1);
      final sig = report.signatures.single;
      expect(sig.cmsValid, isTrue);
      expect(sig.digestValid, isTrue);
      expect(sig.intact, isTrue);
      expect(sig.certValid, isTrue);
    } finally {
      await testDir.delete(recursive: true);
    }
  });
}

class _StaticTrustedRootsProvider implements pdf.TrustedRootsProvider {
  _StaticTrustedRootsProvider(this._roots);

  final List<Uint8List> _roots;

  @override
  Future<List<Uint8List>> getTrustedRootsDer() async => _roots;
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
