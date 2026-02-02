import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart' as pdf;
import 'package:pdf_plus/src/crypto/sha256.dart';
import 'package:test/test.dart';

void main() {
  group('PdfCmsSigner', () {
    test('signDetachedSha256RsaFromPem produces CMS signature', () {
      if (!_hasOpenSsl()) return;

      final Directory testDir =
          Directory.systemTemp.createTempSync('pdf_plus_cms_');
      try {
        _runCmdSync('openssl', <String>[
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-keyout',
          '${testDir.path}/user_key.pem',
          '-out',
          '${testDir.path}/user_cert.pem',
          '-days',
          '365',
          '-nodes',
          '-subj',
          '/CN=PdfPlus Test',
          '-addext',
          'keyUsage=digitalSignature'
        ]);

        final String privateKeyPem =
            File('${testDir.path}/user_key.pem').readAsStringSync();
        final String certificatePem =
            File('${testDir.path}/user_cert.pem').readAsStringSync();

        final Uint8List content = Uint8List.fromList(
          utf8.encode('pdf-plus-cms-test-content'),
        );
        final Uint8List digest =
            Uint8List.fromList(sha256.convert(content).bytes);

        final Uint8List cmsDer = pdf.PdfCmsSigner.signDetachedSha256RsaFromPem(
          contentDigest: digest,
          privateKeyPem: privateKeyPem,
          certificatePem: certificatePem,
          chainPem: const <String>[],
        );

        expect(cmsDer, isNotEmpty);
      } finally {
        if (testDir.existsSync()) {
          testDir.deleteSync(recursive: true);
        }
      }
    });
  });
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

void _runCmdSync(String exe, List<String> args) {
  final result = Process.runSync(exe, args, runInShell: true);
  if (result.exitCode != 0) {
    throw StateError(
      "Falha ao executar $exe ${args.join(' ')}\n${result.stdout}\n${result.stderr}",
    );
  }
}
