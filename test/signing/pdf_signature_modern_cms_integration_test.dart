import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart' as core;
import 'package:pdf_plus/signing.dart' as pdf;
import 'package:test/test.dart';

void main() {
  group('PDF modern CMS integration', () {
    for (final algorithm in _algorithms) {
      test(
        '${algorithm.name}: validates + extracts + inspects signed PDF',
        () async {
          if (!_hasOpenSsl()) return;

          final Directory testDir =
              await Directory.systemTemp.createTemp('pdf_plus_modern_cms_');
          try {
            final keyPath = '${testDir.path}/${algorithm.name}_key.pem';
            final certPath = '${testDir.path}/${algorithm.name}_cert.pem';

            await _generateKeyAndCert(
              algorithm: algorithm,
              keyPath: keyPath,
              certPath: certPath,
            );

            final unsignedPdf = await _buildUnsignedPdf();
            final signedPdf = await _externallySignWithOpenSslCms(
              pdfBytes: unsignedPdf,
              fieldName: 'Sig_${algorithm.name}',
              keyPath: keyPath,
              certPath: certPath,
              digestArg: algorithm.cmsDigestArg,
              workDir: testDir,
            );

            final certPem = File(certPath).readAsStringSync();

            final validation =
                await pdf.PdfSignatureValidator().validateAllSignatures(
              signedPdf,
              trustedRootsPem: <String>[certPem],
            );
            expect(validation.signatures, hasLength(1));
            expect(
              validation.signatures.first.cmsValid,
              isTrue,
              reason: validation.signatures.first.message,
            );
            expect(validation.signatures.first.digestValid, isTrue);
            expect(validation.signatures.first.intact, isTrue);

            final extraction =
                await pdf.PdfSignatureExtractor().extractSignatures(signedPdf);
            expect(extraction.signatures, hasLength(1));
            expect(extraction.signatures.first.contentsPresent, isTrue);
            expect(extraction.signatures.first.signerCertificate, isNotNull);
            expect(
              extraction.signatures.first.signedAttrsOids,
              contains('1.2.840.113549.1.9.4'),
            );

            final inspection = await pdf.PdfSecurityInspector().inspect(
              signedPdf,
              validateSignatures: true,
              includeSha256: true,
            );
            expect(inspection.isPdf, isTrue);
            expect(inspection.isSigned, isTrue);
            expect(inspection.signatureCount, 1);
            expect(inspection.supportedSubFilters, isTrue);
            expect(inspection.allSignaturesIntact, isTrue);
            expect(inspection.isCorrupted, isFalse);
            expect(inspection.sha256Hex, isNotNull);
          } finally {
            await testDir.delete(recursive: true);
          }
        },
        timeout: const Timeout(Duration(minutes: 3)),
        skip: _hasOpenSsl() ? false : 'openssl not available',
      );
    }
  });
}

const _algorithms = <_AlgorithmConfig>[
  _AlgorithmConfig(name: 'ecdsa', cmsDigestArg: 'sha256'),
  _AlgorithmConfig(name: 'ed25519', cmsDigestArg: 'sha512'),
];

class _AlgorithmConfig {
  const _AlgorithmConfig({
    required this.name,
    required this.cmsDigestArg,
  });

  final String name;
  final String cmsDigestArg;
}

Future<Uint8List> _buildUnsignedPdf() async {
  final doc = core.PdfDocument();
  final page = core.PdfPage(doc);
  final g = page.getGraphics();
  g.drawString(
    core.PdfFont.helvetica(doc),
    12,
    'Modern CMS integration test',
    50,
    750,
  );
  return Uint8List.fromList(await doc.save());
}

Future<void> _generateKeyAndCert({
  required _AlgorithmConfig algorithm,
  required String keyPath,
  required String certPath,
}) async {
  if (algorithm.name == 'ecdsa') {
    await _runCmd('openssl', <String>[
      'ecparam',
      '-name',
      'prime256v1',
      '-genkey',
      '-noout',
      '-out',
      keyPath.replaceAll('/', Platform.pathSeparator),
    ]);
    await _runCmd('openssl', <String>[
      'req',
      '-new',
      '-x509',
      '-key',
      keyPath.replaceAll('/', Platform.pathSeparator),
      '-out',
      certPath.replaceAll('/', Platform.pathSeparator),
      '-days',
      '365',
      '-subj',
      '/CN=PdfPlus ECDSA Integration',
    ]);
    return;
  }

  await _runCmd('openssl', <String>[
    'genpkey',
    '-algorithm',
    'ed25519',
    '-out',
    keyPath.replaceAll('/', Platform.pathSeparator),
  ]);
  await _runCmd('openssl', <String>[
    'req',
    '-new',
    '-x509',
    '-key',
    keyPath.replaceAll('/', Platform.pathSeparator),
    '-out',
    certPath.replaceAll('/', Platform.pathSeparator),
    '-days',
    '365',
    '-subj',
    '/CN=PdfPlus Ed25519 Integration',
  ]);
}

Future<Uint8List> _externallySignWithOpenSslCms({
  required Uint8List pdfBytes,
  required String fieldName,
  required String keyPath,
  required String certPath,
  required String digestArg,
  required Directory workDir,
}) async {
  final prepared = await pdf.PdfExternalSigning.preparePdf(
    inputBytes: Uint8List.fromList(pdfBytes),
    pageNumber: 1,
    bounds: core.PdfRect.fromLTWH(100, 100, 220, 50),
    fieldName: fieldName,
    signature: pdf.PdfSignatureConfig()
      ..contactInfo = 'Integration test'
      ..reason = 'CMS modern algorithms',
  );

  final preparedBytes = prepared.preparedPdfBytes;
  final ranges = prepared.byteRange;
  final part1 = preparedBytes.sublist(ranges[0], ranges[0] + ranges[1]);
  final part2 = preparedBytes.sublist(ranges[2], ranges[2] + ranges[3]);

  final dataToSignPath = '${workDir.path}/data_to_sign_$fieldName.bin';
  final sink = File(dataToSignPath).openWrite();
  sink.add(part1);
  sink.add(part2);
  await sink.close();

  final p7sPath = '${workDir.path}/signature_$fieldName.der';
  await _runCmd('openssl', <String>[
    'cms',
    '-sign',
    '-binary',
    '-md',
    digestArg,
    '-in',
    dataToSignPath.replaceAll('/', Platform.pathSeparator),
    '-signer',
    certPath.replaceAll('/', Platform.pathSeparator),
    '-inkey',
    keyPath.replaceAll('/', Platform.pathSeparator),
    '-out',
    p7sPath.replaceAll('/', Platform.pathSeparator),
    '-outform',
    'DER',
  ]);

  final cmsDer = File(p7sPath).readAsBytesSync();
  return pdf.PdfExternalSigning.embedSignature(
    preparedPdfBytes: preparedBytes,
    pkcs7Bytes: cmsDer,
  );
}

bool _hasOpenSsl() {
  try {
    final result = Process.runSync('openssl', const <String>['version']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

Future<void> _runCmd(String exe, List<String> args) async {
  final result = await Process.run(exe, args, runInShell: true);
  if (result.exitCode != 0) {
    throw StateError(
      'Falha ao executar $exe ${args.join(' ')}\n${result.stdout}\n${result.stderr}',
    );
  }
}
