import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart' as core;
import 'package:pdf_plus/signing.dart' as pdf;
import 'package:test/test.dart';

/// Locks the `/adbe.pkcs7.sha1` WITH-signed-attributes branch (the "double
/// hash"). No such file exists in the corpus, so we synthesize one with OpenSSL:
///
///  * eContent = SHA1(ByteRange)                     (the encapsulated digest)
///  * messageDigest signed attribute = SHA1(eContent) (added by `cms -sign`)
///  * signature over the signed attributes
///
/// Integrity therefore requires BOTH `SHA1(ByteRange) == eContent` and
/// `messageDigest == SHA1(eContent)`. This test would fail if either link were
/// dropped (false "tampered") or if the second link were skipped (which would
/// let a document tampered together with its eContent pass as intact).
void main() {
  test(
    'validates synthetic /adbe.pkcs7.sha1 WITH signed attributes (double hash)',
    () async {
      if (!_hasOpenSsl()) return;

      final tempDir =
          await Directory.systemTemp.createTemp('pdf_plus_sha1_attrs_');
      try {
        final keyPath = '${tempDir.path}/key.pem';
        final certPath = '${tempDir.path}/cert.pem';
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
          '-sha1',
          '-subj',
          '/CN=Legacy SHA1 Signer',
        ]);

        // Unsigned base PDF.
        final core.PdfDocument doc = core.PdfDocument();
        final page = core.PdfPage(doc);
        page.getGraphics().drawString(
              core.PdfFont.helvetica(doc),
              12,
              'adbe.pkcs7.sha1 with signed attributes',
              50,
              750,
            );
        final Uint8List baseBytes = Uint8List.fromList(await doc.save());

        // Prepare a placeholder whose /SubFilter is the legacy adbe.pkcs7.sha1.
        final prepared = await pdf.PdfExternalSigning.preparePdf(
          inputBytes: baseBytes,
          pageNumber: 1,
          bounds: core.PdfRect.fromLBRT(50, 400, 290, 470),
          fieldName: 'Signature1',
          signature: pdf.PdfSignatureConfig(subFilter: 'adbe.pkcs7.sha1'),
          contentsReserveSize: 16384,
        );

        final range =
            pdf.PdfExternalSigning.extractByteRange(prepared.preparedPdfBytes);
        final Uint8List rangeData =
            _extractByteRangeData(prepared.preparedPdfBytes, range);

        // eContent = SHA1(ByteRange), computed with OpenSSL to avoid extra deps.
        final rangePath = '${tempDir.path}/range.bin';
        File(rangePath).writeAsBytesSync(rangeData);
        final eContentPath = '${tempDir.path}/econtent.bin';
        await _runCmd('openssl', [
          'dgst',
          '-sha1',
          '-binary',
          '-out',
          eContentPath,
          rangePath,
        ]);

        // Sign the eContent as ENCAPSULATED content (-nodetach) with SHA-1.
        // `cms -sign` adds signed attributes (incl. messageDigest = SHA1(eContent))
        // by default, producing the double-hash structure we want to exercise.
        final p7Path = '${tempDir.path}/sig.p7s';
        await _runCmd('openssl', [
          'cms',
          '-sign',
          '-binary',
          '-nodetach',
          '-md',
          'sha1',
          '-in',
          eContentPath,
          '-signer',
          certPath,
          '-inkey',
          keyPath,
          '-outform',
          'DER',
          '-out',
          p7Path,
        ]);
        final Uint8List pkcs7 =
            Uint8List.fromList(File(p7Path).readAsBytesSync());

        final Uint8List finalBytes = pdf.PdfExternalSigning.embedSignature(
          preparedPdfBytes: prepared.preparedPdfBytes,
          pkcs7Bytes: pkcs7,
        );

        final report = await pdf.PdfSignatureValidator().validateAllSignatures(
          finalBytes,
          includeSignatureFields: true,
          validateTemporal: false,
        );

        expect(report.signatures, hasLength(1));
        final sig = report.signatures.single;
        expect(sig.signatureField?.subFilter, '/adbe.pkcs7.sha1');
        expect(sig.signedAttrsOids ?? const <String>[], isNotEmpty,
            reason: 'signature must carry signed attributes for this branch');
        expect(sig.cmsValid, isTrue);
        expect(sig.digestValid, isTrue,
            reason: 'both hash links must validate');
        expect(sig.intact, isTrue);
      } finally {
        await tempDir.delete(recursive: true);
      }
    },
    timeout: const Timeout(Duration(minutes: 3)),
    skip: _hasOpenSsl() ? false : 'openssl not available',
  );
}

Uint8List _extractByteRangeData(Uint8List bytes, List<int> range) {
  if (range.length != 4) {
    throw ArgumentError('Invalid ByteRange.');
  }
  final start1 = range[0];
  final len1 = range[1];
  final start2 = range[2];
  final len2 = range[3];
  final out = Uint8List(len1 + len2);
  out.setRange(0, len1, bytes, start1);
  out.setRange(len1, len1 + len2, bytes, start2);
  return out;
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
    throw Exception(
      'Command failed ($exe ${args.join(' ')}): ${result.stderr}',
    );
  }
}
