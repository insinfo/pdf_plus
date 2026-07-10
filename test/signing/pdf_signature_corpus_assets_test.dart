import 'dart:io';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

/// Smoke validation for PDF assets added to the corpus that are not covered by
/// the format-specific suites. Guards against false signature detection on
/// unsigned documents and confirms the timestamp document is recognized.
void main() {
  group('corpus assets', () {
    // Unsigned documents must yield no signatures (no false positives).
    const unsigned = <String>[
      'test/assets/pdfs/Relatorio - stf-fachin-1.pdf',
      'test/assets/pdfs/paginador.pdf',
      'test/assets/pdfs/paginador (1).pdf',
      'test/assets/pdfs/paginador (2).pdf',
      'test/assets/pdfs/paginador (3).pdf',
    ];

    for (final path in unsigned) {
      test('reports no signatures for unsigned ${_name(path)}', () async {
        final file = File(path);
        expect(file.existsSync(), isTrue,
            reason: 'File not found: ${file.path}');

        final report = await PdfSignatureValidator().validateAllSignatures(
          file.readAsBytesSync(),
          includeSignatureFields: true,
          validateTemporal: false,
        );
        expect(report.signatures, isEmpty);
      });
    }

    test('recognizes the RFC3161 timestamp in decisao.pdf', () async {
      final file = File('test/assets/pdfs/decisao.pdf');
      expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

      final report = await PdfSignatureValidator().validateAllSignatures(
        file.readAsBytesSync(),
        includeSignatureFields: true,
        validateTemporal: false,
      );
      expect(report.signatures, hasLength(1));
      final sig = report.signatures.single;
      expect(sig.signatureField?.subFilter, '/ETSI.RFC3161');
      // Timestamp token itself must carry a verifiable CMS signature.
      expect(sig.cmsValid, isTrue);
    });
  });
}

String _name(String path) => path.split('/').last;
