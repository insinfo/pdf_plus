import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  group('politica de assinatura na mesclagem', () {
    test('padrao remove assinatura invalida sem marcar saida como corrompida',
        () async {
      final merged = await PdfDocument.merge(<Uint8List>[_signedSaliPdf()]);

      final quick = PdfQuickInfo.fromBytes(merged);
      final inspection = PdfSecurityInspector().quickInspect(merged);

      expect(quick.hasPdfHeader, isTrue);
      expect(quick.hasEofMarker, isTrue);
      expect(quick.hasSignatures, isFalse);
      expect(inspection.isPdf, isTrue);
      expect(inspection.isSigned, isFalse);
      expect(inspection.isCorrupted, isFalse);
      expect(inspection.signatureCount, 0);
    });

    test('modo estrito recusa origem assinada', () async {
      final future = PdfDocument.merge(
        <Uint8List>[_signedSaliPdf()],
        options: const PdfMergeOptions(rejectSignedSources: true),
      );

      await expectLater(future, throwsA(isA<PdfMergeException>()));
    });

  });
}

Uint8List _signedSaliPdf() {
  const path = 'test/assets/pdfs/documento (13).pdf';
  final file = File(path);
  expect(file.existsSync(), isTrue, reason: 'PDF de regressao ausente: $path');
  return file.readAsBytesSync();
}
