import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

void main() {
  group('round-trip', () {
    test('mesclar o resultado de uma mesclagem funciona', () async {
      final a = await buildTextPdf(pageCount: 2, prefix: 'A');
      final b = asset('termo.pdf');

      final first = await PdfDocument.merge(<Uint8List>[a, b]);
      final second = await PdfDocument.merge(<Uint8List>[first, a]);

      final pagesA = reopen(a).pageCount;
      final pagesB = reopen(b).pageCount;
      expect(reopen(first).pageCount, pagesA + pagesB);
      expect(reopen(second).pageCount, pagesA + pagesB + pagesA);
    });

    test('o conteúdo sobrevive a duas mesclagens seguidas', () async {
      final source = asset('termo.pdf');
      final once = await PdfDocument.merge(<Uint8List>[source]);
      final twice = await PdfDocument.merge(<Uint8List>[once]);

      final original = reopen(source);
      final result = reopen(twice);
      for (var i = 0; i < original.pageCount; i++) {
        expect(decodedPageContent(result, i), decodedPageContent(original, i));
      }
    });

    test('o documento mesclado aceita edição incremental', () async {
      final merged = await PdfDocument.merge(<Uint8List>[asset('termo.pdf')]);

      final document = PdfDocument.parseFromBytes(merged);
      document.addUriAnnotation(
        pageNumber: 1,
        bounds: const PdfRect(10, 10, 100, 20),
        uri: 'https://example.org/depois-do-merge',
      );
      final updated = await document.save(useIsolate: false);

      expect(reopen(updated).pageCount, reopen(merged).pageCount);
      expect(
        String.fromCharCodes(updated)
            .contains('https://example.org/depois-do-merge'),
        isTrue,
      );
    });

    test('o documento mesclado pode ser assinado depois', () async {
      // Caso de uso real: mesclar o processo e assinar o consolidado.
      final merged = await PdfDocument.merge(<Uint8List>[asset('termo.pdf')]);

      final document = PdfDocument.parseFromBytes(merged);
      document.addSignatureField(
        pageNumber: 1,
        bounds: const PdfRect(40, 40, 200, 60),
        fieldName: 'AssinaturaDoConsolidado',
      );
      final prepared = await document.save(useIsolate: false);

      final fields = reopen(prepared).extractSignatureFields();
      expect(fields.map((f) => f.fieldName), contains('AssinaturaDoConsolidado'));
    });

    test('a saída não tem assinatura pendente inesperada', () async {
      final merged = await PdfDocument.merge(<Uint8List>[asset('termo.pdf')]);
      final report =
          await PdfSignatureValidator().validateAllSignatures(merged);
      expect(report.signatures, isEmpty);
    });
  });
}
