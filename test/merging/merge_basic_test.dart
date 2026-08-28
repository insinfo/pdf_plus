import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

void main() {
  group('merge básico', () {
    test('soma as páginas na ordem das origens', () async {
      final a = await buildTextPdf(pageCount: 2, prefix: 'A');
      final b = await buildTextPdf(pageCount: 3, prefix: 'B');

      final merged = reopen(await PdfDocument.merge(<Uint8List>[a, b]));
      expect(merged.pageCount, 5);
    });

    test('cada página mantém o próprio tamanho', () async {
      final a = await buildTextPdf(pageCount: 1, format: PdfPageFormat.a4);
      final b = await buildTextPdf(pageCount: 1, format: PdfPageFormat.a5);

      final merged = reopen(await PdfDocument.merge(<Uint8List>[a, b]));
      final boxA = merged.resolvePageMediaBox(merged.pageDictAt(0)!)!;
      final boxB = merged.resolvePageMediaBox(merged.pageDictAt(1)!)!;

      expect(boxA[2] - boxA[0], closeTo(PdfPageFormat.a4.width, 0.01));
      expect(boxB[2] - boxB[0], closeTo(PdfPageFormat.a5.width, 0.01));
    });

    test('mesclar um único documento preserva a contagem', () async {
      final merged =
          await PdfDocument.merge(<Uint8List>[await buildTextPdf(pageCount: 4)]);
      expect(reopen(merged).pageCount, 4);
    });

    test('lista vazia gera um documento sem páginas', () async {
      final merged = await PdfDocument.merge(<Uint8List>[]);
      expect(reopen(merged).pageCount, 0);
    });
  });

  group('API', () {
    test('importPage traz uma página só', () async {
      final source = await buildTextPdf(pageCount: 5);

      final document = PdfDocument();
      final merger = PdfDocumentMerger(document);
      merger.importPage(reopen(source), 2);
      merger.finish();

      final merged = reopen(await document.save(useIsolate: false));
      expect(merged.pageCount, 1);
    });

    test('importPageRange respeita as duas pontas', () async {
      final source = await buildTextPdf(pageCount: 6);

      final document = PdfDocument();
      final merger = PdfDocumentMerger(document);
      merger.importPageRange(reopen(source), 1, 3);
      merger.finish();

      final merged = reopen(await document.save(useIsolate: false));
      expect(merged.pageCount, 3);
    });

    test('append devolve as páginas criadas', () async {
      final source = await buildTextPdf(pageCount: 3);

      final document = PdfDocument();
      final merger = PdfDocumentMerger(document);
      final pages = merger.append(reopen(source));
      merger.finish();

      expect(pages.length, 3);
      expect(document.pdfPageList.pages.length, 3);
    });

    test('appendDocument funciona direto no PdfDocument', () async {
      final source = await buildTextPdf(pageCount: 2);

      final document = PdfDocument();
      document.appendDocument(reopen(source));
      final merged = reopen(await document.save(useIsolate: false));

      expect(merged.pageCount, 2);
    });

    test('mesclar depois de finish é recusado', () async {
      final source = await buildTextPdf(pageCount: 1);
      final merger = PdfDocumentMerger(PdfDocument());
      merger.finish();

      expect(() => merger.append(reopen(source)), throwsA(isA<StateError>()));
    });

    test('as páginas são anexadas depois das que o destino já tinha', () async {
      final document = PdfDocument();
      PdfPage(document, pageFormat: PdfPageFormat.a4);

      final merger = PdfDocumentMerger(document);
      merger.append(reopen(await buildTextPdf(pageCount: 2)));
      merger.finish();

      final merged = reopen(await document.save(useIsolate: false));
      expect(merged.pageCount, 3);
    });
  });

  group('modo flatten', () {
    test('preserva páginas, tamanho e conteúdo gráfico', () async {
      final source = asset('termo.pdf');
      final original = reopen(source);
      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[source],
        options: const PdfMergeOptions(mode: PdfMergeMode.flatten),
      ));

      expect(merged.pageCount, original.pageCount);
      for (var i = 0; i < merged.pageCount; i++) {
        final before = original.resolvePageMediaBox(original.pageDictAt(i)!)!;
        final after = merged.resolvePageMediaBox(merged.pageDictAt(i)!)!;
        expect(after[2] - after[0], closeTo(before[2] - before[0], 0.01));
        expect(after[3] - after[1], closeTo(before[3] - before[1], 0.01));
      }

      // As imagens da origem seguem no arquivo.
      expect(merged.extractImages(), isNotEmpty);
    });

    test('descarta anotações, que é o contrato do modo', () async {
      final source = asset('termo.pdf');
      expect(annotationCount(reopen(source)), greaterThan(0));

      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[source],
        options: const PdfMergeOptions(mode: PdfMergeMode.flatten),
      ));
      expect(annotationCount(merged), 0);
    });

    test('a página vira um Form XObject desenhado', () async {
      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[asset('termo.pdf')],
        options: const PdfMergeOptions(mode: PdfMergeMode.flatten),
      ));

      final resources = merged.resolvePageResources(merged.pageDictAt(0)!)!;
      final xObjects = merged.resolve(resources.values['/XObject']);
      expect(xObjects, isA<PdfDictToken>());

      var forms = 0;
      for (final value in (xObjects as PdfDictToken).values.values) {
        final object = merged.resolve(value);
        if (object is! PdfDictToken) continue;
        final subtype = object.values['/Subtype'];
        if (subtype is PdfNameToken && subtype.value == '/Form') forms++;
      }
      expect(forms, greaterThan(0));
    });

    test('mescla vários documentos no modo flatten', () async {
      final a = await buildTextPdf(pageCount: 2);
      final b = await buildTextPdf(pageCount: 1);

      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[a, b],
        options: const PdfMergeOptions(mode: PdfMergeMode.flatten),
      ));
      expect(merged.pageCount, 3);
    });
  });

  group('avisos', () {
    test('a mesclagem relata o que se perdeu', () async {
      final document = PdfDocument();
      final merger = PdfDocumentMerger(document);
      merger.append(reopen(asset('sample3.pdf')), label: 'processo');
      merger.finish();
      await document.save(useIsolate: false);

      expect(merger.warnings, isNotEmpty);
      expect(merger.warnings.every((w) => w.startsWith('[processo]')), isTrue);
    });

    test('documento sem perdas não gera aviso', () async {
      final document = PdfDocument();
      final merger = PdfDocumentMerger(document);
      merger.append(reopen(await buildTextPdf(pageCount: 2)));
      merger.finish();
      await document.save(useIsolate: false);

      expect(merger.warnings, isEmpty);
    });
  });
}
