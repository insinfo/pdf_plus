import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

void main() {
  group('anotações', () {
    test('todas as anotações atravessam a mesclagem', () async {
      final bytes = asset('termo.pdf');
      final source = reopen(bytes);
      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes]));

      expect(annotationCount(merged), annotationCount(source));
    });

    test('/P aponta para a página que contém a anotação', () async {
      final merged =
          reopen(await PdfDocument.merge(<Uint8List>[asset('termo.pdf')]));

      for (var i = 0; i < merged.pageCount; i++) {
        final pageRef = merged.pageRefs[i];
        for (final annot in annotationsOf(merged, i)) {
          final parent = PdfParserObjects.asRef(annot.values['/P']);
          expect(parent, isNotNull);
          expect(parent!.obj, pageRef.obj, reason: 'página ${i + 1}');
        }
      }
    });

    test('a anotação não guarda /Parent de campo quando não é widget',
        () async {
      final merged =
          reopen(await PdfDocument.merge(<Uint8List>[asset('termo.pdf')]));

      for (var i = 0; i < merged.pageCount; i++) {
        for (final annot in annotationsOf(merged, i)) {
          if (PdfParserObjects.asName(annot.values['/Subtype']) == '/Widget') {
            continue;
          }
          expect(annot.values['/Parent'], isNull);
        }
      }
    });

    test('importAnnotations desligado deixa as páginas limpas', () async {
      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[asset('termo.pdf')],
        options: const PdfMergeOptions(importAnnotations: false),
      ));

      expect(annotationCount(merged), 0);
    });
  });

  group('links e destinos', () {
    test('os links continuam sabendo para onde saltar', () async {
      final bytes = asset('sample3.pdf');
      final source = reopen(bytes);
      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes]));

      expect(linksWithDestination(merged), linksWithDestination(source));
    });

    test('mesclado duas vezes, cada cópia salta dentro de si mesma', () async {
      final bytes = asset('sample3.pdf');
      final single = reopen(await PdfDocument.merge(<Uint8List>[bytes]));
      final doubled =
          reopen(await PdfDocument.merge(<Uint8List>[bytes, bytes]));

      expect(doubled.pageCount, single.pageCount * 2);

      // Um link da segunda cópia precisa apontar para uma página da segunda
      // cópia, nunca para a primeira.
      final offset = single.pageCount;
      var checked = 0;
      for (var page = offset; page < doubled.pageCount && checked < 25; page++) {
        for (final annot in annotationsOf(doubled, page)) {
          if (PdfParserObjects.asName(annot.values['/Subtype']) != '/Link') {
            continue;
          }
          final target = linkTargetPage(doubled, annot);
          if (target == null) continue;
          expect(target, greaterThanOrEqualTo(offset),
              reason: 'link da página ${page + 1} saltou para a outra cópia');
          checked++;
        }
      }
      expect(checked, greaterThan(0));
    });

    test('destino fora do intervalo importado vira aviso, não link quebrado',
        () async {
      final bytes = asset('sample3.pdf');
      final document = PdfDocument();
      final merger = PdfDocumentMerger(document);
      // Só as primeiras páginas: parte dos destinos fica de fora.
      merger.importPageRange(reopen(bytes), 0, 4);
      merger.finish();
      final merged = reopen(await document.save(useIsolate: false));

      expect(
        merger.warnings.any((w) => w.contains('fora do intervalo')),
        isTrue,
      );

      for (var i = 0; i < merged.pageCount; i++) {
        for (final annot in annotationsOf(merged, i)) {
          if (PdfParserObjects.asName(annot.values['/Subtype']) != '/Link') {
            continue;
          }
          final dest = merged.resolve(annot.values['/Dest']);
          if (dest is PdfArrayToken && dest.values.isNotEmpty) {
            // Nenhum destino remanescente pode apontar para o vazio.
            expect(PdfParserObjects.asRef(dest.values.first), isNotNull);
          }
        }
      }
    });

    test('links externos passam intactos', () async {
      final document = PdfDocument();
      final page = PdfPage(document, pageFormat: PdfPageFormat.a4);
      PdfAnnot(
        page,
        PdfAnnotUrlLink(
          rect: const PdfRect(10, 10, 100, 20),
          url: 'https://example.org/teste',
        ),
      );
      final source = await document.save(useIsolate: false);

      final merged = await PdfDocument.merge(<Uint8List>[source]);
      final text = String.fromCharCodes(merged);
      expect(text.contains('https://example.org/teste'), isTrue);
    });
  });
}
