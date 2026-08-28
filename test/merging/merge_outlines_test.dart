import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

void main() {
  const withOutline = 'paginador.pdf';

  group('bookmarks', () {
    test('a árvore inteira chega ao documento mesclado', () async {
      final bytes = asset(withOutline);
      final source = reopen(bytes);
      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes]));

      expect(outlineCount(source), greaterThan(0));
      expect(outlineCount(merged), outlineCount(source));
      expect(outlineTitles(merged), outlineTitles(source));
    });

    test('cada bookmark salta para uma página existente', () async {
      final merged =
          reopen(await PdfDocument.merge(<Uint8List>[asset(withOutline)]));

      for (var i = 0; i < outlineCount(merged); i++) {
        final target = outlineTargetPage(merged, i);
        expect(target, isNotNull, reason: 'bookmark $i sem destino');
        expect(target, inInclusiveRange(0, merged.pageCount - 1));
      }
    });

    test('mesclado duas vezes, a segunda cópia aponta para si mesma', () async {
      final bytes = asset(withOutline);
      final single = reopen(await PdfDocument.merge(<Uint8List>[bytes]));
      final doubled =
          reopen(await PdfDocument.merge(<Uint8List>[bytes, bytes]));

      final count = outlineCount(single);
      expect(outlineCount(doubled), count * 2);

      final offset = single.pageCount;
      for (var i = count; i < count * 2; i++) {
        final target = outlineTargetPage(doubled, i);
        expect(target, isNotNull);
        expect(target, greaterThanOrEqualTo(offset),
            reason: 'bookmark $i saltou para a primeira cópia');
      }
    });

    test('destino nomeado vira destino explícito, com a mesma vista', () async {
      // Os bookmarks deste documento apontam por nome (`/A /D (6044075)`).
      // A mesclagem resolve o nome na árvore de nomes da origem e reemite um
      // destino explícito — assim o documento navega sem depender de a árvore
      // de nomes ter sido reconstruída.
      final bytes = asset(withOutline);
      final source = reopen(bytes);
      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes]));

      final sourceRoot = source.rootDict!;
      final sourceOutlines =
          source.resolve(sourceRoot.values['/Outlines']) as PdfDictToken;
      final firstSource =
          source.resolve(sourceOutlines.values['/First']) as PdfDictToken;
      final sourceAction =
          source.resolve(firstSource.values['/A']) as PdfDictToken;
      expect(
        source.resolve(sourceAction.values['/D']),
        isA<PdfStringToken>(),
        reason: 'a fixture precisa usar destino nomeado',
      );

      final mergedRoot = merged.rootDict!;
      final mergedOutlines =
          merged.resolve(mergedRoot.values['/Outlines']) as PdfDictToken;
      final firstMerged =
          merged.resolve(mergedOutlines.values['/First']) as PdfDictToken;
      final dest = merged.resolve(firstMerged.values['/Dest']);

      expect(dest, isA<PdfArrayToken>());
      final values = (dest as PdfArrayToken).values;
      expect(PdfParserObjects.asRef(values.first), isNotNull);
      // A vista vem do destino original, não do padrão `/Fit` do modelo.
      expect(PdfParserObjects.asName(values[1]), '/XYZ');
    });

    test('groupBookmarksPerDocument cria um nó por origem', () async {
      final bytes = asset(withOutline);
      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[bytes, bytes],
        options: const PdfMergeOptions(groupBookmarksPerDocument: true),
      ));

      final titles = outlineTitles(merged);
      expect(titles.where((t) => t.startsWith('documento')).length, 2);
    });

    test('importBookmarks desligado não cria /Outlines', () async {
      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[asset(withOutline)],
        options: const PdfMergeOptions(importBookmarks: false),
      ));

      expect(outlineCount(merged), 0);
    });
  });
}
