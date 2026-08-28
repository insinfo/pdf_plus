import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

void main() {
  group('fidelidade de conteúdo', () {
    test('o conteúdo das páginas atravessa a mesclagem intacto', () async {
      final bytes = asset('10 assinaturas.pdf');
      final source = reopen(bytes);
      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes]));

      expect(merged.pageCount, source.pageCount);
      for (var i = 0; i < source.pageCount; i++) {
        expect(
          decodedPageContent(merged, i),
          decodedPageContent(source, i),
          reason: 'página ${i + 1}',
        );
      }
    });

    test('as imagens continuam presentes e do mesmo tamanho', () async {
      final bytes = asset('10 assinaturas.pdf');
      final source = reopen(bytes);
      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes]));

      final before = source.extractImages();
      final after = merged.extractImages();
      expect(after.length, before.length);

      for (var i = 0; i < before.length; i++) {
        expect(after[i].width, before[i].width);
        expect(after[i].height, before[i].height);
        expect(after[i].filter, before[i].filter);
        expect(
          merged.readStreamData(after[i].imageRef)!.length,
          source.readStreamData(before[i].imageRef)!.length,
        );
      }
    });

    test('streams com filtro são copiados byte a byte', () async {
      final bytes = asset('10 assinaturas.pdf');
      final source = reopen(bytes);
      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes]));

      final before = source.extractImages().first;
      final after = merged.extractImages().first;
      expect(
        merged.readStreamData(after.imageRef),
        source.readStreamData(before.imageRef),
      );
    });

    test('os recursos de cada página apontam para objetos existentes',
        () async {
      final bytes = asset('termo.pdf');
      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes]));

      for (var i = 0; i < merged.pageCount; i++) {
        final resources = merged.resolvePageResources(merged.pageDictAt(i)!);
        expect(resources, isNotNull, reason: 'página ${i + 1}');

        final fonts = merged.resolve(resources!.values['/Font']);
        if (fonts is! PdfDictToken) continue;
        for (final entry in fonts.values.entries) {
          expect(
            merged.resolve(entry.value),
            isA<PdfDictToken>(),
            reason: 'fonte ${entry.key} da página ${i + 1}',
          );
        }
      }
    });
  });

  group('deduplicação de recursos', () {
    test('cinco cópias saem menores que cinco vezes uma', () async {
      final bytes = asset('10 assinaturas.pdf');
      final one = await PdfDocument.merge(<Uint8List>[bytes]);
      final five = await PdfDocument.merge(List<Uint8List>.filled(5, bytes));

      expect(five.length, lessThan(one.length * 5));
      expect(reopen(five).pageCount, reopen(one).pageCount * 5);
    });

    test('desligar a deduplicação aumenta o arquivo', () async {
      final bytes = asset('10 assinaturas.pdf');
      final withDedup = await PdfDocument.merge(
        List<Uint8List>.filled(3, bytes),
      );
      final without = await PdfDocument.merge(
        List<Uint8List>.filled(3, bytes),
        options: const PdfMergeOptions(deduplicateResources: false),
      );

      expect(withDedup.length, lessThan(without.length));
    });

    test('um recurso compartilhado por duas páginas vira um objeto só',
        () async {
      final bytes = await buildImagePdf(pageCount: 3);
      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes]));

      final imageRefs = <int>{};
      for (var i = 0; i < merged.pageCount; i++) {
        final resources = merged.resolvePageResources(merged.pageDictAt(i)!);
        final xObjects = merged.resolve(resources?.values['/XObject']);
        if (xObjects is! PdfDictToken) continue;
        for (final value in xObjects.values.values) {
          final ref = PdfParserObjects.asRef(value);
          if (ref != null) imageRefs.add(ref.obj);
        }
      }

      expect(imageRefs.length, 1);
    });
  });
}
