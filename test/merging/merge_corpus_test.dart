import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

/// Varredura do corpus inteiro: todo PDF de `test/assets/pdfs` precisa mesclar
/// sem exceção, preservando páginas e conteúdo.
void main() {
  final files = Directory('test/assets/pdfs')
      .listSync()
      .whereType<File>()
      .where((f) => f.path.toLowerCase().endsWith('.pdf'))
      .toList()
    ..sort((a, b) => a.path.compareTo(b.path));

  group('corpus', () {
    for (final file in files) {
      final name = file.path.split(RegExp(r'[\\/]')).last;

      test(name, () async {
        final bytes = file.readAsBytesSync();
        final source = reopen(bytes);
        final pageCount = source.pageCount;
        if (pageCount == 0) {
          markTestSkipped('$name não tem páginas legíveis');
          return;
        }

        final merged = await PdfDocument.merge(<Uint8List>[bytes]);
        final result = reopen(merged);

        expect(result.pageCount, pageCount, reason: 'contagem de páginas');

        for (var i = 0; i < pageCount; i++) {
          expect(
            decodedPageContent(result, i),
            decodedPageContent(source, i),
            reason: 'conteúdo da página ${i + 1}',
          );
        }
      }, timeout: const Timeout(Duration(minutes: 5)));
    }

    test('o corpus inteiro cabe em um único documento', () async {
      final inputs = <Uint8List>[];
      var expectedPages = 0;
      for (final file in files) {
        final bytes = file.readAsBytesSync();
        final pages = reopen(bytes).pageCount;
        if (pages == 0) continue;
        // Os maiores ficam de fora para o teste não virar um benchmark.
        if (bytes.length > 2 * 1024 * 1024) continue;
        inputs.add(bytes);
        expectedPages += pages;
      }

      final merged = await PdfDocument.merge(inputs);
      expect(reopen(merged).pageCount, expectedPages);
    }, timeout: const Timeout(Duration(minutes: 10)));
  });
}
