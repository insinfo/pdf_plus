import 'dart:io';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/io/pdf_random_access_reader_io.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

/// Mesclar direto de um leitor de arquivo evita carregar a origem inteira em
/// memória — o caso dos processos digitalizados de centenas de MB.
void main() {
  group('origem por leitor de arquivo', () {
    test('mescla sem carregar o arquivo em memória', () async {
      final file = File('test/assets/pdfs/paginador.pdf');
      final reader = PdfRandomAccessFileReader.openSync(file);
      final parser = PdfDocumentParser.fromReader(reader, allowRepair: true);

      final document = PdfDocument();
      final merger = PdfDocumentMerger(document);
      final pages = merger.append(parser, label: 'arquivo');
      merger.finish();
      final merged = await document.save(useIsolate: false);
      reader.close();

      final result = reopen(merged);
      expect(pages.length, result.pageCount);
      expect(result.pageCount, reopen(asset('paginador.pdf')).pageCount);
      expect(merger.warnings, isEmpty);
    });

    test('o conteúdo sai igual ao da leitura por bytes', () async {
      final file = File('test/assets/pdfs/termo.pdf');
      final reader = PdfRandomAccessFileReader.openSync(file);

      final fromReader = PdfDocument();
      final merger = PdfDocumentMerger(fromReader);
      merger.append(PdfDocumentParser.fromReader(reader, allowRepair: true));
      merger.finish();
      final viaReader = reopen(await fromReader.save(useIsolate: false));
      reader.close();

      final viaBytes = reopen(await PdfDocument.merge(<dynamic>[
        asset('termo.pdf'),
      ].cast()));

      expect(viaReader.pageCount, viaBytes.pageCount);
      for (var i = 0; i < viaReader.pageCount; i++) {
        expect(decodedPageContent(viaReader, i), decodedPageContent(viaBytes, i));
      }
    });
  });
}
