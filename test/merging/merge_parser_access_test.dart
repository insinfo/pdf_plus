import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_predictor.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_document_info.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:pdf_plus/src/pdf/io/pdf_random_access_reader_io.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

void main() {
  group('leitura de streams', () {
    // O leitor por janela devolvia null para qualquer stream que não coubesse
    // nos primeiros 8 KB lidos: a escalada de janelas só acontecia quando o
    // cabeçalho falhava, nunca quando o stream não cabia. Isso deixava a
    // mesclagem sem imagens e sem conteúdo.
    const file = 'test/assets/pdfs/10 assinaturas.pdf';
    const imageObject = 17;
    const imageLength = 13955;

    PdfIndirectRef ref(PdfDocumentParser parser) {
      final images = parser.extractImages();
      expect(images, isNotEmpty);
      return images.first.imageRef;
    }

    test('stream maior que a janela vem inteiro, vindo de arquivo', () {
      for (final cache in <bool>[true, false]) {
        final reader = PdfRandomAccessFileReader.openSync(File(file));
        final parser =
            PdfDocumentParser.fromReader(reader, enableCache: cache);
        final data = parser.readStreamData(ref(parser));
        expect(data, isNotNull, reason: 'enableCache: $cache');
        expect(data!.length, imageLength, reason: 'enableCache: $cache');
        reader.close();
      }
    });

    test('stream maior que a janela vem inteiro, vindo de memória', () {
      final bytes = asset('10 assinaturas.pdf');
      for (final cache in <bool>[true, false]) {
        final parser = PdfDocumentParser(bytes, enableCache: cache);
        final data = parser.readStreamData(ref(parser));
        expect(data, isNotNull, reason: 'enableCache: $cache');
        expect(data!.length, imageLength, reason: 'enableCache: $cache');
      }
    });

    test('o objeto lido é o esperado', () {
      final parser = PdfDocumentParser(asset('10 assinaturas.pdf'));
      final object = parser.getObject(imageObject);
      expect(object, isNotNull);
      expect(object!.streamData!.length, imageLength);
    });
  });

  group('preditor de xref stream', () {
    // Sem desfazer o preditor PNG, todo offset lido da tabela é lixo: em
    // sample3.pdf apontavam para além do fim do arquivo, e 95% dos objetos
    // ficavam ilegíveis.
    test('todos os objetos da tabela são legíveis', () {
      final parser = PdfDocumentParser(asset('sample3.pdf'), allowRepair: true);
      final ids = parser.objectIds;
      expect(ids.length, greaterThan(10000));

      var falhas = 0;
      for (final id in ids) {
        if (parser.storageOf(id) == XrefType.free) continue;
        if (parser.getObject(id) == null) falhas++;
      }
      expect(falhas, 0);
    });

    test('a contagem de páginas reflete o documento inteiro', () {
      final parser = PdfDocumentParser(asset('sample3.pdf'), allowRepair: true);
      expect(parser.pageCount, 366);
    });

    test('desfaz o filtro Up do PNG', () {
      // Duas linhas de 3 bytes: a primeira sem filtro, a segunda somando a
      // anterior.
      final data = Uint8List.fromList(<int>[
        0, 10, 20, 30, //
        2, 1, 2, 3,
      ]);
      final out = PdfParserPredictor.apply(
        data,
        const PdfPredictorParams(predictor: 12, columns: 3),
      );
      expect(out, <int>[10, 20, 30, 11, 22, 33]);
    });

    test('sem preditor os dados passam intactos', () {
      final data = Uint8List.fromList(<int>[1, 2, 3, 4]);
      final out = PdfParserPredictor.apply(data, const PdfPredictorParams());
      expect(identical(out, data), isTrue);
    });
  });

  group('API pública de objetos', () {
    test('expõe catálogo, páginas e atributos herdados', () {
      final parser = PdfDocumentParser(asset('paginador.pdf'), allowRepair: true);

      expect(parser.rootDict, isNotNull);
      expect(parser.rootRef, isNotNull);
      expect(parser.pageRefs.length, parser.pageCount);

      final page = parser.pageDictAt(0)!;
      expect(parser.resolvePageMediaBox(page), isNotNull);
      expect(parser.resolvePageResources(page), isNotNull);
    });

    test('resolve segue referências indiretas', () {
      final parser = PdfDocumentParser(asset('paginador.pdf'), allowRepair: true);
      final root = parser.rootDict!;
      final pages = parser.resolve(root.values['/Pages']);
      expect(pages, isA<PdfDictToken>());
    });

    test('pageRefs é memorizado', () {
      final parser = PdfDocumentParser(asset('paginador.pdf'), allowRepair: true);
      expect(identical(parser.pageRefs, parser.pageRefs), isTrue);
    });
  });
}
