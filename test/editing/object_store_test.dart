import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/format/array.dart';
import 'package:pdf_plus/src/pdf/format/base.dart';
import 'package:pdf_plus/src/pdf/format/dict.dart';
import 'package:pdf_plus/src/pdf/format/indirect.dart';
import 'package:pdf_plus/src/pdf/format/num.dart';
import 'package:pdf_plus/src/pdf/obj/object.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_document_info.dart';
import 'package:pdf_plus/widgets.dart' as pw;
import 'package:test/test.dart';

/// Objeto solto no documento, com número e geração escolhidos.
PdfObject<PdfDataType> put(
  PdfDocument document,
  PdfDataType params, {
  int? objser,
  int objgen = 0,
}) =>
    PdfObject<PdfDataType>(
      document,
      params: params,
      objser: objser,
      objgen: objgen,
    );

/// PDF simples, para exercitar a leitura pelo parser de origem.
Future<Uint8List> buildPdf() async {
  final document = pw.Document();
  document.addPage(
    pw.Page(build: (context) => pw.Center(child: pw.Text('Pagina 1'))),
  );
  return document.save();
}

void main() {
  group('PdfObjectId', () {
    test('igualdade e hash consideram número e geração', () {
      expect(const PdfObjectId(3, 0), const PdfObjectId(3, 0));
      expect(const PdfObjectId(3, 0), isNot(const PdfObjectId(3, 1)));
      expect(const PdfObjectId(3, 0).hashCode, const PdfObjectId(3, 0).hashCode);
      final ids = <PdfObjectId>{}
        ..add(const PdfObjectId(3, 0))
        ..add(const PdfObjectId(3, 0))
        ..add(const PdfObjectId(3, 1));
      expect(ids, hasLength(2));
    });

    test('fromIndirect e toIndirect são inversos', () {
      const ref = PdfIndirect(9, 2);
      final id = PdfObjectId.fromIndirect(ref);
      expect(id.number, 9);
      expect(id.generation, 2);
      expect(id.toIndirect(), ref);
    });

    test('fromObject usa objser e objgen', () {
      final document = PdfDocument();
      final object = put(document, PdfDict(), objser: 40, objgen: 5);
      expect(PdfObjectId.fromObject(object), const PdfObjectId(40, 5));
    });
  });

  group('PdfObjectStore — documento novo', () {
    test('encontra o objeto pela referência', () {
      final document = PdfDocument();
      final target = put(document, PdfDict.values(<String, PdfDataType>{
        '/Type': const PdfName('/Test'),
      }));
      final store = PdfObjectStore(document);

      expect(store.lookup(target.ref()), same(target));
      expect(store.containsId(PdfObjectId.fromObject(target)), isTrue);
    });

    test('referência inexistente devolve null', () {
      final document = PdfDocument();
      final store = PdfObjectStore(document);
      expect(store.lookup(const PdfIndirect(9999, 0)), isNull);
      expect(store.containsId(const PdfObjectId(9999, 0)), isFalse);
    });

    test('a geração faz parte da chave', () {
      final document = PdfDocument();
      final gen0 = put(document, const PdfName('/Zero'), objser: 77);
      final gen1 = put(document, const PdfName('/Um'), objser: 77, objgen: 1);
      final store = PdfObjectStore(document);

      expect(store.lookup(const PdfIndirect(77, 0)), same(gen0));
      expect(store.lookup(const PdfIndirect(77, 1)), same(gen1));
    });

    test('sem parser o store não enxerga nada além do materializado', () {
      final document = PdfDocument();
      final store = PdfObjectStore(document);
      expect(store.hasSourceParser, isFalse);
    });
  });

  group('PdfObjectStore — invalidação do índice', () {
    test('objeto acrescentado depois da primeira consulta é encontrado', () {
      final document = PdfDocument();
      final store = PdfObjectStore(document);
      expect(store.lookup(const PdfIndirect(9999, 0)), isNull);

      final added = put(document, PdfDict());
      expect(store.lookup(added.ref()), same(added));
    });

    test('objeto removido deixa de ser encontrado', () {
      final document = PdfDocument();
      final target = put(document, PdfDict());
      final store = PdfObjectStore(document);
      expect(store.lookup(target.ref()), same(target));

      document.objects.remove(target);
      expect(store.lookup(target.ref()), isNull);
    });

    test('troca que mantém o tamanho só é vista depois de invalidate', () {
      final document = PdfDocument();
      final first = put(document, PdfDict());
      final store = PdfObjectStore(document);
      expect(store.lookup(first.ref()), same(first));

      final before = document.objects.length;
      document.objects.remove(first);
      final second = put(document, PdfDict());
      expect(document.objects.length, before);

      // Índice desatualizado: o tamanho não mudou.
      expect(store.lookup(second.ref()), isNull);

      store.invalidate();
      expect(store.lookup(second.ref()), same(second));
      expect(store.lookup(first.ref()), isNull);
    });
  });

  group('PdfObjectStore — resolução', () {
    test('valor direto volta como está', () {
      final document = PdfDocument();
      final store = PdfObjectStore(document);
      const value = PdfName('/Direto');
      expect(store.resolve(value), same(value));
      expect(store.resolve(null), isNull);
    });

    test('segue uma cadeia de referências', () {
      final document = PdfDocument();
      final leaf = put(document, PdfDict.values(<String, PdfDataType>{
        '/Type': const PdfName('/Folha'),
      }));
      final middle = put(document, leaf.ref());
      final root = put(document, middle.ref());
      final store = PdfObjectStore(document);

      final resolved = store.resolve(root.ref());
      expect(resolved, same(leaf.params));
      expect(store.resolveDict(root.ref()), same(leaf.params));
    });

    test('maxDepth interrompe a cadeia', () {
      final document = PdfDocument();
      final leaf = put(document, PdfDict());
      final middle = put(document, leaf.ref());
      final root = put(document, middle.ref());
      final store = PdfObjectStore(document);

      expect(store.resolve(root.ref(), maxDepth: 1), isA<PdfIndirect>());
      expect(store.resolveDict(root.ref(), maxDepth: 1), isNull);
      expect(store.resolveDict(root.ref(), maxDepth: 2), isNull);
      // Três saltos: root -> middle -> leaf -> dicionário.
      expect(store.resolveDict(root.ref(), maxDepth: 3), same(leaf.params));
    });

    test('ciclo não trava a resolução', () {
      final document = PdfDocument();
      // 500 aponta para si próprio; 501 aponta para 500.
      put(document, const PdfIndirect(500, 0), objser: 500);
      final entry = put(document, const PdfIndirect(500, 0), objser: 501);
      final store = PdfObjectStore(document);

      expect(store.resolve(entry.ref()), const PdfIndirect(500, 0));
      expect(store.resolveDict(entry.ref()), isNull);
    });

    test('referência quebrada resolve para null', () {
      final document = PdfDocument();
      final store = PdfObjectStore(document);
      expect(store.resolve(const PdfIndirect(4242, 0)), isNull);
      expect(store.resolveDict(const PdfIndirect(4242, 0)), isNull);
      expect(store.resolveArray(const PdfIndirect(4242, 0)), isNull);
    });

    test('resolveDict e resolveArray filtram pelo tipo', () {
      final document = PdfDocument();
      final dict = put(document, PdfDict());
      final array = put(document, PdfArray());
      final store = PdfObjectStore(document);

      expect(store.resolveDict(dict.ref()), isA<PdfDict>());
      expect(store.resolveArray(dict.ref()), isNull);
      expect(store.resolveArray(array.ref()), isA<PdfArray>());
      expect(store.resolveDict(array.ref()), isNull);

      final direct = PdfArray<PdfNum>(<PdfNum>[const PdfNum(1)]);
      expect(store.resolveArray(direct), same(direct));
    });
  });

  group('PdfObjectStore — documento carregado', () {
    late Uint8List bytes;

    setUpAll(() async {
      bytes = await buildPdf();
    });

    /// Referência de um objeto que o parser conhece mas que não foi
    /// materializado: o content stream da primeira página.
    PdfIndirect contentRef(PdfDocumentParser parser) {
      final page = parser.pageDictAt(0)!;
      final ref = PdfParserObjects.asRef(page.values['/Contents'])!;
      return PdfIndirect(ref.obj, ref.gen);
    }

    test('forDocument liga o store ao parser de origem', () {
      final document = PdfDocument.parseFromBytes(bytes);
      expect(PdfObjectStore.forDocument(document).hasSourceParser, isTrue);
      expect(PdfObjectStore.forDocument(PdfDocument()).hasSourceParser, isFalse);
    });

    test('sem parser o objeto do arquivo não é encontrado', () {
      final document = PdfDocument.parseFromBytes(bytes);
      final parser = document.prev as PdfDocumentParser;
      final ref = contentRef(parser);

      expect(PdfObjectStore(document).lookup(ref), isNull);
    });

    test('com parser o objeto do arquivo é materializado sob demanda', () {
      final document = PdfDocument.parseFromBytes(bytes);
      final parser = document.prev as PdfDocumentParser;
      final ref = contentRef(parser);
      final store = PdfObjectStore.forDocument(document);

      final object = store.lookup(ref)!;
      expect(object.objser, ref.ser);
      expect(object.objgen, ref.gen);
      // Do stream vem o dicionário; o corpo continua com o parser.
      expect(object.params, isA<PdfDict>());
      expect((object.params as PdfDict).containsKey('/Length'), isTrue);
      expect(parser.readStreamData(PdfIndirectRef(ref.ser, ref.gen)), isNotNull);
    });

    test('o objeto lido do parser não entra em document.objects', () {
      final document = PdfDocument.parseFromBytes(bytes);
      final parser = document.prev as PdfDocumentParser;
      final ref = contentRef(parser);
      final store = PdfObjectStore.forDocument(document);

      final before = document.objects.length;
      expect(store.lookup(ref), isNotNull);
      expect(document.objects.length, before);
      expect(store.containsId(PdfObjectId.fromIndirect(ref)), isFalse);
    });

    test('a leitura pelo parser é cacheada', () {
      final document = PdfDocument.parseFromBytes(bytes);
      final parser = document.prev as PdfDocumentParser;
      final ref = contentRef(parser);
      final store = PdfObjectStore.forDocument(document);

      expect(store.lookup(ref), same(store.lookup(ref)));
    });

    test('objeto já materializado vence a leitura pelo parser', () {
      final document = PdfDocument.parseFromBytes(bytes);
      final store = PdfObjectStore.forDocument(document);
      final catalog = document.catalog;

      expect(store.lookup(catalog.ref()), same(catalog));
    });

    test('a página materializada resolve pelo store', () {
      final document = PdfDocument.parseFromBytes(bytes);
      final store = PdfObjectStore.forDocument(document);
      final page = document.pdfPageList.pages.first;
      final contents = page.params['/Contents'];

      expect(store.resolveDict(contents), isA<PdfDict>());
    });
  });

  group('PdfObjectStore.of', () {
    test('devolve a mesma instância para o mesmo documento', () {
      final document = PdfDocument();
      final other = PdfDocument();

      expect(PdfObjectStore.of(document), same(PdfObjectStore.of(document)));
      expect(
        PdfObjectStore.of(document),
        isNot(same(PdfObjectStore.of(other))),
      );
      expect(PdfObjectStore.of(document).document, same(document));
      expect(PdfObjectStore.of(document).hasSourceParser, isFalse);
    });
  });
}
