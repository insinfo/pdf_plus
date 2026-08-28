import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/format/array.dart';
import 'package:pdf_plus/src/pdf/format/base.dart';
import 'package:pdf_plus/src/pdf/format/dict.dart';
import 'package:pdf_plus/src/pdf/obj/object.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:test/test.dart';

import '../merging/merge_helpers.dart';

/// Percorre todo objeto alcançável a partir do catálogo e devolve as
/// referências que caem em [forbidden].
///
/// É a contraparte de `danglingReferences` de `merge_integrity_test.dart`: um
/// objeto de página removido continua existindo nos bytes antigos do
/// incremental update, então ele **resolve** — o que não pode sobrar é alguém
/// ainda apontando para ele.
List<String> referencesTo(PdfDocumentParser parser, Set<int> forbidden) {
  final problems = <String>[];
  final visited = <int>{};

  void walk(dynamic value, String path, int depth) {
    if (depth > 64) return;

    if (value is PdfRefToken) {
      if (forbidden.contains(value.obj)) {
        problems.add('$path -> ${value.obj} ${value.gen} R');
        return;
      }
      final target = parser.getObject(value.obj);
      if (target == null) return;
      if (!visited.add(value.obj)) return;
      walk(target.value, '$path/${value.obj}', depth + 1);
      return;
    }

    if (value is PdfArrayToken) {
      for (var i = 0; i < value.values.length; i++) {
        walk(value.values[i], '$path[$i]', depth + 1);
      }
      return;
    }

    if (value is PdfDictToken) {
      for (final entry in value.values.entries) {
        walk(entry.value, '$path${entry.key}', depth + 1);
      }
    }
  }

  final root = parser.rootDict;
  if (root == null) return <String>['sem catálogo'];
  walk(root, '/Root', 0);
  return problems;
}

/// Referências que não resolvem, alcançáveis a partir do catálogo.
List<String> danglingReferences(PdfDocumentParser parser) {
  final problems = <String>[];
  final visited = <int>{};

  void walk(dynamic value, String path, int depth) {
    if (depth > 64) return;

    if (value is PdfRefToken) {
      final target = parser.getObject(value.obj);
      if (target == null) {
        problems.add('$path -> ${value.obj} ${value.gen} R não existe');
        return;
      }
      if (!visited.add(value.obj)) return;
      walk(target.value, '$path/${value.obj}', depth + 1);
      return;
    }

    if (value is PdfArrayToken) {
      for (var i = 0; i < value.values.length; i++) {
        walk(value.values[i], '$path[$i]', depth + 1);
      }
      return;
    }

    if (value is PdfDictToken) {
      for (final entry in value.values.entries) {
        walk(entry.value, '$path${entry.key}', depth + 1);
      }
    }
  }

  final root = parser.rootDict;
  if (root == null) return <String>['sem catálogo'];
  walk(root, '/Root', 0);
  return problems;
}

/// Nomes registrados em `/Names /Dests`.
List<String> namedDestinations(PdfDocumentParser parser) {
  final names = <String>[];
  final root = parser.rootDict;
  if (root == null) return names;
  final namesDict = parser.resolve(root.values['/Names']);
  if (namesDict is! PdfDictToken) return names;

  void walk(dynamic node, int depth) {
    if (depth > 32) return;
    final dict = parser.resolve(node);
    if (dict is! PdfDictToken) return;
    final entries = parser.resolve(dict.values['/Names']);
    if (entries is PdfArrayToken) {
      for (var i = 0; i + 1 < entries.values.length; i += 2) {
        final key = parser.resolve(entries.values[i]);
        if (key is PdfStringToken) names.add(String.fromCharCodes(key.bytes));
      }
    }
    final kids = parser.resolve(dict.values['/Kids']);
    if (kids is PdfArrayToken) {
      for (final kid in kids.values) {
        walk(kid, depth + 1);
      }
    }
  }

  walk(namesDict.values['/Dests'], 0);
  return names;
}

/// Faixas de `/PageLabels`, como pares `índice inicial -> prefixo/estilo`.
Map<int, String> pageLabelRanges(PdfDocumentParser parser) {
  final ranges = <int, String>{};
  final root = parser.rootDict;
  if (root == null) return ranges;
  final labels = parser.resolve(root.values['/PageLabels']);
  if (labels is! PdfDictToken) return ranges;
  final nums = parser.resolve(labels.values['/Nums']);
  if (nums is! PdfArrayToken) return ranges;

  for (var i = 0; i + 1 < nums.values.length; i += 2) {
    final key = parser.resolve(nums.values[i]);
    final value = parser.resolve(nums.values[i + 1]);
    if (key is! int || value is! PdfDictToken) continue;
    final style = PdfParserObjects.asName(value.values['/S']) ?? '';
    final start = parser.resolve(value.values['/St']);
    ranges[key] = '$style:${start is int ? start : ''}';
  }
  return ranges;
}

/// Referências do `/AcroForm /Fields` no topo.
List<int> acroFormFieldIds(PdfDocumentParser parser) {
  final form = acroForm(parser);
  if (form == null) return const <int>[];
  final fields = parser.resolve(form.values['/Fields']);
  if (fields is! PdfArrayToken) return const <int>[];
  return <int>[
    for (final value in fields.values)
      if (PdfParserObjects.asRef(value) != null)
        PdfParserObjects.asRef(value)!.obj,
  ];
}

/// Documento novo, com uma página por índice e conteúdo distinto em cada uma.
PdfDocument newDocumentWith(int count) {
  final document = PdfDocument();
  for (var i = 0; i < count; i++) {
    final page = PdfPage(document, pageFormat: PdfPageFormat.a4);
    final graphics = page.getGraphics();
    graphics.setColor(PdfColors.black);
    graphics.drawRect(10, 10, 20.0 + i * 7, 30.0 + i);
    graphics.fillPath();
  }
  return document;
}

/// Cria um link interno explícito de [from] para [to].
PdfObject<PdfDict> addExplicitLink(PdfPage from, PdfPage to) {
  final annot = PdfObject<PdfDict>(
    from.pdfDocument,
    params: PdfDict.values(<String, PdfDataType>{
      '/Type': const PdfName('/Annot'),
      '/Subtype': const PdfName('/Link'),
      '/Rect': PdfArray.fromNum(<double>[0, 0, 100, 20]),
      '/Dest': PdfArray<PdfDataType>(<PdfDataType>[
        to.ref(),
        const PdfName('/Fit'),
      ]),
    }),
  );
  final annots = from.params['/Annots'];
  if (annots is PdfArray) {
    annots.values.add(annot.ref());
  } else {
    from.params['/Annots'] =
        PdfArray<PdfDataType>(<PdfDataType>[annot.ref()]);
  }
  return annot;
}

/// PDF com destino nomeado, bookmarks, link interno, `/OpenAction`, rótulos de
/// página e um widget de assinatura — tudo apontando para a página 2.
Future<Uint8List> buildRichPdf() async {
  final document = newDocumentWith(5);
  final pages = document.pdfPageList.pages;

  document.pdfNames.addDest('alvo', pages[2]);
  document.outline
    ..add(PdfOutline(document, title: 'para o alvo', anchor: 'alvo'))
    ..add(PdfOutline(document, title: 'para a quarta', dest: pages[3]));

  addExplicitLink(pages[0], pages[2]);

  document.catalog.params['/OpenAction'] = PdfArray<PdfDataType>(
    <PdfDataType>[pages[2].ref(), const PdfName('/Fit')],
  );

  document.pageLabels.labels[0] = PdfPageLabel.romanLower();
  document.pageLabels.labels[2] = PdfPageLabel.arabic();

  document.addSignatureField(
    pageNumber: 3,
    bounds: const PdfRect(10, 10, 100, 40),
    fieldName: 'assinatura',
  );

  return document.save(useIsolate: false);
}

void main() {
  group('validação', () {
    test('índice fora do intervalo é recusado', () {
      final editor = PdfPageCollectionEditor(newDocumentWith(3));
      expect(() => editor.remove(3), throwsRangeError);
      expect(() => editor.remove(-1), throwsRangeError);
      expect(() => editor[3], throwsRangeError);
      expect(() => editor.move(0, 3), throwsRangeError);
      expect(() => editor.duplicate(9), throwsRangeError);
      expect(() => editor.removeRange(1, 9), throwsRangeError);
      expect(() => editor.removeRange(2, 1), throwsRangeError);
    });

    test('inserir no fim é permitido, além do fim não', () {
      final document = newDocumentWith(2);
      final editor = PdfPageCollectionEditor(document);
      final page = editor[0];
      expect(() => editor.insert(2, page), returnsNormally);
      expect(() => editor.insert(3, page), throwsRangeError);
    });

    test('página de outro documento é recusada', () {
      final editor = PdfPageCollectionEditor(newDocumentWith(1));
      final stranger = newDocumentWith(1).pdfPageList.pages.first;
      expect(
        () => editor.insert(0, stranger),
        throwsA(isA<PdfPageEditException>()),
      );
    });

    test('reorder exige permutação completa', () {
      final editor = PdfPageCollectionEditor(newDocumentWith(3));
      expect(
        () => editor.reorder(<int>[0, 1]),
        throwsA(isA<PdfPageEditException>()),
      );
      expect(
        () => editor.reorder(<int>[0, 1, 1]),
        throwsA(isA<PdfPageEditException>()),
      );
      expect(() => editor.reorder(<int>[0, 1, 5]), throwsRangeError);
      expect(() => editor.reorder(<int>[2, 1, 0]), returnsNormally);
    });
  });

  group('ordem final — documento novo', () {
    test('remove tira a página certa e a saída recarrega', () async {
      final document = newDocumentWith(4);
      final expected = <PdfPage>[
        document.pdfPageList.pages[0],
        document.pdfPageList.pages[2],
        document.pdfPageList.pages[3],
      ];
      final editor = PdfPageCollectionEditor(document);
      final removed = editor.remove(1);

      expect(editor.pages, expected);
      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 3);
      expect(referencesTo(out, <int>{removed.objser}), isEmpty);
      expect(danglingReferences(out), isEmpty);
    });

    test('removeRange respeita o fim exclusivo', () async {
      final document = newDocumentWith(5);
      final editor = PdfPageCollectionEditor(document);
      final removed = editor.removeRange(1, 3);

      expect(removed, hasLength(2));
      expect(editor.length, 3);
      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 3);
      expect(
        referencesTo(out, <int>{for (final page in removed) page.objser}),
        isEmpty,
      );
    });

    test('insert move a página que o construtor já registrou', () async {
      final document = newDocumentWith(2);
      final editor = PdfPageCollectionEditor(document);

      // O construtor registra a página no fim da lista sozinho.
      final page = PdfPage(document, pageFormat: PdfPageFormat.a4);
      expect(editor.length, 3);
      expect(editor.indexOf(page), 2);

      editor.insert(0, page);
      expect(editor.length, 3, reason: 'inserir de novo duplicaria em /Kids');
      expect(editor.indexOf(page), 0);

      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 3);
      expect(out.pageRefs.map((e) => e.obj).toSet(), hasLength(3));
    });

    test('uma página removida pode voltar por insert', () async {
      final document = newDocumentWith(3);
      final editor = PdfPageCollectionEditor(document);
      final removed = editor.remove(1);
      expect(editor.length, 2);

      editor.insert(0, removed);
      expect(editor.length, 3);
      expect(editor.indexOf(removed), 0);

      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 3);
      expect(danglingReferences(out), isEmpty);
      expect(decodedPageContent(out, 0), isNotNull);
    });

    test('move e reorder deixam a ordem pedida', () async {
      final document = newDocumentWith(4);
      final editor = PdfPageCollectionEditor(document);
      final original = List<PdfPage>.of(editor.pages);

      editor.move(0, 3);
      expect(editor.pages, <PdfPage>[
        original[1],
        original[2],
        original[3],
        original[0],
      ]);

      editor.reorder(<int>[3, 2, 1, 0]);
      expect(editor.pages, <PdfPage>[
        original[0],
        original[3],
        original[2],
        original[1],
      ]);

      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 4);
      expect(danglingReferences(out), isEmpty);
    });
  });

  group('ordem final — documento carregado', () {
    test('paginador.pdf perde exatamente as páginas removidas', () async {
      final document =
          PdfDocument.load(PdfDocumentParser(asset('paginador.pdf'), allowRepair: true));
      expect(document.pdfPageList.pages, hasLength(94));

      final editor = PdfPageCollectionEditor(document);
      final removed = <int>{for (var i = 0; i < 3; i++) editor[i].objser};
      editor.removeRange(0, 3);

      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 91);
      expect(referencesTo(out, removed), isEmpty);
      expect(danglingReferences(out), isEmpty);
    });

    test('termo.pdf reordenado continua com as duas páginas', () async {
      final document = PdfDocument.load(
          PdfDocumentParser(asset('termo.pdf'), allowRepair: true));
      final editor = PdfPageCollectionEditor(document);
      editor.reorder(<int>[1, 0]);

      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 2);
    });

    test('remover tudo deixa um documento sem páginas que ainda abre',
        () async {
      final document = PdfDocument.load(
          PdfDocumentParser(asset('termo.pdf'), allowRepair: true));
      final editor = PdfPageCollectionEditor(document);
      final removed = <int>{editor[0].objser, editor[1].objser};
      editor.removeRange(0, 2);

      final out = reopen(await document.save(useIsolate: false));
      // `pageCount` cai na varredura de reparo quando a árvore fica vazia e
      // reencontra os objetos antigos nos bytes anteriores; o que interessa é
      // a árvore `/Pages` do incremental update.
      final pages = out.resolve(out.rootDict!.values['/Pages']);
      expect(pages, isA<PdfDictToken>());
      expect(out.resolve((pages as PdfDictToken).values['/Count']), 0);
      final kids = out.resolve(pages.values['/Kids']);
      expect(kids is PdfArrayToken ? kids.values : const <dynamic>[], isEmpty);
      expect(referencesTo(out, removed), isEmpty);
    });
  });

  group('nenhuma referência para página removida', () {
    test('paginador.pdf: destino nomeado e bookmark somem juntos', () async {
      final document = PdfDocument.load(
          PdfDocumentParser(asset('paginador.pdf'), allowRepair: true));
      final editor = PdfPageCollectionEditor(document);
      final removed = <int>{editor[0].objser};
      editor.remove(0);

      final out = reopen(await document.save(useIsolate: false));
      expect(referencesTo(out, removed), isEmpty);
      expect(danglingReferences(out), isEmpty);

      // O primeiro bookmark saltava para a primeira página.
      expect(outlineTitles(out), isNot(contains('Ementa e Acórdão')));
      expect(outlineTitles(out), hasLength(5));
      expect(namedDestinations(out), isNot(contains('6044075')));
      expect(namedDestinations(out), hasLength(5));
      expect(editor.warnings, isNotEmpty);
    });

    test('todas as estruturas cobertas soltam a página removida', () async {
      final document = PdfDocument.load(
          PdfDocumentParser(await buildRichPdf(), allowRepair: true));
      final editor = PdfPageCollectionEditor(document);

      final target = editor[2];
      final removed = <int>{target.objser};
      final widgetIds = acroFormFieldIds(
          PdfDocumentParser(await buildRichPdf(), allowRepair: true));
      expect(widgetIds, hasLength(1));

      editor.remove(2);
      final out = reopen(await document.save(useIsolate: false));

      expect(out.pageCount, 4);
      expect(referencesTo(out, removed), isEmpty,
          reason: 'nada pode continuar apontando para a página removida');
      expect(danglingReferences(out), isEmpty);

      // destino nomeado
      expect(namedDestinations(out), isEmpty);
      // bookmark por âncora sumiu, bookmark por página ficou
      expect(outlineTitles(out), <String>['para a quarta']);
      // link interno da página 0 saiu de /Annots
      expect(annotationCount(out), 0);
      // /OpenAction apagado
      expect(out.rootDict!.values['/OpenAction'], isNull);
      // widget da página removida saiu de /AcroForm /Fields
      expect(acroFormFieldIds(out), isEmpty);
      // rótulos recalculados para quatro páginas
      expect(pageLabelRanges(out).keys, isNotEmpty);
    });

    test('a política retarget aponta para a página vizinha', () async {
      final document = PdfDocument.load(
          PdfDocumentParser(asset('paginador.pdf'), allowRepair: true));
      final editor = PdfPageCollectionEditor(
        document,
        brokenReferencePolicy: PdfBrokenReferencePolicy.retarget,
      );
      final removed = <int>{editor[0].objser};
      final neighbour = editor[1].objser;
      editor.remove(0);

      final out = reopen(await document.save(useIsolate: false));
      expect(referencesTo(out, removed), isEmpty);
      // O bookmark continua na árvore, agora apontando para a vizinha.
      expect(outlineTitles(out), hasLength(6));
      expect(outlineTitles(out), contains('Ementa e Acórdão'));
      expect(namedDestinations(out), hasLength(6));

      final names = parseNamedDestination(out, '6044075');
      expect(names, neighbour);
    });

    test('a política throwError recusa antes de mudar qualquer coisa',
        () async {
      final document = PdfDocument.load(
          PdfDocumentParser(asset('paginador.pdf'), allowRepair: true));
      final editor = PdfPageCollectionEditor(
        document,
        brokenReferencePolicy: PdfBrokenReferencePolicy.throwError,
      );

      expect(
        () => editor.remove(0),
        throwsA(isA<PdfPageEditException>()),
      );
      expect(editor.length, 94, reason: 'a lista não pode ter sido tocada');

      // Uma página que ninguém referencia continua removível.
      expect(() => editor.remove(50), returnsNormally);
      expect(editor.length, 93);

      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 93);
      expect(danglingReferences(out), isEmpty);
    });
  });

  group('reordenar preserva o conteúdo', () {
    test('documento novo: cada página leva o próprio conteúdo', () async {
      final document = newDocumentWith(4);
      final before = reopen(await document.save(useIsolate: false));
      final expected = <Uint8List?>[
        for (var i = 0; i < 4; i++) decodedPageContent(before, i),
      ];
      expect(expected.whereType<Uint8List>(), hasLength(4));
      expect(expected[0], isNot(expected[1]));

      final editor = PdfPageCollectionEditor(document);
      editor.reorder(<int>[3, 1, 2, 0]);

      final after = reopen(await document.save(useIsolate: false));
      expect(decodedPageContent(after, 0), expected[3]);
      expect(decodedPageContent(after, 1), expected[1]);
      expect(decodedPageContent(after, 2), expected[2]);
      expect(decodedPageContent(after, 3), expected[0]);
    });

    test('documento carregado: paginador.pdf embaralhado', () async {
      final source = PdfDocumentParser(asset('paginador.pdf'), allowRepair: true);
      final expected = <Uint8List?>[
        for (var i = 0; i < 6; i++) decodedPageContent(source, i),
      ];

      final document = PdfDocument.load(
          PdfDocumentParser(asset('paginador.pdf'), allowRepair: true));
      final editor = PdfPageCollectionEditor(document);
      final order = <int>[
        5, 4, 3, 2, 1, 0,
        for (var i = 6; i < editor.length; i++) i,
      ];
      editor.reorder(order);

      final after = reopen(await document.save(useIsolate: false));
      for (var i = 0; i < 6; i++) {
        expect(decodedPageContent(after, i), expected[5 - i],
            reason: 'a página $i deveria trazer o conteúdo da ${5 - i}');
      }
    });

    test('mover não gera aviso nem quebra referência', () async {
      final document = PdfDocument.load(
          PdfDocumentParser(asset('paginador.pdf'), allowRepair: true));
      final editor = PdfPageCollectionEditor(document);
      editor.move(0, 93);

      expect(editor.warnings, isEmpty);
      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 94);
      expect(outlineTitles(out), hasLength(6));
      expect(danglingReferences(out), isEmpty);
    });
  });

  group('duplicate', () {
    test('documento novo: duas páginas com o mesmo conteúdo', () async {
      final document = newDocumentWith(2);
      final editor = PdfPageCollectionEditor(document);
      final copy = editor.duplicate(0);

      expect(editor.length, 3);
      expect(editor.indexOf(copy), 1);

      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 3);
      expect(decodedPageContent(out, 0), isNotNull);
      expect(decodedPageContent(out, 1), decodedPageContent(out, 0));
      expect(decodedPageContent(out, 2), isNot(decodedPageContent(out, 0)));
      expect(danglingReferences(out), isEmpty);
    });

    test('documento carregado: a cópia entra no lugar pedido', () async {
      final document = PdfDocument.load(
          PdfDocumentParser(asset('termo.pdf'), allowRepair: true));
      final editor = PdfPageCollectionEditor(document);
      editor.duplicate(1, at: 0);

      expect(editor.length, 3);
      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 3);
      expect(decodedPageContent(out, 0), decodedPageContent(out, 2));
      expect(decodedPageContent(out, 0), isNot(decodedPageContent(out, 1)));
    });

    test('a cópia não leva as anotações, e isso vira aviso', () async {
      final document = PdfDocument.load(
          PdfDocumentParser(asset('termo.pdf'), allowRepair: true));
      final editor = PdfPageCollectionEditor(document);
      final beforeCount = annotationsOf(
              PdfDocumentParser(asset('termo.pdf'), allowRepair: true), 1)
          .length;
      expect(beforeCount, greaterThan(0));

      editor.duplicate(1);
      expect(editor.warnings, isNotEmpty);

      final out = reopen(await document.save(useIsolate: false));
      expect(annotationsOf(out, 2), isEmpty);
      expect(annotationsOf(out, 1), hasLength(beforeCount));
    });

    test('remover o original não mata o conteúdo da cópia', () async {
      final document = newDocumentWith(2);
      final editor = PdfPageCollectionEditor(document);
      editor.duplicate(0);
      editor.remove(0);

      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 2);
      expect(decodedPageContent(out, 0), isNotNull);
      expect(danglingReferences(out), isEmpty);
    });
  });

  group('/PageLabels', () {
    test('remover no meio desloca as faixas', () async {
      final document = PdfDocument.load(
          PdfDocumentParser(await buildRichPdf(), allowRepair: true));
      final before = pageLabelRanges(
          PdfDocumentParser(await buildRichPdf(), allowRepair: true));
      expect(before.keys, <int>[0, 2]);

      final editor = PdfPageCollectionEditor(document);
      editor.remove(0);

      final out = reopen(await document.save(useIsolate: false));
      final after = pageLabelRanges(out);
      // A faixa romana perdeu a primeira página; a arábica subiu para o índice
      // 1 e continua começando no mesmo número.
      expect(after.keys.first, 0);
      expect(after.keys, hasLength(2));
      expect(after.keys.last, 1);
      expect(editor.warnings.any((e) => e.contains('/PageLabels')), isTrue);
    });

    test('reordenar reparte as faixas página a página', () async {
      final document = PdfDocument.load(
          PdfDocumentParser(await buildRichPdf(), allowRepair: true));
      final editor = PdfPageCollectionEditor(document);
      editor.reorder(<int>[4, 3, 2, 1, 0]);

      final out = reopen(await document.save(useIsolate: false));
      final ranges = pageLabelRanges(out);
      // Nenhuma sequência antiga sobreviveu inteira: cada página abre a
      // própria faixa.
      expect(ranges, hasLength(5));
      expect(ranges.keys, <int>[0, 1, 2, 3, 4]);
      expect(danglingReferences(out), isEmpty);
    });
  });

  group('avisos', () {
    test('a lista relata o que foi perdido e pode ser esvaziada', () async {
      final document = PdfDocument.load(
          PdfDocumentParser(await buildRichPdf(), allowRepair: true));
      final editor = PdfPageCollectionEditor(document);
      expect(editor.warnings, isEmpty);

      editor.remove(2);
      expect(editor.warnings, isNotEmpty);
      expect(
        editor.warnings.any((e) => e.contains('destino nomeado "alvo"')),
        isTrue,
      );
      expect(editor.warnings.any((e) => e.contains('bookmark')), isTrue);
      expect(editor.warnings.any((e) => e.contains('/OpenAction')), isTrue);

      editor.clearWarnings();
      expect(editor.warnings, isEmpty);
    });

    test('a lista é imutável para quem lê', () {
      final editor = PdfPageCollectionEditor(newDocumentWith(1));
      expect(() => editor.warnings.add('x'), throwsUnsupportedError);
    });
  });

  group('insertImported', () {
    test('traz uma página de outro arquivo para a posição pedida', () async {
      final document = newDocumentWith(2);
      final editor = PdfPageCollectionEditor(document);
      final source = PdfDocumentParser(asset('termo.pdf'), allowRepair: true);

      final imported = editor.insertImported(0, source, 0);
      expect(editor.length, 3);
      expect(editor.indexOf(imported), 0);

      final out = reopen(await document.save(useIsolate: false));
      expect(out.pageCount, 3);
      expect(danglingReferences(out), isEmpty);
    });
  });
}

/// Número do objeto de página para onde o destino nomeado [name] aponta.
int? parseNamedDestination(PdfDocumentParser parser, String name) {
  final root = parser.rootDict;
  if (root == null) return null;
  final namesDict = parser.resolve(root.values['/Names']);
  if (namesDict is! PdfDictToken) return null;

  int? found;
  void walk(dynamic node, int depth) {
    if (depth > 32 || found != null) return;
    final dict = parser.resolve(node);
    if (dict is! PdfDictToken) return;
    final entries = parser.resolve(dict.values['/Names']);
    if (entries is PdfArrayToken) {
      for (var i = 0; i + 1 < entries.values.length; i += 2) {
        final key = parser.resolve(entries.values[i]);
        if (key is! PdfStringToken) continue;
        if (String.fromCharCodes(key.bytes) != name) continue;
        var dest = parser.resolve(entries.values[i + 1]);
        if (dest is PdfDictToken) dest = parser.resolve(dest.values['/D']);
        if (dest is PdfArrayToken && dest.values.isNotEmpty) {
          found = PdfParserObjects.asRef(dest.values.first)?.obj;
        }
        return;
      }
    }
    final kids = parser.resolve(dict.values['/Kids']);
    if (kids is PdfArrayToken) {
      for (final kid in kids.values) {
        walk(kid, depth + 1);
      }
    }
  }

  walk(namesDict.values['/Dests'], 0);
  return found;
}
