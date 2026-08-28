import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:pdf_plus/widgets.dart' as pw;
import 'package:test/test.dart';

import '../merging/merge_helpers.dart';

/// Referências que não resolvem, a partir do catálogo.
///
/// Mesma ideia do percorredor de `merge_integrity_test.dart`: um arquivo que
/// abre e perde metade do documento é o modo de falha mais traiçoeiro de uma
/// edição incremental. Os PDFs do corpus já trazem referências penduradas de
/// origem, então os testes comparam o conjunto antes e depois da edição.
Set<String> danglingReferences(PdfDocumentParser parser) {
  final problems = <String>{};
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
  if (root == null) return <String>{'sem catálogo'};
  walk(root, '/Root', 0);
  return problems;
}

/// O conteúdo decodificado de todas as páginas, para provar que a edição de
/// anotações não encostou no desenho.
List<Uint8List?> allPageContents(PdfDocumentParser parser) => <Uint8List?>[
      for (var i = 0; i < parser.pageCount; i++) decodedPageContent(parser, i),
    ];

/// PDF de uma página, base das fixtures montadas à mão.
Future<Uint8List> buildBasePdf() async {
  final document = pw.Document();
  document.addPage(
    pw.Page(build: (context) => pw.Center(child: pw.Text('base'))),
  );
  return document.save();
}

/// PDF com um widget de assinatura que já tem `/AP /N`.
Future<Uint8List> buildWidgetWithAppearance() async {
  final document = PdfDocument.parseFromBytes(
    await buildBasePdf(),
    allowRepair: true,
  );
  final page = document.pdfPageList.pages.first;
  final widget = PdfAnnotSign(
    rect: const PdfRect(50, 400, 120, 40),
    fieldName: 'visto',
  );
  final canvas = widget.appearance(
    document,
    PdfAnnotAppearance.normal,
    boundingBox: const PdfRect(0, 0, 120, 40),
  );
  canvas.setFillColor(PdfColors.red);
  canvas.drawRect(0, 0, 120, 40);
  canvas.fillPath();
  PdfAnnot(page, widget);
  return document.save();
}

/// Os números de um array de qualquer tamanho.
///
/// `PdfParserObjects.asNumArray` só serve para caixas: exige quatro valores.
List<double>? numbersOf(PdfDocumentParser parser, dynamic value) {
  final array = parser.resolve(value);
  if (array is! PdfArrayToken) return null;
  final numbers = <double>[];
  for (final item in array.values) {
    final resolved = parser.resolve(item);
    if (resolved is int) {
      numbers.add(resolved.toDouble());
    } else if (resolved is double) {
      numbers.add(resolved);
    } else {
      return null;
    }
  }
  return numbers;
}

/// Os subtipos das anotações de uma página do arquivo já regravado.
List<String?> subtypesOf(PdfDocumentParser parser, int pageIndex) => <String?>[
      for (final annot in annotationsOf(parser, pageIndex))
        PdfParserObjects.asName(annot.values['/Subtype']),
    ];

void main() {
  group('PdfAnnotationCollection — leitura', () {
    test('lista as três anotações de termo.pdf com subtipo, rect e flags', () {
      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      final annotations = PdfAnnotationCollection.onPage(document, 1);

      expect(annotations.length, 3);
      expect(
        annotations.annotations.map((e) => e.subtype),
        everyElement('/Link'),
      );
      for (final annotation in annotations.annotations) {
        expect(annotation.rect, isNotNull);
        expect(annotation.rect!.isNotEmpty, isTrue);
        expect(annotation.flags, 4);
        expect(annotation.flagSet, <PdfAnnotFlags>{PdfAnnotFlags.print});
        // termo.pdf não traz nem `/Contents` nem `/NM` nos links.
        expect(annotation.contents, isNull);
        expect(annotation.name, isNull);
        expect(annotation.color, isNull);
        expect(annotation.isWidget, isFalse);
      }
      expect(annotations.warnings, isEmpty);
    });

    test('a primeira página de termo.pdf não tem anotação', () {
      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      expect(PdfAnnotationCollection.onPage(document, 0).length, 0);
    });

    test('whereSubtype filtra e byName acha pelo /NM', () {
      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      final annotations = PdfAnnotationCollection.onPage(document, 1);

      expect(annotations.whereSubtype('/Link').length, 3);
      expect(annotations.whereSubtype('/Widget'), isEmpty);
      expect(annotations.byName('inexistente'), isNull);

      annotations[1].name = 'link-do-meio';
      expect(annotations.byName('link-do-meio'), isNotNull);
      expect(
        identical(annotations.byName('link-do-meio'), annotations[1]),
        isTrue,
      );
    });

    test('rectTopLeft converte pelo PdfCoordinateTransformer', () {
      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      final annotations = PdfAnnotationCollection.onPage(document, 1);
      final view = annotations[0];

      final box = view.rect!;
      final topLeft = view.rectTopLeft!;
      expect(topLeft.width, closeTo(box.width, 1e-9));
      expect(topLeft.height, closeTo(box.height, 1e-9));

      // Ida e volta pelo mesmo transformador precisa devolver a caixa original.
      view.rectTopLeft = topLeft;
      expect(view.rect!.left, closeTo(box.left, 1e-9));
      expect(view.rect!.bottom, closeTo(box.bottom, 1e-9));
      expect(view.rect!.right, closeTo(box.right, 1e-9));
      expect(view.rect!.top, closeTo(box.top, 1e-9));
    });
  });

  group('PdfAnnotationCollection — alteração', () {
    test('grava /Rect, /Contents, /NM, /F e /C e a saída recarrega', () async {
      final original = reopen(asset('termo.pdf'));
      final before = allPageContents(original);

      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      final annotations = PdfAnnotationCollection.onPage(document, 1);
      final view = annotations[0];
      view
        ..rect = const PdfBox(10, 20, 110, 60)
        ..contents = 'Revisar antes de assinar'
        ..name = 'anotacao-um'
        ..flags = 6
        ..color = const PdfColor(1, 0, 0);

      final saved = reopen(await document.save());
      final annots = annotationsOf(saved, 1);
      expect(annots.length, 3);

      final edited = annots.first;
      expect(
        PdfParserObjects.asNumArray(edited.values['/Rect']),
        <double>[10, 20, 110, 60],
      );
      final contents = saved.resolve(edited.values['/Contents']);
      expect(
        String.fromCharCodes((contents as PdfStringToken).bytes),
        'Revisar antes de assinar',
      );
      final name = saved.resolve(edited.values['/NM']);
      expect(String.fromCharCodes((name as PdfStringToken).bytes),
          'anotacao-um');
      expect(PdfParserObjects.asInt(edited.values['/F']), 6);
      expect(numbersOf(saved, edited.values['/C']), <double>[1, 0, 0]);
      // A leitura de volta devolve a mesma cor.
      expect(
        PdfAnnotationCollection.onPage(
          PdfDocument.parseFromBytes(await document.save(), allowRepair: true),
          1,
        )[0].color,
        const PdfColor(1, 0, 0),
      );
      // O que não foi tocado continua lá.
      expect(edited.values['/A'], isNotNull);
      expect(edited.values['/BS'], isNotNull);

      // Nenhuma página teve o desenho alterado.
      expect(allPageContents(saved), before);
    });

    test('flagSet e setFlag descrevem o mesmo /F', () async {
      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      final view = PdfAnnotationCollection.onPage(document, 1)[0];

      view.flagSet = <PdfAnnotFlags>{
        PdfAnnotFlags.print,
        PdfAnnotFlags.readOnly,
      };
      expect(view.flags, 4 | 64);

      view.setFlag(PdfAnnotFlags.hidden, true);
      expect(view.isHidden, isTrue);
      view.setFlag(PdfAnnotFlags.hidden, false);
      expect(view.isHidden, isFalse);
      expect(view.flags, 4 | 64);
    });

    test('alterar duas vezes materializa um único objeto substituto', () async {
      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      final view = PdfAnnotationCollection.onPage(document, 1)[0];
      final number = view.reference!.ser;

      view.contents = 'primeiro';
      view.contents = 'segundo';
      view.name = 'terceiro';

      expect(
        document.objects.where((object) => object.objser == number).length,
        1,
      );

      final saved = reopen(await document.save());
      final contents =
          saved.resolve(annotationsOf(saved, 1).first.values['/Contents']);
      expect(
        String.fromCharCodes((contents as PdfStringToken).bytes),
        'segundo',
      );
    });

    test('remover a cor apaga /C', () async {
      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      final view = PdfAnnotationCollection.onPage(document, 1)[0];
      view.color = PdfColors.blue;
      view.color = null;

      final saved = reopen(await document.save());
      expect(annotationsOf(saved, 1).first.values['/C'], isNull);
    });

    test('salvar duas vezes não duplica a anotação alterada', () async {
      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      PdfAnnotationCollection.onPage(document, 1)[0].contents = 'idempotente';

      await document.save();
      final saved = reopen(await document.save());

      expect(annotationsOf(saved, 1).length, 3);
      expect(subtypesOf(saved, 1), <String>['/Link', '/Link', '/Link']);
    });
  });

  group('PdfAnnotationCollection — remoção', () {
    test('remove uma anotação e preserva o conteúdo das páginas', () async {
      final original = reopen(asset('termo.pdf'));
      final before = allPageContents(original);

      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      final annotations = PdfAnnotationCollection.onPage(document, 1);
      final removed = annotations[1].reference!;
      expect(annotations.remove(annotations[1]), isTrue);
      expect(annotations.length, 2);

      final saved = reopen(await document.save());
      expect(annotationsOf(saved, 1).length, 2);
      expect(allPageContents(saved), before);

      // O objeto da anotação continua no arquivo antigo, mas ninguém mais
      // aponta para ele a partir da página.
      final page = saved.pageDictAt(1)!;
      final annots = saved.resolve(page.values['/Annots']) as PdfArrayToken;
      expect(
        annots.values
            .map((e) => PdfParserObjects.asRef(e)?.obj)
            .contains(removed.ser),
        isFalse,
      );
    });

    test('remover todas deixa /Annots vazio e o documento legível', () async {
      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      final annotations = PdfAnnotationCollection.onPage(document, 1);
      for (final view in List.of(annotations.annotations)) {
        expect(annotations.remove(view), isTrue);
      }

      final saved = reopen(await document.save());
      expect(saved.pageCount, 2);
      expect(annotationsOf(saved, 1), isEmpty);
      expect(annotationCount(saved), 0);
    });

    test('remover não deixa referência pendurada nova', () async {
      final original = reopen(asset('termo.pdf'));
      final before = danglingReferences(original);

      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      final annotations = PdfAnnotationCollection.onPage(document, 1);
      annotations[0].contents = 'alterada';
      annotations.remove(annotations[2]);

      final saved = reopen(await document.save());
      expect(danglingReferences(saved).difference(before), isEmpty);
    });

    test('remover um widget também o tira de /AcroForm /Fields', () async {
      final document = PdfDocument.parseFromBytes(
        await buildWidgetWithAppearance(),
        allowRepair: true,
      );
      final annotations = PdfAnnotationCollection.onPage(document, 0);
      final widget = annotations.whereSubtype('/Widget').single;
      expect(widget.isWidget, isTrue);

      expect(annotations.remove(widget), isTrue);
      expect(annotations.acroForm.fields!.values, isEmpty);

      final saved = reopen(await document.save());
      expect(annotationsOf(saved, 0), isEmpty);
      expect(fieldNames(saved), isEmpty);
    });
  });

  group('PdfAnnotationCollection — flatten', () {
    test('desenha o /AP /N na página e remove a anotação', () async {
      final source = await buildWidgetWithAppearance();
      final before = allPageContents(reopen(source));

      final document = PdfDocument.parseFromBytes(source, allowRepair: true);
      final annotations = PdfAnnotationCollection.onPage(document, 0);
      final widget = annotations.whereSubtype('/Widget').single;
      final appearance = widget.normalAppearance!;
      expect(appearance.stateName, isNull);
      expect(appearance.bbox.width, 120);

      expect(annotations.flatten(widget), isTrue);
      expect(annotations.warnings, isEmpty);

      final saved = reopen(await document.save());
      expect(annotationsOf(saved, 0), isEmpty);

      final content = String.fromCharCodes(decodedPageContent(saved, 0)!);
      // O desenho ficou depois do conteúdo original, que continua intacto.
      expect(content, contains('/Xap${appearance.id.number}_0 Do'));
      expect(
        content.startsWith(String.fromCharCodes(before.first!)),
        isFalse,
        reason: 'o editor de conteúdo envolve o original em q ... Q',
      );
      expect(content, contains(String.fromCharCodes(before.first!).trim()));
    });

    test('recusa e avisa quando a anotação não tem aparência', () async {
      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      final annotations = PdfAnnotationCollection.onPage(document, 1);

      expect(annotations.flatten(annotations[0]), isFalse);
      expect(annotations.length, 3);
      expect(annotations.warnings.single, contains('sem /AP'));

      final saved = reopen(await document.save());
      expect(annotationsOf(saved, 1).length, 3);
    });

    test('flattenAll mantém o que não tem aparência', () async {
      final document =
          PdfDocument.parseFromBytes(asset('termo.pdf'), allowRepair: true);
      final annotations = PdfAnnotationCollection.onPage(document, 1);

      expect(annotations.flattenAll(), 0);
      expect(annotations.length, 3);
      expect(annotations.warnings.length, 3);
    });

    test('achatar não deixa referência pendurada nova', () async {
      final source = await buildWidgetWithAppearance();
      final before = danglingReferences(reopen(source));

      final document = PdfDocument.parseFromBytes(source, allowRepair: true);
      final annotations = PdfAnnotationCollection.onPage(document, 0);
      annotations.flatten(annotations.whereSubtype('/Widget').single);

      final saved = reopen(await document.save());
      expect(danglingReferences(saved).difference(before), isEmpty);
    });
  });
}
