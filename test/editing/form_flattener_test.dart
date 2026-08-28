import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/format/array.dart';
import 'package:pdf_plus/src/pdf/format/base.dart';
import 'package:pdf_plus/src/pdf/format/bool.dart';
import 'package:pdf_plus/src/pdf/format/dict.dart';
import 'package:pdf_plus/src/pdf/format/num.dart';
import 'package:pdf_plus/src/pdf/format/string.dart';
import 'package:pdf_plus/src/pdf/obj/graphic_stream.dart';
import 'package:pdf_plus/src/pdf/obj/object.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:pdf_plus/widgets.dart' as pw;
import 'package:test/test.dart';

import '../merging/merge_helpers.dart';

/// Referências que não resolvem, a partir do catálogo.
///
/// Mesma ideia do percorredor de `merge_integrity_test.dart`. Os arquivos do
/// corpus já trazem referências penduradas de origem — `sample3.pdf` tem uma
/// em `/Outlines` —, então o que os testes cobram é que o achatamento não
/// acrescente nenhuma.
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

/// Quantos widgets sobraram em `/Annots` no documento inteiro.
int widgetCount(PdfDocumentParser parser) {
  var total = 0;
  for (var i = 0; i < parser.pageCount; i++) {
    for (final annot in annotationsOf(parser, i)) {
      if (PdfParserObjects.asName(annot.values['/Subtype']) == '/Widget') {
        total++;
      }
    }
  }
  return total;
}

/// O conteúdo de uma página como texto, para procurar o operador `Do`.
String pageContentText(PdfDocumentParser parser, int pageIndex) {
  final bytes = decodedPageContent(parser, pageIndex);
  return bytes == null ? '' : String.fromCharCodes(bytes);
}

/// PDF de uma página, base de todas as fixtures montadas à mão.
Future<Uint8List> buildBasePdf() async {
  final document = pw.Document();
  document.addPage(
    pw.Page(build: (context) => pw.Center(child: pw.Text('base'))),
  );
  return document.save();
}

/// Desenha um retângulo cheio na aparência.
void paintBox(PdfGraphics canvas, double width, double height, PdfColor color) {
  canvas.setFillColor(color);
  canvas.drawRect(0, 0, width, height);
  canvas.fillPath();
}

/// PDF com dois campos: um com `/AP /N` e outro sem nenhuma aparência.
Future<Uint8List> buildTwoFieldForm() async {
  final document =
      PdfDocument.parseFromBytes(await buildBasePdf(), allowRepair: true);
  final page = document.pdfPageList.pages.first;

  final withAppearance = PdfAnnotSign(
    rect: const PdfRect(100, 500, 200, 60),
    fieldName: 'com_aparencia',
  );
  paintBox(
    withAppearance.appearance(
      document,
      PdfAnnotAppearance.normal,
      boundingBox: const PdfRect(0, 0, 200, 60),
    ),
    200,
    60,
    const PdfColor(1, 0, 0),
  );
  PdfAnnot(page, withAppearance);

  PdfAnnot(
    page,
    PdfAnnotSign(
      rect: const PdfRect(100, 300, 200, 60),
      fieldName: 'sem_aparencia',
    ),
  );

  return document.save();
}

/// PDF com dois campos, ambos com `/AP /N`.
Future<Uint8List> buildTwoAppearanceForm() async {
  final document =
      PdfDocument.parseFromBytes(await buildBasePdf(), allowRepair: true);
  final page = document.pdfPageList.pages.first;

  for (final entry in <MapEntry<String, double>>[
    const MapEntry<String, double>('primeiro', 500),
    const MapEntry<String, double>('segundo', 300),
  ]) {
    final widget = PdfAnnotSign(
      rect: PdfRect(100, entry.value, 200, 60),
      fieldName: entry.key,
    );
    paintBox(
      widget.appearance(
        document,
        PdfAnnotAppearance.normal,
        boundingBox: const PdfRect(0, 0, 200, 60),
      ),
      200,
      60,
      const PdfColor(1, 0, 0),
    );
    PdfAnnot(page, widget);
  }

  return document.save();
}

/// PDF com um campo cujo `/Rect` é o dobro da `/BBox` da aparência.
Future<Uint8List> buildScaledForm() async {
  final document =
      PdfDocument.parseFromBytes(await buildBasePdf(), allowRepair: true);
  final widget = PdfAnnotSign(
    rect: const PdfRect(50, 400, 240, 80),
    fieldName: 'escalado',
  );
  paintBox(
    widget.appearance(
      document,
      PdfAnnotAppearance.normal,
      boundingBox: const PdfRect(0, 0, 120, 40),
    ),
    120,
    40,
    const PdfColor(0, 0, 1),
  );
  PdfAnnot(document.pdfPageList.pages.first, widget);
  return document.save();
}

/// PDF com `/AP /N` em dois estados; [selected] liga o `/AS`.
Future<Uint8List> buildStateForm({required bool selected}) async {
  final document =
      PdfDocument.parseFromBytes(await buildBasePdf(), allowRepair: true);
  final widget = PdfAnnotSign(
    rect: const PdfRect(50, 400, 100, 50),
    fieldName: 'marcado',
  );
  paintBox(
    widget.appearance(
      document,
      PdfAnnotAppearance.normal,
      name: '/Off',
      boundingBox: const PdfRect(0, 0, 100, 50),
    ),
    100,
    50,
    const PdfColor(1, 1, 1),
  );
  paintBox(
    widget.appearance(
      document,
      PdfAnnotAppearance.normal,
      name: '/Yes',
      selected: selected,
      boundingBox: const PdfRect(0, 0, 100, 50),
    ),
    100,
    50,
    const PdfColor(0, 1, 0),
  );
  PdfAnnot(document.pdfPageList.pages.first, widget);
  return document.save();
}

/// PDF com um campo oculto (`/F` com o bit `hidden`) que tem aparência.
Future<Uint8List> buildHiddenForm() async {
  final document =
      PdfDocument.parseFromBytes(await buildBasePdf(), allowRepair: true);
  final widget = PdfAnnotSign(
    rect: const PdfRect(50, 400, 120, 40),
    fieldName: 'oculto',
    flags: <PdfAnnotFlags>{PdfAnnotFlags.hidden},
  );
  paintBox(
    widget.appearance(
      document,
      PdfAnnotAppearance.normal,
      boundingBox: const PdfRect(0, 0, 120, 40),
    ),
    120,
    40,
    const PdfColor(0, 0, 0),
  );
  PdfAnnot(document.pdfPageList.pages.first, widget);
  return document.save();
}

/// PDF com hierarquia `/Kids`: o campo tem nome e o filho é só o widget.
///
/// A biblioteca ainda não cria formulário hierárquico, então a árvore é
/// montada com os objetos crus sobre um documento já carregado.
Future<Uint8List> buildKidsForm() async {
  final document =
      PdfDocument.parseFromBytes(await buildBasePdf(), allowRepair: true);
  final page = document.pdfPageList.pages.first;

  final appearance = PdfGraphicXObject(document, '/Form');
  appearance.params['/BBox'] = PdfArray.fromNum(<double>[0, 0, 120, 40]);
  paintBox(
    PdfGraphics(appearance, appearance.buf),
    120,
    40,
    const PdfColor(0, 0, 1),
  );
  appearance.altered = true;

  final widget = PdfObject<PdfDict>(
    document,
    params: PdfDict.values(<String, PdfDataType>{
      '/Type': const PdfName('/Annot'),
      '/Subtype': const PdfName('/Widget'),
      '/Rect': PdfArray.fromNum(<double>[60, 200, 180, 240]),
      '/F': const PdfNum(4),
      '/P': page.ref(),
      '/AP': PdfDict.values(<String, PdfDataType>{'/N': appearance.ref()}),
    }),
  );

  final field = PdfObject<PdfDict>(
    document,
    params: PdfDict.values(<String, PdfDataType>{
      '/FT': const PdfName('/Tx'),
      '/T': PdfString.fromString('grupo'),
      '/Kids': PdfArray<PdfDataType>(<PdfDataType>[widget.ref()]),
    }),
  );
  widget.params['/Parent'] = field.ref();

  page.params['/Annots'] = PdfArray<PdfDataType>(<PdfDataType>[widget.ref()]);
  document.catalog.params['/AcroForm'] = PdfDict.values(<String, PdfDataType>{
    '/Fields': PdfArray<PdfDataType>(<PdfDataType>[field.ref()]),
    '/NeedAppearances': const PdfBool(true),
  });

  return document.save();
}

void main() {
  group('PdfFormFlattener — sample3.pdf, 63 campos', () {
    late Uint8List source;
    late PdfDocument document;
    late PdfFormFlattenResult result;

    setUpAll(() {
      source = asset('sample3.pdf');
      document = PdfDocument.parseFromBytes(source, allowRepair: true);
      result = PdfFormFlattener(document).flatten();
    });

    test('acha e achata os 63 campos sem nenhum aviso', () {
      expect(fieldNames(reopen(source)).length, 63);
      expect(result.flattened.length, 63);
      expect(result.warnings, isEmpty);
      expect(result.remainingFields, 0);
      expect(result.acroFormRemoved, isTrue);
      expect(result.isComplete, isTrue);
      expect(
        result.flattened.map((e) => e.fieldType).toSet(),
        <String>{'/Tx'},
      );
    });

    test('a saída não tem mais /AcroForm nem widget em /Annots', () async {
      final before = reopen(source);
      final saved = reopen(await document.save());

      expect(saved.rootDict!.values['/AcroForm'], isNull);
      expect(fieldNames(saved), isEmpty);
      expect(widgetCount(saved), 0);
      // Só os 63 widgets saíram: os links continuam todos lá.
      expect(widgetCount(before), 63);
      expect(annotationCount(saved), annotationCount(before) - 63);
      expect(saved.pageCount, 366);
    });

    test('o desenho da aparência está no /Contents da página', () async {
      final saved = reopen(await document.save());

      for (final field in result.flattened.take(5)) {
        final content = pageContentText(saved, field.pageIndex);
        expect(
          content,
          contains('/Xap${field.appearance.number}_'
              '${field.appearance.generation} Do'),
          reason: 'campo ${field.name} na página ${field.pageIndex}',
        );
      }
    });

    test('a página carrega a aparência em /Resources /XObject', () async {
      final saved = reopen(await document.save());
      final field = result.flattened.first;

      final page = saved.pageDictAt(field.pageIndex)!;
      final resources =
          saved.resolve(page.values['/Resources']) as PdfDictToken;
      final xObjects =
          saved.resolve(resources.values['/XObject']) as PdfDictToken;
      final name = '/Xap${field.appearance.number}_'
          '${field.appearance.generation}';

      expect(xObjects.values.keys, contains(name));
      expect(
        PdfParserObjects.asRef(xObjects.values[name])?.obj,
        field.appearance.number,
      );
      // A aparência não foi copiada: é o objeto do arquivo original.
      expect(saved.getObject(field.appearance.number)?.streamData, isNotNull);
    });

    test('salvar duas vezes não desenha o mesmo campo duas vezes', () async {
      await document.save();
      final saved = reopen(await document.save());

      final field = result.flattened.first;
      final name = '/Xap${field.appearance.number}_'
          '${field.appearance.generation} Do';
      expect(
        name.allMatches(pageContentText(saved, field.pageIndex)).length,
        1,
      );
      expect(widgetCount(saved), 0);
    });

    test('não deixa nenhuma referência pendurada nova', () async {
      final before = danglingReferences(reopen(source));
      final saved = reopen(await document.save());
      expect(danglingReferences(saved).difference(before), isEmpty);
    });

    test('achatar de novo não encontra mais nada', () {
      final again = PdfFormFlattener(document).flatten();
      expect(again.flattened, isEmpty);
      expect(again.warnings.single, contains('não tem /AcroForm'));
    });
  });

  group('PdfFormFlattener — campo sem aparência', () {
    test('gera aviso e sobrevive ao achatamento', () async {
      final source = await buildTwoFieldForm();
      final document = PdfDocument.parseFromBytes(source, allowRepair: true);

      final result = PdfFormFlattener(document).flatten();

      expect(result.flattened.single.name, 'com_aparencia');
      expect(result.flattened.single.fieldType, '/Sig');
      expect(result.remainingFields, 1);
      expect(result.acroFormRemoved, isFalse);
      expect(result.isComplete, isFalse);
      expect(result.warnings.single, contains('sem_aparencia'));
      expect(result.warnings.single, contains('sem /AP'));
      expect(
        result.warnings.single,
        contains('não sintetiza aparência'),
      );

      final saved = reopen(await document.save());
      expect(fieldNames(saved), <String>['sem_aparencia']);
      expect(widgetCount(saved), 1);
      expect(
        pageContentText(saved, 0),
        contains('/Xap${result.flattened.single.appearance.number}_0 Do'),
      );
      expect(danglingReferences(saved).difference(danglingReferences(
        reopen(source),
      )), isEmpty);
    });

    test('achatar só um campo pelo nome deixa o resto intacto', () async {
      final document = PdfDocument.parseFromBytes(
        await buildTwoFieldForm(),
        allowRepair: true,
      );

      final result = PdfFormFlattener(document)
          .flatten(fieldNames: <String>['com_aparencia']);

      expect(result.flattened.single.name, 'com_aparencia');
      expect(result.warnings, isEmpty);
      expect(result.remainingFields, 1);

      final saved = reopen(await document.save());
      expect(fieldNames(saved), <String>['sem_aparencia']);
    });

    test('achatar em duas chamadas reaproveita o editor da página', () async {
      final document = PdfDocument.parseFromBytes(
        await buildTwoAppearanceForm(),
        allowRepair: true,
      );

      final flattener = PdfFormFlattener(document);
      final first = flattener.flatten(fieldNames: <String>['primeiro']);
      final second = flattener.flatten(fieldNames: <String>['segundo']);

      expect(first.flattened.single.name, 'primeiro');
      expect(second.flattened.single.name, 'segundo');
      expect(second.warnings, isEmpty);
      expect(second.acroFormRemoved, isTrue);

      final saved = reopen(await document.save());
      final content = pageContentText(saved, 0);
      expect(widgetCount(saved), 0);
      // Um `Do` por campo, e um único par `q`/`Q` envolvendo o original.
      expect(' Do '.allMatches(content).length, 2);
      expect('q'.allMatches(content).length, 'Q'.allMatches(content).length);
      for (final field in <PdfFlattenedField>[
        first.flattened.single,
        second.flattened.single,
      ]) {
        expect(content, contains('/Xap${field.appearance.number}_0 Do'));
      }
    });

    test('pedir um campo inexistente vira aviso', () async {
      final document = PdfDocument.parseFromBytes(
        await buildTwoFieldForm(),
        allowRepair: true,
      );

      final result =
          PdfFormFlattener(document).flatten(fieldNames: <String>['fantasma']);

      expect(result.flattened, isEmpty);
      expect(result.warnings.single, contains('"fantasma" não existe'));
    });
  });

  group('PdfFormFlattener — posicionamento', () {
    test('escala a aparência da /BBox até o /Rect do widget', () async {
      final document = PdfDocument.parseFromBytes(
        await buildScaledForm(),
        allowRepair: true,
      );

      final result = PdfFormFlattener(document).flatten();
      expect(result.warnings, isEmpty);

      final field = result.flattened.single;
      expect(field.rect, const PdfBox(50, 400, 290, 480));

      final saved = reopen(await document.save());
      // /BBox 120x40 dentro de um /Rect 240x80: escala 2 em cada eixo.
      expect(
        pageContentText(saved, 0),
        contains('2 0 0 2 50 400 cm '
            '/Xap${field.appearance.number}_0 Do'),
      );
    });

    test('o retângulo também é relatado em coordenadas top-left', () async {
      final document = PdfDocument.parseFromBytes(
        await buildScaledForm(),
        allowRepair: true,
      );

      final field = PdfFormFlattener(document).flatten().flattened.single;
      expect(field.displayRect.width, closeTo(240, 1e-9));
      expect(field.displayRect.height, closeTo(80, 1e-9));
      expect(field.displayRect.left, closeTo(50, 1e-9));
      // A página tem 841.89 pt de altura; o topo do widget está em y=480.
      expect(field.displayRect.top, closeTo(841.89 - 480, 1e-2));
    });
  });

  group('PdfFormFlattener — estados de aparência', () {
    test('escolhe o estado apontado por /AS', () async {
      final document = PdfDocument.parseFromBytes(
        await buildStateForm(selected: true),
        allowRepair: true,
      );

      final result = PdfFormFlattener(document).flatten();

      expect(result.warnings, isEmpty);
      expect(result.flattened.single.appearanceState, '/Yes');
      expect(result.acroFormRemoved, isTrue);

      final saved = reopen(await document.save());
      expect(widgetCount(saved), 0);
      expect(
        pageContentText(saved, 0),
        contains('/Xap${result.flattened.single.appearance.number}_0 Do'),
      );
    });

    test('vários estados sem /AS é ambíguo: avisa e mantém', () async {
      final document = PdfDocument.parseFromBytes(
        await buildStateForm(selected: false),
        allowRepair: true,
      );

      final result = PdfFormFlattener(document).flatten();

      expect(result.flattened, isEmpty);
      expect(result.remainingFields, 1);
      expect(result.warnings.single, contains('2 estados'));
      expect(result.warnings.single, contains('sem /AS'));

      final saved = reopen(await document.save());
      expect(widgetCount(saved), 1);
      expect(fieldNames(saved), <String>['marcado']);
    });
  });

  group('PdfFormFlattener — hierarquia e /NeedAppearances', () {
    test('percorre /Kids, achata o widget e remove o campo pai', () async {
      final source = await buildKidsForm();
      final document = PdfDocument.parseFromBytes(source, allowRepair: true);

      final result = PdfFormFlattener(document).flatten();

      expect(result.warnings, isEmpty);
      expect(result.flattened.single.name, 'grupo');
      expect(result.flattened.single.fieldType, '/Tx');
      expect(result.acroFormRemoved, isTrue);

      final saved = reopen(await document.save());
      expect(saved.rootDict!.values['/AcroForm'], isNull);
      expect(widgetCount(saved), 0);
      expect(
        pageContentText(saved, 0),
        contains('/Xap${result.flattened.single.appearance.number}_0 Do'),
      );
      expect(
        danglingReferences(saved).difference(danglingReferences(reopen(source))),
        isEmpty,
      );
    });

    test('/NeedAppearances some junto com o /AcroForm', () async {
      final document = PdfDocument.parseFromBytes(
        await buildKidsForm(),
        allowRepair: true,
      );
      expect(
        acroForm(reopen(await buildKidsForm()))!.values['/NeedAppearances'],
        isNotNull,
      );

      PdfFormFlattener(document).flatten();
      final saved = reopen(await document.save());
      expect(saved.rootDict!.values['/AcroForm'], isNull);
    });

    test('com removeAcroFormWhenEmpty falso o /AcroForm fica sem campos',
        () async {
      final document = PdfDocument.parseFromBytes(
        await buildKidsForm(),
        allowRepair: true,
      );

      final result = PdfFormFlattener(
        document,
        options: const PdfFormFlattenOptions(removeAcroFormWhenEmpty: false),
      ).flatten();

      expect(result.acroFormRemoved, isFalse);
      expect(result.remainingFields, 0);

      final saved = reopen(await document.save());
      final form = acroForm(saved)!;
      expect(form.values['/NeedAppearances'], isNull);
      final fields = saved.resolve(form.values['/Fields']) as PdfArrayToken;
      expect(fields.values, isEmpty);
      expect(widgetCount(saved), 0);
    });
  });

  group('PdfFormFlattener — campos invisíveis', () {
    test('por padrão o campo oculto é removido sem desenhar', () async {
      final document = PdfDocument.parseFromBytes(
        await buildHiddenForm(),
        allowRepair: true,
      );

      final result = PdfFormFlattener(document).flatten();

      expect(result.flattened, isEmpty);
      expect(result.warnings.single, contains('invisível'));
      expect(result.warnings.single, contains('removido sem desenhar'));
      expect(result.acroFormRemoved, isTrue);

      final saved = reopen(await document.save());
      expect(widgetCount(saved), 0);
      expect(pageContentText(saved, 0), isNot(contains(' Do')));
    });

    test('com a política keep o campo oculto continua no formulário',
        () async {
      final document = PdfDocument.parseFromBytes(
        await buildHiddenForm(),
        allowRepair: true,
      );

      final result = PdfFormFlattener(
        document,
        options: const PdfFormFlattenOptions(
          invisibleFields: PdfInvisibleFieldPolicy.keep,
        ),
      ).flatten();

      expect(result.flattened, isEmpty);
      expect(result.remainingFields, 1);
      expect(result.warnings.single, contains('mantido'));

      final saved = reopen(await document.save());
      expect(fieldNames(saved), <String>['oculto']);
      expect(widgetCount(saved), 1);
    });
  });

  group('PdfFormFlattener — documento sem formulário', () {
    test('avisa e não altera nada', () async {
      final source = asset('termo.pdf');
      final document = PdfDocument.parseFromBytes(source, allowRepair: true);

      final result = PdfFormFlattener(document).flatten();

      expect(result.flattened, isEmpty);
      expect(result.remainingFields, 0);
      expect(result.acroFormRemoved, isFalse);
      expect(result.warnings.single, contains('não tem /AcroForm'));

      final before = reopen(source);
      final saved = reopen(await document.save());
      expect(
        <Uint8List?>[
          for (var i = 0; i < saved.pageCount; i++)
            decodedPageContent(saved, i),
        ],
        <Uint8List?>[
          for (var i = 0; i < before.pageCount; i++)
            decodedPageContent(before, i),
        ],
      );
      expect(annotationCount(saved), 3);
    });
  });
}
