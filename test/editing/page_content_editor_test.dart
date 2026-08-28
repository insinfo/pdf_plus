import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:test/test.dart';

/// Bytes de um PDF do corpus de teste.
Uint8List asset(String name) =>
    File('test/assets/pdfs/$name').readAsBytesSync();

/// Reabre um PDF gerado, garantindo que ele é legível.
PdfDocumentParser reopen(Uint8List bytes) =>
    PdfDocumentParser(bytes, allowRepair: true);

/// Números dos objetos listados no `/Contents` da página.
List<int> contentRefs(PdfDocumentParser parser, int pageIndex) {
  final page = parser.pageDictAt(pageIndex);
  if (page == null) return const <int>[];
  final contents = parser.resolve(page.values['/Contents']);
  if (contents is PdfArrayToken) {
    return contents.values
        .map((e) => PdfParserObjects.asRef(e)?.obj)
        .whereType<int>()
        .toList();
  }
  final single = PdfParserObjects.asRef(page.values['/Contents']);
  return single == null ? const <int>[] : <int>[single.obj];
}

/// Conteúdo de um stream, já descomprimido.
Uint8List? streamBytes(PdfDocumentParser parser, int objId) {
  final object = parser.getObject(objId);
  var data = object?.streamData;
  if (object == null || data == null) return null;

  final dict = object.value;
  if (dict is PdfDictToken) {
    final filter = parser.resolve(dict.values['/Filter']);
    final names = <String>[
      if (filter is PdfNameToken) filter.value,
      if (filter is PdfArrayToken)
        ...filter.values.whereType<PdfNameToken>().map((e) => e.value),
    ];
    for (final name in names) {
      if (name != '/FlateDecode') return null;
      data = Uint8List.fromList(ZLibDecoder().decodeBytes(data!));
    }
  }
  return data;
}

/// Texto de um stream de conteúdo.
String streamText(PdfDocumentParser parser, int objId) {
  final bytes = streamBytes(parser, objId);
  return bytes == null ? '' : String.fromCharCodes(bytes);
}

/// Conteúdo completo da página, na ordem em que o leitor vai executá-lo.
String pageContent(PdfDocumentParser parser, int pageIndex) {
  final buffer = StringBuffer();
  for (final ref in contentRefs(parser, pageIndex)) {
    buffer.write(streamText(parser, ref));
  }
  return buffer.toString();
}

/// Nomes das fontes declaradas no `/Resources` da página.
List<String> fontNames(PdfDocumentParser parser, int pageIndex) {
  final page = parser.pageDictAt(pageIndex);
  if (page == null) return const <String>[];
  final resources = parser.resolvePageResources(page);
  if (resources == null) return const <String>[];
  final fonts = parser.resolve(resources.values['/Font']);
  if (fonts is! PdfDictToken) return const <String>[];
  return fonts.values.keys.toList()..sort();
}

/// Uma imagem RGBA mínima, só para exercitar o carimbo de imagem.
PdfImage tinyImage(PdfDocument document) => PdfImage(
      document,
      image: Uint8List.fromList(List<int>.filled(4 * 4 * 4, 0x80)),
      width: 4,
      height: 4,
    );

void main() {
  group('página nova', () {
    test('subposição, conteúdo original e sobreposição nesta ordem', () async {
      final document = PdfDocument();
      final page = PdfPage(document, pageFormat: PdfPageFormat.a4);
      final font = PdfFont.helvetica(document);

      final original = page.getGraphics();
      original.drawString(font, 12, 'ORIGINAL', 40, 700);

      final editor = PdfPageContentEditor(page);
      editor.drawOverlay((canvas) {
        canvas.drawString(font, 12, 'SOBREPOSTO', 40, 600);
      });
      editor.drawUnderlay((canvas) {
        canvas.drawString(font, 12, 'SUBPOSTO', 40, 500);
      });

      final parser = reopen(await document.save(useIsolate: false));
      expect(parser.pageCount, 1);

      final content = pageContent(parser, 0);
      expect(content.indexOf('(SUBPOSTO)'), greaterThanOrEqualTo(0));
      expect(content.indexOf('(SUBPOSTO)'), lessThan(content.indexOf('(ORIGINAL)')));
      expect(
          content.indexOf('(ORIGINAL)'), lessThan(content.indexOf('(SOBREPOSTO)')));
    });

    test('o conteúdo antigo fica isolado entre um stream q e um stream Q',
        () async {
      final document = PdfDocument();
      final page = PdfPage(document, pageFormat: PdfPageFormat.a4);
      final font = PdfFont.helvetica(document);
      page.getGraphics().drawString(font, 12, 'ORIGINAL', 40, 700);

      PdfPageContentEditor(page).drawOverlay((canvas) {
        canvas.drawString(font, 12, 'CARIMBO', 40, 600);
      });

      final parser = reopen(await document.save(useIsolate: false));
      final refs = contentRefs(parser, 0);
      expect(refs, hasLength(3));

      expect(streamText(parser, refs[0]).trim(), 'q');
      expect(streamText(parser, refs[1]), contains('(ORIGINAL)'));
      expect(streamText(parser, refs[2]).trimLeft(), startsWith('Q'));
      expect(streamText(parser, refs[2]), contains('(CARIMBO)'));
    });

    test('o carimbo de texto se ancora pelo alto da página', () async {
      final document = PdfDocument();
      final page = PdfPage(document, pageFormat: PdfPageFormat.a4);
      final editor = PdfPageContentEditor(page);
      final font = PdfFont.helvetica(document);

      editor.drawStamp(PdfTextStamp(
        text: 'TOPO',
        font: font,
        fontSize: 10,
        anchor: PdfStampAnchor.topLeft,
        marginX: 20,
        marginY: 20,
      ));

      final parser = reopen(await document.save(useIsolate: false));
      final content = pageContent(parser, 0);
      expect(content, contains('(TOPO)'));

      // A matriz do carimbo põe a origem local no canto inferior esquerdo do
      // retângulo ancorado: x = 20 e y = altura - 20 - altura do texto.
      final match = RegExp(r'1 0 0 1 (\S+) (\S+) cm').firstMatch(content);
      expect(match, isNotNull);
      expect(double.parse(match!.group(1)!), closeTo(20, 0.01));
      expect(
          double.parse(match.group(2)!),
          closeTo(
              PdfPageFormat.a4.height - 20 - font.emptyLineHeight * 10, 0.01));
    });

    test('o carimbo de imagem entra como XObject da página', () async {
      final document = PdfDocument();
      final page = PdfPage(document, pageFormat: PdfPageFormat.a4);
      final image = tinyImage(document);

      PdfPageContentEditor(page).drawStamp(PdfImageStamp(
        image: image,
        width: 40,
        anchor: PdfStampAnchor.bottomRight,
      ));

      final parser = reopen(await document.save(useIsolate: false));
      final content = pageContent(parser, 0);
      expect(content, contains('${image.name} Do'));
      expect(content, contains('40 0 0 40 0 0 cm'),
          reason: 'a altura sai da proporção da imagem');

      final resources = parser.resolvePageResources(parser.pageDictAt(0)!);
      final xObjects = parser.resolve(resources!.values['/XObject']);
      expect(xObjects, isA<PdfDictToken>());
      expect((xObjects as PdfDictToken).values.keys, contains(image.name));
    });

    test('a página girada recebe o carimbo em pé', () async {
      final document = PdfDocument();
      final page = PdfPage(document,
          pageFormat: PdfPageFormat.a4, rotate: PdfPageRotation.rotate90);
      final editor = PdfPageContentEditor(page);

      expect(editor.transformer.displayWidth,
          closeTo(PdfPageFormat.a4.height, 1e-6));

      editor.drawStamp(PdfTextStamp(
        text: 'GIRADO',
        font: PdfFont.helvetica(document),
        anchor: PdfStampAnchor.topLeft,
        marginX: 10,
        marginY: 10,
      ));

      final parser = reopen(await document.save(useIsolate: false));
      final content = pageContent(parser, 0);
      expect(content, contains('(GIRADO)'));
      // Matriz de giro de 90° anti-horário: o leitor gira a página de volta.
      expect(content, contains('0 1 -1 0 '));
    });
  });

  group('documento carregado', () {
    test('recarrega, mantém o conteúdo original e mostra o novo', () async {
      final bytes = asset('termo.pdf');
      final source = reopen(bytes);
      final originalRefs = contentRefs(source, 0);
      final originalContent = pageContent(source, 0);

      final document = PdfDocument.parseFromBytes(bytes, allowRepair: true);
      final page = PdfPageContentEditor.distinctPages(document).first;
      final editor = PdfPageContentEditor(page);
      editor.drawOverlay((canvas) {
        canvas.drawString(
            PdfFont.helvetica(document), 12, 'CARIMBO F4', 40, 40);
      });

      final saved = await document.save(useIsolate: false);
      final parser = reopen(saved);

      // (a) o documento recarrega
      expect(parser.pageCount, source.pageCount);

      // (b) o stream original continua lá, byte a byte
      for (final ref in originalRefs) {
        expect(contentRefs(parser, 0), contains(ref));
        expect(
          parser.getObject(ref)!.streamData,
          source.getObject(ref)!.streamData,
          reason: 'o stream $ref não pode ser reescrito',
        );
      }
      expect(pageContent(parser, 0), contains(originalContent));

      // (c) o conteúdo novo aparece
      expect(pageContent(parser, 0), contains('(CARIMBO F4)'));
    });

    test('o conteúdo original é envolvido por q e Q', () async {
      final bytes = asset('termo.pdf');
      final source = reopen(bytes);
      final originalRef = contentRefs(source, 0).single;

      final document = PdfDocument.parseFromBytes(bytes, allowRepair: true);
      PdfPageContentEditor(PdfPageContentEditor.distinctPages(document).first)
          .drawOverlay((canvas) {
        canvas.drawString(
            PdfFont.helvetica(document), 12, 'CARIMBO F4', 40, 40);
      });

      final parser = reopen(await document.save(useIsolate: false));
      final refs = contentRefs(parser, 0);
      final index = refs.indexOf(originalRef);

      expect(index, 1, reason: 'o stream q precisa vir antes do original');
      expect(streamText(parser, refs[0]).trim(), 'q');
      expect(streamText(parser, refs[2]).trimLeft(), startsWith('Q'));
    });

    test('os recursos originais da página sobrevivem ao carimbo', () async {
      final bytes = asset('termo.pdf');
      final originalFonts = fontNames(reopen(bytes), 0);
      expect(originalFonts, isNotEmpty);

      final document = PdfDocument.parseFromBytes(bytes, allowRepair: true);
      PdfPageContentEditor(PdfPageContentEditor.distinctPages(document).first)
          .drawOverlay((canvas) {
        canvas.drawString(
            PdfFont.helvetica(document), 12, 'CARIMBO F4', 40, 40);
      });

      final parser = reopen(await document.save(useIsolate: false));
      final fonts = fontNames(parser, 0);
      for (final name in originalFonts) {
        expect(fonts, contains(name));
      }
      expect(fonts.length, originalFonts.length + 1,
          reason: 'só a fonte do carimbo entra');
    });

    test('recursos em objeto indireto não se perdem', () async {
      // A maioria dos PDFs do corpus guarda o `/Resources` da página em um
      // objeto indireto que o parser não materializa. Sem cuidado, desenhar
      // sobre a página substitui a referência e apaga fontes e imagens.
      final bytes = asset('pedido.pdf');
      final source = reopen(bytes);
      final originalFonts = fontNames(source, 0);
      expect(originalFonts, isNotEmpty);

      final document = PdfDocument.parseFromBytes(bytes, allowRepair: true);
      PdfPageContentEditor(PdfPageContentEditor.distinctPages(document).first)
          .drawOverlay((canvas) {
        canvas.drawString(
            PdfFont.helvetica(document), 12, 'CARIMBO F4', 40, 40);
      });

      final parser = reopen(await document.save(useIsolate: false));
      final fonts = fontNames(parser, 0);
      for (final name in originalFonts) {
        expect(fonts, contains(name));
      }
      expect(fonts.length, originalFonts.length + 1);

      final resources = parser.resolvePageResources(parser.pageDictAt(0)!);
      expect(resources!.values.keys, contains('/XObject'));
      expect(pageContent(parser, 0), contains('(CARIMBO F4)'));
    });

    test('salvar duas vezes não duplica o carimbo', () async {
      final bytes = asset('termo.pdf');
      final document = PdfDocument.parseFromBytes(bytes, allowRepair: true);
      PdfPageContentEditor(PdfPageContentEditor.distinctPages(document).first)
          .drawOverlay((canvas) {
        canvas.drawString(
            PdfFont.helvetica(document), 12, 'CARIMBO F4', 40, 40);
      });

      final first = reopen(await document.save(useIsolate: false));
      final second = reopen(await document.save(useIsolate: false));

      expect(contentRefs(second, 0), contentRefs(first, 0));
      expect(pageContent(second, 0), pageContent(first, 0));
      expect(
        RegExp(r'\(CARIMBO F4\)').allMatches(pageContent(second, 0)).length,
        1,
      );
    });

    test('subposição fica embaixo do conteúdo carregado', () async {
      final bytes = asset('termo.pdf');
      final source = reopen(bytes);
      final originalRef = contentRefs(source, 0).single;

      final document = PdfDocument.parseFromBytes(bytes, allowRepair: true);
      final editor = PdfPageContentEditor(
          PdfPageContentEditor.distinctPages(document).first);
      editor.drawUnderlay((canvas) {
        canvas.drawString(
            PdfFont.helvetica(document), 12, 'MARCA', 100, 100);
      });

      final parser = reopen(await document.save(useIsolate: false));
      final refs = contentRefs(parser, 0);

      expect(streamText(parser, refs.first), contains('(MARCA)'));
      expect(refs.indexOf(originalRef), greaterThan(0));
      final content = pageContent(parser, 0);
      expect(content.indexOf('(MARCA)'),
          lessThan(content.indexOf(pageContent(source, 0).substring(0, 32))));
    });
  });

  group('PdfBatesNumbering', () {
    test('formata prefixo, dígitos e sufixo', () {
      const bates = PdfBatesNumbering(prefix: 'PROC-', suffix: '/2026');
      expect(bates.format(1), 'PROC-000001/2026');
      expect(bates.format(1234567), 'PROC-1234567/2026');
      expect(const PdfBatesNumbering(digits: 0).format(7), '7');
    });

    test('numera todas as páginas de um documento carregado', () async {
      final bytes = asset('termo.pdf');
      final document = PdfDocument.parseFromBytes(bytes, allowRepair: true);

      const bates = PdfBatesNumbering(prefix: 'PROC-', digits: 6);
      expect(bates.applyToDocument(document), 2,
          reason: 'a lista de páginas de um documento carregado tem '
              'duplicatas; a numeração precisa ignorá-las');

      final parser = reopen(await document.save(useIsolate: false));
      expect(parser.pageCount, 2);
      expect(pageContent(parser, 0), contains('(PROC-000001)'));
      expect(pageContent(parser, 1), contains('(PROC-000002)'));
      expect(pageContent(parser, 0), isNot(contains('(PROC-000002)')));
    });

    test('numera apenas o intervalo pedido, com início e passo próprios',
        () async {
      final document = PdfDocument();
      for (var i = 0; i < 4; i++) {
        PdfPage(document, pageFormat: PdfPageFormat.a4);
      }

      const bates = PdfBatesNumbering(
        prefix: 'F',
        digits: 3,
        start: 10,
        step: 5,
        anchor: PdfStampAnchor.bottomLeft,
      );
      expect(bates.applyToDocument(document, from: 1, to: 3), 2);

      final parser = reopen(await document.save(useIsolate: false));
      expect(parser.pageCount, 4);
      expect(pageContent(parser, 0), isNot(contains('(F')));
      expect(pageContent(parser, 1), contains('(F010)'));
      expect(pageContent(parser, 2), contains('(F015)'));
      expect(pageContent(parser, 3), isNot(contains('(F')));
    });

    test('intervalo vazio ou fora da faixa não carimba nada', () {
      final document = PdfDocument();
      PdfPage(document, pageFormat: PdfPageFormat.a4);

      const bates = PdfBatesNumbering();
      expect(bates.applyToDocument(document, from: 5), 0);
      expect(bates.applyToDocument(document, from: 0, to: 0), 0);
      expect(bates.applyToDocument(document, to: 99), 1);
    });
  });
}
