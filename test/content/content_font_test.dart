import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:test/test.dart';

import 'content_test_helpers.dart';

/// Mapeamento de bytes para texto.
///
/// O extrator usa `/ToUnicode` quando existe e cai para WinAnsi/latin-1 quando
/// não existe. Estes testes fixam os dois caminhos e, principalmente, fixam o
/// caso em que **não há** como acertar: Type0 subsetada sem `/ToUnicode`.
void main() {
  group('CMap /ToUnicode', () {
    test('bfchar e codespacerange', () {
      final cmap = PdfContentFont.parseToUnicode(ascii('''
/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
3 beginbfchar
<0003> <0020>
<0024> <0041>
<0025> <00C1>
endbfchar
endcmap
'''));

      expect(cmap.codeByteLength, 2);
      expect(cmap.map[0x03], ' ');
      expect(cmap.map[0x24], 'A');
      expect(cmap.map[0x25], 'Á');
    });

    test('bfrange com destino simples e com array', () {
      final cmap = PdfContentFont.parseToUnicode(ascii('''
2 beginbfrange
<0041> <0043> <0061>
<0050> <0052> [<0078> <0079> <007A>]
endbfrange
'''));

      expect(cmap.map[0x41], 'a');
      expect(cmap.map[0x42], 'b');
      expect(cmap.map[0x43], 'c');
      expect(cmap.map[0x50], 'x');
      expect(cmap.map[0x51], 'y');
      expect(cmap.map[0x52], 'z');
    });

    test('destino com par substituto', () {
      final cmap = PdfContentFont.parseToUnicode(
          ascii('1 beginbfchar\n<0001> <D83DDE00>\nendbfchar\n'));
      expect(cmap.map[1], '\u{1F600}');
    });

    test('CMap inválido não lança e devolve mapa vazio', () {
      expect(PdfContentFont.parseToUnicode(ascii('lixo aleatorio')).isEmpty,
          isTrue);
      expect(PdfContentFont.parseToUnicode(Uint8List(0)).isEmpty, isTrue);
    });
  });

  group('decodificação de códigos', () {
    test('fonte simples com ToUnicode', () {
      final font = PdfContentFont(
        toUnicode: <int, String>{0x41: 'X', 0x42: 'Y'},
        firstChar: 0x41,
        widths: <double>[600, 700],
      );
      final glyphs = font.decode(Uint8List.fromList(<int>[0x41, 0x42]));
      expect(glyphs.map((e) => e.text).join(), 'XY');
      expect(glyphs.map((e) => e.width).toList(), <double>[600, 700]);
      expect(glyphs.every((e) => e.mapped), isTrue);
    });

    test('fonte simples sem ToUnicode cai para WinAnsi/latin-1', () {
      final font = PdfContentFont();
      expect(font.decodeText(Uint8List.fromList(<int>[0x41, 0xE7, 0xE3])),
          'Açã');
      // 0x92 é aspa curva em WinAnsi e um caractere de controle em latin-1.
      expect(font.decodeText(Uint8List.fromList(<int>[0x92])), '’');
      expect(font.decodeText(Uint8List.fromList(<int>[0x80])), '€');
    });

    test('Type0 com ToUnicode lê códigos de dois bytes', () {
      final font = PdfContentFont(
        composite: true,
        codeByteLength: 2,
        toUnicode: <int, String>{0x0024: 'A', 0x0025: 'B'},
        cidWidths: <int, double>{0x24: 550},
        defaultWidth: 1000,
      );
      final glyphs =
          font.decode(Uint8List.fromList(<int>[0x00, 0x24, 0x00, 0x25]));
      expect(glyphs, hasLength(2));
      expect(glyphs.map((e) => e.text).join(), 'AB');
      expect(glyphs[0].width, 550);
      expect(glyphs[1].width, 1000); // /DW
    });

    test('Type0 subsetada sem ToUnicode é indecifrável, e isso é declarado',
        () {
      final font = PdfContentFont(composite: true, codeByteLength: 2);
      final glyphs = font.decode(Uint8List.fromList(<int>[0x00, 0x24]));

      expect(glyphs.single.text, '�');
      expect(glyphs.single.mapped, isFalse);
      expect(font.hasReliableTextMapping, isFalse);
    });

    test('/Differences por nome de glifo', () {
      final font = PdfContentFont(differences: <int, String>{
        0x41: PdfContentFont.glyphNameToText('/ccedilla')!,
        0x42: PdfContentFont.glyphNameToText('/uni00E3')!,
      });
      expect(font.decodeText(Uint8List.fromList(<int>[0x41, 0x42])), 'çã');
      expect(PdfContentFont.glyphNameToText('/g42'), isNull);
    });
  });

  group('fontes lidas de PDFs reais', () {
    test('decisao.pdf: Type0 subsetada com /ToUnicode e /W', () {
      final parser = openAsset('decisao.pdf');
      final resources = PdfParserContentResources.forPage(parser, 0)!;

      final font = resources.findFont('/F1');
      expect(font, isNotNull);
      expect(font!.baseFont, contains('Palatino'));
      expect(font.composite, isTrue);
      expect(font.codeByteLength, 2);
      expect(font.toUnicode, isNotEmpty);
      expect(font.cidWidths, isNotEmpty);
      expect(font.hasReliableTextMapping, isTrue);

      // O cache devolve a mesma instância.
      expect(identical(resources.findFont('/F1'), font), isTrue);
    });

    test('termo.pdf: TrueType sem /ToUnicode lê pelo fallback WinAnsi', () {
      final parser = openAsset('termo.pdf');
      final resources = PdfParserContentResources.forPage(parser, 0)!;

      final font = resources.findFont('/F1');
      expect(font, isNotNull);
      expect(font!.baseFont, contains('Calibri'));
      expect(font.composite, isFalse);
      expect(font.toUnicode, isEmpty,
          reason: 'esta fonte não traz /ToUnicode; o texto sai por WinAnsi');
      expect(font.widths, isNotEmpty);
      expect(font.widthOf(font.firstChar), greaterThan(0));
      // Sem /ToUnicode a fonte simples ainda é considerada legível — é o
      // fallback latin-1/WinAnsi que sustenta essa afirmação.
      expect(font.hasReliableTextMapping, isTrue);
    });

    test('Invoice.pdf usa Helvetica sem ToUnicode e ainda assim lê', () {
      final parser = openAsset('Invoice.pdf');
      final items = PdfTextExtractor.extractPage(parser, 0);
      final helvetica =
          items.where((e) => (e.baseFont ?? '').contains('Helvetica'));
      expect(helvetica, isNotEmpty);
      expect(helvetica.every((e) => e.fullyMapped), isTrue);
    });

    test('recurso ausente devolve nulo em vez de explodir', () {
      final parser = openAsset('Invoice.pdf');
      final resources = PdfParserContentResources.forPage(parser, 0)!;
      expect(resources.findFont('/NaoExiste'), isNull);
      expect(resources.findFormXObject('/NaoExiste'), isNull);
    });
  });
}
