import 'package:pdf_plus/pdf.dart';
import 'package:test/test.dart';

import 'content_test_helpers.dart';

/// Extração de texto com posição.
///
/// Os testes verificam três coisas: o texto conhecido aparece, a posição cai
/// dentro da `/MediaBox` da página, e o cálculo de matriz bate com números
/// fechados em um stream sintético.
void main() {
  group('geometria em stream sintético', () {
    final font = PdfContentFont(
      resourceName: '/F1',
      baseFont: '/Teste',
      subtype: '/Type1',
      firstChar: 65,
      widths: <double>[500, 500],
    );
    final resources =
        PdfMapContentResources(fonts: <String, PdfContentFont>{'/F1': font});

    List<PdfTextItem> run(String stream) =>
        PdfTextExtractor(resources: resources)
            .extract(PdfContentParser.parseBytes(ascii(stream)));

    test('Tm posiciona a linha de base e a largura vem de /Widths', () {
      final items = run('BT /F1 10 Tf 1 0 0 1 100 700 Tm (AB) Tj ET');

      expect(items, hasLength(1));
      final item = items.single;
      expect(item.text, 'AB');
      expect(item.fontName, '/F1');
      expect(item.baseFont, '/Teste');
      expect(item.origin.x, closeTo(100, 1e-9));
      expect(item.origin.y, closeTo(700, 1e-9));
      // 2 glifos de 500/1000 em, 10pt => 10pt de avanço.
      expect(item.bounds.left, closeTo(100, 1e-9));
      expect(item.bounds.width, closeTo(10, 1e-9));
      expect(item.bounds.bottom, closeTo(697.5, 1e-9));
      expect(item.bounds.height, closeTo(10, 1e-9));
      expect(item.renderedFontSize, closeTo(10, 1e-9));
    });

    test('cm multiplica posição e tamanho', () {
      final items =
          run('q 2 0 0 2 5 5 cm BT /F1 10 Tf 1 0 0 1 100 700 Tm (AB) Tj ET Q');

      final item = items.single;
      expect(item.origin.x, closeTo(205, 1e-9));
      expect(item.origin.y, closeTo(1405, 1e-9));
      expect(item.bounds.width, closeTo(20, 1e-9));
      expect(item.renderedFontSize, closeTo(20, 1e-9));
    });

    test('Q restaura a CTM salva por q', () {
      final items = run('q 2 0 0 2 0 0 cm Q '
          'BT /F1 10 Tf 1 0 0 1 100 700 Tm (AB) Tj ET');
      expect(items.single.origin.x, closeTo(100, 1e-9));
      expect(items.single.bounds.width, closeTo(10, 1e-9));
    });

    test('Td, TD e T* acumulam a matriz de linha', () {
      final items = run('BT /F1 10 Tf 12 TL 1 0 0 1 50 500 Tm '
          '(AB) Tj 0 -20 Td (AB) Tj T* (AB) Tj ET');

      expect(items.map((e) => e.origin.y.round()).toList(),
          <int>[500, 480, 468]);
      expect(items.map((e) => e.origin.x.round()).toList(), <int>[50, 50, 50]);
    });

    test('Tc, Tw e Tz entram no avanço', () {
      final base = run('BT /F1 10 Tf 1 0 0 1 0 0 Tm (AB) Tj ET').single;
      final spaced =
          run('BT /F1 10 Tf 3 Tc 1 0 0 1 0 0 Tm (AB) Tj ET').single;
      final scaled =
          run('BT /F1 10 Tf 200 Tz 1 0 0 1 0 0 Tm (AB) Tj ET').single;

      expect(base.bounds.width, closeTo(10, 1e-9));
      expect(spaced.bounds.width, closeTo(16, 1e-9)); // 2 * (5 + 3)
      expect(scaled.bounds.width, closeTo(20, 1e-9));
    });

    test('TJ aplica o ajuste e vira espaço quando o vão é grande', () {
      final items = run('BT /F1 10 Tf 1 0 0 1 0 0 Tm [(AB) -1000 (AB)] TJ ET');
      final item = items.single;
      expect(item.text, 'AB AB');
      // 10 (AB) + 10 (ajuste de 1000/1000 * 10) + 10 (AB)
      expect(item.bounds.width, closeTo(30, 1e-9));
    });

    test("' e \" avançam de linha antes de desenhar", () {
      final items = run('BT /F1 10 Tf 15 TL 1 0 0 1 20 400 Tm '
          "(AB) ' 1 2 (AB) \" ET");
      expect(items, hasLength(2));
      expect(items[0].origin.y, closeTo(385, 1e-9));
      expect(items[1].origin.y, closeTo(370, 1e-9));
    });

    test('fonte desconhecida ainda produz texto, com largura arbitrada', () {
      final items = run('BT /NaoExiste 10 Tf 1 0 0 1 0 0 Tm (AB) Tj ET');
      expect(items.single.text, 'AB');
      expect(items.single.baseFont, isNull);
      // Sem `/Widths` o extrator arbitra 500/1000 em por glifo.
      expect(items.single.bounds.width, closeTo(10, 1e-9));
    });
  });

  group('PDFs reais do corpus', () {
    void expectInsideMediaBox(String name, int pageIndex, PdfTextItem item) {
      final parser = openAsset(name);
      final page = parser.pageDictAt(pageIndex)!;
      final box = parser.resolvePageMediaBox(page)!;
      final left = box[0] < box[2] ? box[0] : box[2];
      final bottom = box[1] < box[3] ? box[1] : box[3];
      final right = box[0] < box[2] ? box[2] : box[0];
      final top = box[1] < box[3] ? box[3] : box[1];

      expect(item.bounds.left, greaterThanOrEqualTo(left - 1));
      expect(item.bounds.right, lessThanOrEqualTo(right + 1));
      expect(item.bounds.bottom, greaterThanOrEqualTo(bottom - 1));
      expect(item.bounds.top, lessThanOrEqualTo(top + 1));
    }

    test('Invoice.pdf: acha o cabeçalho e o número da fatura', () {
      final items = PdfTextExtractor.extractPage(openAsset('Invoice.pdf'), 0);
      expect(items, isNotEmpty);

      final header =
          items.firstWhere((e) => e.text.trim() == 'INVOICE', orElse: () {
        fail('não achou "INVOICE" em ${items.take(10).toList()}');
      });
      expect(header.fontName, isNotNull);
      expect(header.baseFont, contains('Helvetica'));
      expect(header.fullyMapped, isTrue);
      expectInsideMediaBox('Invoice.pdf', 0, header);

      // Cabeçalho fica na metade de cima de uma página A4/Letter.
      expect(header.bounds.bottom, greaterThan(600));

      final text = PdfTextExtractor.plainText(items);
      expect(text, contains('Invoice Number: 2058557939'));
      expect(text, contains('Abraham Swearegin'));
    });

    test('termo.pdf: texto com acento vindo de /ToUnicode', () {
      final items = PdfTextExtractor.extractPage(openAsset('termo.pdf'), 0);
      final text = PdfTextExtractor.plainText(items);

      expect(text,
          contains('TERMO ASSINADO POR MEIO DO CERTIFICADO DIGITAL ICP-BRASIL'));
      expect(text, contains('Declaração'));
      expect(items.every((e) => e.fullyMapped), isTrue,
          reason: 'todas as fontes da página têm /ToUnicode');

      final title = items.firstWhere((e) => e.text.contains('TERMO'));
      expectInsideMediaBox('termo.pdf', 0, title);
      expect(title.bounds.width, greaterThan(0));
      expect(title.renderedFontSize, greaterThan(5));
    });

    test('paginador.pdf: texto dentro de Form XObject aninhado', () {
      final parser = openAsset('paginador.pdf');
      final items = PdfTextExtractor.extractPage(parser, 0);
      final text = PdfTextExtractor.plainText(items);

      expect(text, contains('Supremo Tribunal Federal'));
      expect(text, contains('ALEXANDRE DE MORAES'));

      // O corpo do acórdão está dentro de Form XObjects.
      expect(items.any((e) => e.formDepth > 0), isTrue);

      // O título sai como um `Tj` inteiro, direto na página.
      final titulo =
          items.firstWhere((e) => e.text.contains('Supremo Tribunal Federal'));
      expect(titulo.formDepth, 0);
      expectInsideMediaBox('paginador.pdf', 0, titulo);

      // O corpo, vindo dos forms, também cai dentro da página.
      for (final item in items.where((e) => e.formDepth > 0)) {
        expectInsideMediaBox('paginador.pdf', 0, item);
      }
    });

    test('decisao.pdf: acentuação e ordem de leitura aproximada', () {
      final items = PdfTextExtractor.extractPage(openAsset('decisao.pdf'), 0);
      final text = PdfTextExtractor.plainText(items);

      expect(text, contains('RECURSO EXTRAORDINÁRIO'));
      expect(text, contains('SANTA CATARINA'));
      for (final item in items) {
        expectInsideMediaBox('decisao.pdf', 0, item);
      }
    });

    test('desligar Form XObject reduz o texto encontrado', () {
      final parser = openAsset('paginador.pdf');
      final withForms = PdfTextExtractor.extractPage(parser, 0);
      final withoutForms = PdfTextExtractor.extractPage(parser, 0,
          options:
              const PdfTextExtractionOptions(followFormXObjects: false));

      expect(withoutForms.length, lessThan(withForms.length));
      expect(PdfTextExtractor.plainText(withoutForms),
          isNot(contains('ALEXANDRE DE MORAES')));
    });
  });

  group('PDF gerado pela própria biblioteca', () {
    test('o texto desenhado volta pela extração, no meio da página', () async {
      const message = 'Conteudo verificavel 123';
      final parser = openBytes(await buildSingleTextPdf(message));

      final items = PdfTextExtractor.extractPage(parser, 0);
      expect(items, isNotEmpty);

      final text = PdfTextExtractor.plainText(items);
      expect(text, contains(message));

      // O layout quebra a frase em uma palavra por `TJ`, então a caixa da
      // frase inteira é a união das caixas das palavras.
      final words =
          items.where((e) => message.contains(e.text.trim())).toList();
      expect(words, hasLength(3));
      for (final word in words) {
        expect(word.fullyMapped, isTrue);
        expect(word.baseFont, contains('Helvetica'));
        expect(word.fontSize, closeTo(24, 1e-6));
      }

      final page = parser.pageDictAt(0)!;
      final box = parser.resolvePageMediaBox(page)!;
      var left = words.first.bounds.left;
      var right = words.first.bounds.right;
      var bottom = words.first.bounds.bottom;
      var top = words.first.bounds.top;
      for (final word in words) {
        left = left < word.bounds.left ? left : word.bounds.left;
        right = right > word.bounds.right ? right : word.bounds.right;
        bottom = bottom < word.bounds.bottom ? bottom : word.bounds.bottom;
        top = top > word.bounds.top ? top : word.bounds.top;
      }

      expect(left, greaterThan(0));
      expect(right, lessThan(box[2]));
      expect(bottom, greaterThan(0));
      expect(top, lessThan(box[3]));

      // `pw.Center` deixa o texto no meio da página nos dois eixos.
      expect((left + right) / 2, closeTo(box[2] / 2, box[2] * 0.05));
      expect((bottom + top) / 2, closeTo(box[3] / 2, box[3] * 0.05));
    });

    test('acentos em fonte padrão passam pela codificação latin-1', () async {
      const message = 'Ação e coração';
      final parser = openBytes(await buildSingleTextPdf(message));
      final text =
          PdfTextExtractor.plainText(PdfTextExtractor.extractPage(parser, 0));
      expect(text, contains(message));
    });
  });
}
