import 'package:pdf_plus/pdf.dart';
import 'package:test/test.dart';

import 'content_test_helpers.dart';

/// Round-trip de content stream.
///
/// **O que estes testes afirmam:** tokenizar e reserializar preserva o
/// significado do stream — `parse(write(parse(x)))` produz exatamente a mesma
/// lista de operadores que `parse(x)`.
///
/// **O que estes testes NÃO afirmam:** igualdade byte a byte. O writer
/// normaliza o espaçamento entre tokens (um espaço entre operandos, uma quebra
/// de linha por operador), então `write(parse(x))` só coincide com `x` quando
/// a origem já usava exatamente esse espaçamento. Os literais em si —
/// notação numérica, escapes de nome e de string, bytes de imagem inline —
/// são preservados, e há um teste específico para isso.
void main() {
  const corpus = <String>[
    'termo.pdf',
    'Invoice.pdf',
    'paginador.pdf',
    'decisao.pdf',
    'C008_2021_4HD.pdf',
    'sample3.pdf',
  ];

  group('equivalência por reanálise em PDFs reais', () {
    for (final name in corpus) {
      test('$name: parse(write(parse(x))) == parse(x)', () {
        final parser = openAsset(name);
        expect(parser.pageCount, greaterThan(0), reason: 'PDF sem páginas');

        final pages = parser.pageCount < 4 ? parser.pageCount : 4;
        var checkedPages = 0;

        for (var index = 0; index < pages; index++) {
          final content = decodePageContent(parser, index);
          if (content == null || content.isEmpty) continue;
          checkedPages++;

          final operators = PdfContentParser.parseBytes(content);
          expect(operators, isNotEmpty,
              reason: '$name página $index não produziu operadores');

          final rewritten = PdfContentWriter.write(operators);
          final reparsed = PdfContentParser.parseBytes(rewritten);

          expect(sameOperators(operators, reparsed), isTrue,
              reason: '$name página $index: '
                  '${describeFirstDifference(operators, reparsed)}');

          // Estabilidade: a segunda volta não pode mais mudar nada.
          final thirdPass = PdfContentParser.parseBytes(
              PdfContentWriter.write(reparsed));
          expect(sameOperators(reparsed, thirdPass), isTrue,
              reason: '$name página $index não é estável na segunda volta');
        }

        expect(checkedPages, greaterThan(0),
            reason: '$name não teve nenhuma página com conteúdo legível');
      });
    }
  });

  test('PDF gerado pela própria biblioteca sobrevive ao round-trip', () async {
    final bytes = await buildSingleTextPdf('Round trip da propria lib');
    final parser = openBytes(bytes);

    final content = decodePageContent(parser, 0);
    expect(content, isNotNull);

    final operators = PdfContentParser.parseBytes(content!);
    expect(operators, isNotEmpty);
    expect(operators.map((e) => e.operator), contains('TJ'));

    final reparsed =
        PdfContentParser.parseBytes(PdfContentWriter.write(operators));
    expect(sameOperators(operators, reparsed), isTrue,
        reason: describeFirstDifference(operators, reparsed));
  });

  group('fidelidade dos literais', () {
    test('números, nomes e strings saem com o lexema original', () {
      final source = ascii('0.10000 0 0 0.10000 +5 0 cm\n'
          '/Nome#20com#20espaco 12 Tf\n'
          r'(a\(b\) \303\251) Tj' '\n'
          '<48656C6C6F> Tj\n');

      final written = PdfContentWriter.write(
          PdfContentParser.parseBytes(source));
      final text = String.fromCharCodes(written);

      expect(text, contains('0.10000'));
      expect(text, contains('+5'));
      expect(text, contains('/Nome#20com#20espaco'));
      expect(text, contains(r'(a\(b\) \303\251)'));
      expect(text, contains('<48656C6C6F>'));
    });

    test('igualdade byte a byte só quando a origem já é canônica', () {
      // Espaçamento canônico: sobrevive inteiro.
      final canonical = ascii('q\n1 0 0 1 10 20 cm\nQ\n');
      expect(PdfContentWriter.write(PdfContentParser.parseBytes(canonical)),
          orderedEquals(canonical));

      // Espaçamento diferente: os bytes mudam, os operadores não.
      final compact = ascii('q 1 0 0 1 10 20 cm Q');
      final rewritten =
          PdfContentWriter.write(PdfContentParser.parseBytes(compact));
      expect(rewritten, isNot(orderedEquals(compact)));
      expect(
          sameOperators(PdfContentParser.parseBytes(compact),
              PdfContentParser.parseBytes(rewritten)),
          isTrue);
    });

    test('comentários preservados quando pedidos', () {
      final source = ascii('% gerado por teste\nq\nQ\n');
      final operators =
          PdfContentParser.parseBytes(source, keepComments: true);
      final written = PdfContentWriter.write(operators);
      expect(written, orderedEquals(source));
    });
  });

  test('todas as páginas legíveis do corpus são equivalentes por reanálise',
      () {
    // Varredura ampla: o objetivo é achar construções que só aparecem em
    // arquivos reais (dicionários inline de `BDC`, operadores de compatibi-
    // lidade `BX`/`EX`, sujeira entre operadores).
    const wide = <String>[
      'stf-fachin-1.pdf',
      'pedido.pdf',
      'downloadPeca.pdf',
      'gov_assinado.pdf',
      'relatorio_de_conformidade.pdf',
      'itext_base_multi.pdf',
      'itext_base_image.pdf',
      'example.pdf',
    ];

    var checked = 0;
    for (final name in wide) {
      final parser = openAsset(name);
      final pages = parser.pageCount < 3 ? parser.pageCount : 3;
      for (var index = 0; index < pages; index++) {
        final content = decodePageContent(parser, index);
        if (content == null || content.isEmpty) continue;
        final operators = PdfContentParser.parseBytes(content);
        final reparsed = PdfContentParser.parseBytes(
            PdfContentWriter.write(operators));
        expect(sameOperators(operators, reparsed), isTrue,
            reason: '$name página $index: '
                '${describeFirstDifference(operators, reparsed)}');
        checked++;
      }
    }
    expect(checked, greaterThanOrEqualTo(8));
  });
}
