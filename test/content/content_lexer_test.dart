import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:test/test.dart';

import 'content_test_helpers.dart';

void main() {
  group('lexer', () {
    test('reconhece cada categoria de token', () {
      final lexer = PdfContentLexer(ascii(
          '12 -3.5 +.25 /Nome (texto) <414243> [ ] << >> true false null Tj % fim\n'));

      final kinds = <PdfContentTokenKind>[];
      final texts = <String>[];
      while (true) {
        final token = lexer.next();
        if (token.kind == PdfContentTokenKind.endOfData) break;
        kinds.add(token.kind);
        texts.add(token.text);
      }

      expect(kinds, <PdfContentTokenKind>[
        PdfContentTokenKind.number,
        PdfContentTokenKind.number,
        PdfContentTokenKind.number,
        PdfContentTokenKind.name,
        PdfContentTokenKind.literalString,
        PdfContentTokenKind.hexString,
        PdfContentTokenKind.arrayStart,
        PdfContentTokenKind.arrayEnd,
        PdfContentTokenKind.dictStart,
        PdfContentTokenKind.dictEnd,
        PdfContentTokenKind.keyword,
        PdfContentTokenKind.keyword,
        PdfContentTokenKind.keyword,
        PdfContentTokenKind.keyword,
        PdfContentTokenKind.comment,
      ]);
      expect(texts.last, ' fim');
    });

    test('números tolerantes', () {
      expect(PdfContentLexer.parseNumber('12'), 12);
      expect(PdfContentLexer.parseNumber('-3.5'), -3.5);
      expect(PdfContentLexer.parseNumber('+.25'), 0.25);
      expect(PdfContentLexer.parseNumber('4.'), 4);
      expect(PdfContentLexer.parseNumber('--3'), -3);
      expect(PdfContentLexer.parseNumber('6.-2'), 6);
      expect(PdfContentLexer.parseNumber('lixo'), 0);
    });

    test('escapes de string literal', () {
      final lexer = PdfContentLexer(
          ascii(r'(a\(b\)c\\d\n\t\101\12\5 e\' + '\n' + 'f)'));
      final token = lexer.next();
      expect(token.kind, PdfContentTokenKind.literalString);
      expect(String.fromCharCodes(token.bytes!),
          'a(b)c\\d\n\tA\n ef');
    });

    test('parênteses aninhados e EOL cru viram \\n', () {
      final lexer = PdfContentLexer(ascii('(um (dois) tres\r\nquatro)'));
      final token = lexer.next();
      expect(String.fromCharCodes(token.bytes!), 'um (dois) tres\nquatro');
    });

    test('string hexadecimal com espaços e dígito ímpar', () {
      final lexer = PdfContentLexer(ascii('<41 42 4>'));
      final token = lexer.next();
      expect(token.kind, PdfContentTokenKind.hexString);
      expect(token.bytes, <int>[0x41, 0x42, 0x40]);
    });

    test('nome com escape #xx', () {
      final lexer = PdfContentLexer(ascii('/Nome#20com#20espaco'));
      final token = lexer.next();
      expect(token.text, '/Nome com espaco');
    });
  });

  group('parser', () {
    test('agrupa operandos com o operador seguinte', () {
      final operators = PdfContentParser.parseBytes(
          ascii('1 0 0 1 10 20 cm\nBT /F1 12 Tf (oi) Tj ET\n'));

      expect(operators.map((e) => e.operator).toList(),
          <String>['cm', 'BT', 'Tf', 'Tj', 'ET']);
      expect(operators.first.operands.length, 6);
      expect(operators.first.numberAt(4), 10);
      expect(operators[2].nameAt(0), '/F1');
      expect(operators[2].numberAt(1), 12);
    });

    test('arrays, dicionários e literais aninhados', () {
      final operators = PdfContentParser.parseBytes(ascii(
          '[(a) -250 (b) [1 2]] TJ\n<</Type /X /Sub <</N 1>> /A [true false null]>> BDC\n'));

      final array = operators.first.operands.first as PdfContentArray;
      expect(array.values.length, 4);
      expect((array.values[1] as PdfContentNumber).value, -250);
      expect((array.values[3] as PdfContentArray).values.length, 2);

      final dict = operators[1].operands.first as PdfContentDict;
      expect(dict.values.keys.toList(), <String>['/Type', '/Sub', '/A']);
      expect((dict.values['/Sub'] as PdfContentDict).values['/N'],
          const PdfContentNumber(1));
      final flags = dict.values['/A'] as PdfContentArray;
      expect(flags.values, <PdfContentValue>[
        const PdfContentBool(true),
        const PdfContentBool(false),
        const PdfContentNull(),
      ]);
    });

    test('comentários são descartados por padrão e mantidos sob demanda', () {
      final data = ascii('% cabecalho\nq\n% meio\nQ\n');
      expect(PdfContentParser.parseBytes(data).map((e) => e.operator).toList(),
          <String>['q', 'Q']);

      final withComments =
          PdfContentParser.parseBytes(data, keepComments: true);
      expect(withComments.length, 4);
      expect(withComments.first, isA<PdfContentComment>());
      expect((withComments.first as PdfContentComment).text, ' cabecalho');
    });

    test('operador desconhecido é preservado com seus operandos', () {
      final operators =
          PdfContentParser.parseBytes(ascii('1 2 3 opDesconhecido\n'));
      expect(operators.single.operator, 'opDesconhecido');
      expect(operators.single.operands.length, 3);
    });

    test('stream truncado não lança', () {
      expect(
          () => PdfContentParser.parseBytes(ascii('BT /F1 12 Tf (texto sem')),
          returnsNormally);
      expect(() => PdfContentParser.parseBytes(ascii('<</A [1 2')),
          returnsNormally);
      expect(() => PdfContentParser.parseBytes(Uint8List(0)), returnsNormally);
    });
  });

  group('writer', () {
    test('preserva a notação numérica original', () {
      final data = ascii('0.10000 0 0 0.10000 +5 -0. cm\n');
      final written = PdfContentWriter.write(PdfContentParser.parseBytes(data));
      expect(String.fromCharCodes(written), '0.10000 0 0 0.10000 +5 -0. cm\n');
    });

    test('formata números quando não há lexema original', () {
      expect(PdfContentWriter.formatNumber(12), '12');
      expect(PdfContentWriter.formatNumber(-0.5), '-0.5');
      expect(PdfContentWriter.formatNumber(1.25), '1.25');
      expect(PdfContentWriter.formatNumber(1 / 3), '0.333333');
    });

    test('escapa string construída à mão', () {
      final written = PdfContentWriter.write(<PdfContentOperator>[
        PdfContentOperator('Tj', <PdfContentValue>[
          PdfContentString(Uint8List.fromList('a(b)\\c\n'.codeUnits)),
        ]),
      ]);
      expect(String.fromCharCodes(written), r'(a\(b\)\\c\n) Tj' '\n');
    });

    test('escapa nomes com caracteres especiais', () {
      expect(PdfContentWriter.escapeName('/A B'), '/A#20B');
      expect(PdfContentWriter.escapeName('/Simples'), '/Simples');
    });
  });
}
