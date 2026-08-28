import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:test/test.dart';

import 'content_test_helpers.dart';

/// Imagem inline `BI … ID … EI`.
///
/// Os bytes entre `ID` e `EI` são binários e podem conter qualquer coisa,
/// inclusive a própria sequência `EI`. Os testes cobrem as três estratégias do
/// parser: comprimento declarado em `/L`, comprimento calculado a partir de
/// `/W`, `/H`, `/BPC` e `/CS` quando não há filtro, e a busca heurística pelo
/// `EI` quando não há como calcular.
void main() {
  group('leitura', () {
    test('comprimento calculado protege bytes que contêm "EI"', () {
      // 4x4 pixels, 8 bits, escala de cinza = 16 bytes de dados, e esses
      // dados carregam " EI " no meio de propósito.
      final pixels = Uint8List.fromList(<int>[
        0, 1, 2, 0x20, 0x45, 0x49, 0x20, 7, //
        8, 9, 10, 11, 12, 13, 14, 15,
      ]);
      final stream = joinBytes(<List<int>>[
        ascii('q 100 0 0 100 10 10 cm\n'),
        ascii('BI /W 4 /H 4 /CS /G /BPC 8 ID '),
        pixels,
        ascii('\nEI\nQ\n'),
      ]);

      final operators = PdfContentParser.parseBytes(stream);
      expect(operators.map((e) => e.operator).toList(),
          <String>['q', 'cm', 'BI', 'Q']);

      final image = operators[2] as PdfInlineImage;
      expect(image.data, orderedEquals(pixels));
      expect(image.dict.lookup('/Width', '/W'), const PdfContentNumber(4));
      expect(image.lengthWasDeclared, isFalse);
    });

    test('`/L` declarado tem prioridade', () {
      // Dados comprimidos fictícios que contêm " EI " e cujo tamanho só o
      // `/L` revela.
      final payload = Uint8List.fromList(<int>[
        0x78, 0x9C, 0x20, 0x45, 0x49, 0x20, 0xFF, 0x00, 0x01,
      ]);
      final stream = joinBytes(<List<int>>[
        ascii('BI /W 8 /H 8 /CS /RGB /BPC 8 /F /Fl /L ${payload.length} ID '),
        payload,
        ascii('\nEI\n'),
      ]);

      final image =
          PdfContentParser.parseBytes(stream).single as PdfInlineImage;
      expect(image.data, orderedEquals(payload));
      expect(image.lengthWasDeclared, isTrue);
    });

    test('busca heurística quando há filtro e não há `/L`', () {
      final payload = ascii('4142434445');
      final stream = joinBytes(<List<int>>[
        ascii('BI /W 5 /H 1 /CS /G /BPC 8 /F /AHx ID '),
        payload,
        ascii('\nEI\n'),
      ]);

      final image =
          PdfContentParser.parseBytes(stream).single as PdfInlineImage;
      expect(image.data, orderedEquals(payload));
      expect(image.lengthWasDeclared, isFalse);
    });

    test('image mask usa 1 bit por pixel', () {
      // 16x2, 1 bpp, mask = 2 bytes por linha, 4 bytes no total.
      final payload = Uint8List.fromList(<int>[0xF0, 0x0F, 0x45, 0x49]);
      final stream = joinBytes(<List<int>>[
        ascii('BI /W 16 /H 2 /IM true /D [1 0] ID '),
        payload,
        ascii(' EI\n'),
      ]);

      final image =
          PdfContentParser.parseBytes(stream).single as PdfInlineImage;
      expect(image.data, orderedEquals(payload));
    });

    test('separador CRLF depois de ID é respeitado', () {
      final payload = Uint8List.fromList(<int>[1, 2, 3, 4]);
      final stream = joinBytes(<List<int>>[
        ascii('BI /W 2 /H 2 /CS /G /BPC 8 ID\r\n'),
        payload,
        ascii('\nEI\n'),
      ]);

      final image =
          PdfContentParser.parseBytes(stream).single as PdfInlineImage;
      expect(image.data, orderedEquals(payload));
      expect(image.separator, <int>[0x0D, 0x0A]);
    });
  });

  group('round-trip', () {
    test('os bytes da imagem saem idênticos e o reparse é equivalente', () {
      final pixels = Uint8List.fromList(
          List<int>.generate(48, (i) => (i * 7 + 3) & 0xFF));
      final stream = joinBytes(<List<int>>[
        ascii('q\n1 0 0 1 0 0 cm\n'),
        ascii('BI /W 4 /H 4 /CS /RGB /BPC 8 /D [0 1 0 1 0 1] ID '),
        pixels,
        ascii('\nEI\n'),
        ascii('Q\n'),
      ]);

      final first = PdfContentParser.parseBytes(stream);
      final written = PdfContentWriter.write(first);
      final second = PdfContentParser.parseBytes(written);

      expect(sameOperators(first, second), isTrue,
          reason: describeFirstDifference(first, second));

      final original = first.whereType<PdfInlineImage>().single;
      final roundTripped = second.whereType<PdfInlineImage>().single;
      expect(roundTripped.data, orderedEquals(original.data));
      expect(roundTripped.data, orderedEquals(pixels));
      expect(roundTripped.dict.values.keys.toList(),
          original.dict.values.keys.toList());

      // Terceira volta continua estável.
      final third = PdfContentParser.parseBytes(PdfContentWriter.write(second));
      expect(sameOperators(second, third), isTrue);
    });

    test('imagem com `/L` mantém o comprimento declarado após reescrita', () {
      final payload =
          Uint8List.fromList(List<int>.generate(30, (i) => (255 - i) & 0xFF));
      final stream = joinBytes(<List<int>>[
        ascii('BI /W 3 /H 3 /CS /RGB /BPC 8 /F /Fl /L ${payload.length} ID '),
        payload,
        ascii('\nEI\n'),
      ]);

      final first = PdfContentParser.parseBytes(stream);
      final second =
          PdfContentParser.parseBytes(PdfContentWriter.write(first));
      final image = second.whereType<PdfInlineImage>().single;

      expect(image.data, orderedEquals(payload));
      expect(image.lengthWasDeclared, isTrue);
      expect(image.dict.lookup('/Length', '/L'),
          PdfContentNumber(payload.length.toDouble()));
    });

    test('texto depois da imagem continua sendo lido', () {
      final stream = joinBytes(<List<int>>[
        ascii('BI /W 2 /H 2 /CS /G /BPC 8 ID '),
        Uint8List.fromList(<int>[1, 2, 3, 4]),
        ascii('\nEI\n'),
        ascii('BT /F1 10 Tf (depois) Tj ET\n'),
      ]);

      final operators = PdfContentParser.parseBytes(stream);
      expect(operators.map((e) => e.operator).toList(),
          <String>['BI', 'BT', 'Tf', 'Tj', 'ET']);
      final shown = operators[3].operands.single as PdfContentString;
      expect(String.fromCharCodes(shown.bytes), 'depois');
    });
  });
}
