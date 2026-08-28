import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/format/array.dart';
import 'package:pdf_plus/src/pdf/format/num.dart';
import 'package:test/test.dart';

/// A conversão que a biblioteca faz hoje, em `PdfDocument._rectFromTopLeft` e
/// em `PdfSignatureBounds.toPdfRect`: só a altura, nada de origem, crop ou
/// rotação. Reproduzida aqui para os testes mostrarem onde ela erra.
PdfRect legacyRectFromTopLeft(
  PdfPage page, {
  required double left,
  required double top,
  required double width,
  required double height,
}) {
  final pageHeight = page.pageFormat.height;
  return PdfRect(left, pageHeight - top - height, width, height);
}

void main() {
  group('caixa na origem, sem rotação', () {
    test('concorda com a conversão antiga — este é o caso que ela acerta', () {
      final document = PdfDocument();
      final page = PdfPage(document, pageFormat: PdfPageFormat.a4);
      final transformer = PdfCoordinateTransformer.forPage(page);

      final novo = transformer.rectFromTopLeft(
          left: 40, top: 60, width: 200, height: 20);
      final antigo = legacyRectFromTopLeft(page,
          left: 40, top: 60, width: 200, height: 20);

      expect(novo.left, closeTo(antigo.left, 1e-9));
      expect(novo.bottom, closeTo(antigo.bottom, 1e-9));
      expect(novo.width, closeTo(200, 1e-9));
      expect(novo.height, closeTo(20, 1e-9));
      expect(novo.bottom, closeTo(PdfPageFormat.a4.height - 60 - 20, 1e-9));
    });

    test('o canto superior esquerdo vira o canto superior esquerdo', () {
      final transformer = PdfCoordinateTransformer(
        box: PdfBox.fromSize(595, 842),
      );

      final origem = transformer.pointFromTopLeft(0, 0);
      expect(origem.x, closeTo(0, 1e-9));
      expect(origem.y, closeTo(842, 1e-9));

      final fim = transformer.pointFromTopLeft(595, 842);
      expect(fim.x, closeTo(595, 1e-9));
      expect(fim.y, closeTo(0, 1e-9));
    });
  });

  group('caixa com origem deslocada — o que a conversão atual erra', () {
    test('a origem da MediaBox entra no resultado', () {
      final document = PdfDocument();
      final page = PdfPage(document, pageFormat: const PdfPageFormat(595, 842));
      // /MediaBox [20 30 615 872]: mesma largura e altura, origem deslocada.
      page.params['/MediaBox'] = PdfArray.fromNum(<double>[20, 30, 615, 872]);

      final transformer = PdfCoordinateTransformer.forPage(page);
      final novo = transformer.rectFromTopLeft(
          left: 0, top: 0, width: 100, height: 50);

      // O correto: o canto superior esquerdo da caixa é (20, 872).
      expect(novo.left, closeTo(20, 1e-9));
      expect(novo.bottom, closeTo(822, 1e-9));

      // A conversão antiga coloca o carimbo 20 pontos à esquerda e 30 abaixo
      // do lugar, porque ignora a origem da caixa.
      final antigo = legacyRectFromTopLeft(page,
          left: 0, top: 0, width: 100, height: 50);
      expect(antigo.left, 0);
      expect(antigo.bottom, closeTo(792, 1e-9));
      expect(novo.left - antigo.left, closeTo(20, 1e-9));
      expect(novo.bottom - antigo.bottom, closeTo(30, 1e-9));
    });

    test('a CropBox manda no que é visível e é recortada pela MediaBox', () {
      final document = PdfDocument();
      final page = PdfPage(document, pageFormat: const PdfPageFormat(595, 842));
      page.params['/MediaBox'] = PdfArray.fromNum(<double>[0, 0, 595, 842]);
      page.params['/CropBox'] = PdfArray.fromNum(<double>[-30, 42, 400, 700]);

      final crop = PdfCoordinateTransformer.forPage(page);
      // A CropBox extrapola a MediaBox pela esquerda; vale a interseção.
      expect(crop.box, const PdfBox(0, 42, 400, 700));
      expect(crop.displayWidth, closeTo(400, 1e-9));
      expect(crop.displayHeight, closeTo(658, 1e-9));

      final rect = crop.rectFromTopLeft(
          left: 10, top: 10, width: 100, height: 20);
      expect(rect.left, closeTo(10, 1e-9));
      expect(rect.bottom, closeTo(700 - 10 - 20, 1e-9));

      // Pedindo a MediaBox explicitamente, a área visível é outra.
      final media =
          PdfCoordinateTransformer.forPage(page, reference: PdfBoxType.media);
      expect(media.box, const PdfBox(0, 0, 595, 842));
      expect(
        media.rectFromTopLeft(left: 10, top: 10, width: 100, height: 20).bottom,
        closeTo(812, 1e-9),
      );
    });

    test('caixas ausentes herdam crop e depois media', () {
      final document = PdfDocument();
      final page = PdfPage(document, pageFormat: const PdfPageFormat(595, 842));
      page.params['/MediaBox'] = PdfArray.fromNum(<double>[0, 0, 595, 842]);
      page.params['/CropBox'] = PdfArray.fromNum(<double>[10, 10, 585, 832]);

      expect(PdfCoordinateTransformer.pageBox(page, PdfBoxType.trim),
          const PdfBox(10, 10, 585, 832));

      page.params['/TrimBox'] = PdfArray.fromNum(<double>[20, 20, 575, 822]);
      expect(PdfCoordinateTransformer.pageBox(page, PdfBoxType.trim),
          const PdfBox(20, 20, 575, 822));
      expect(PdfCoordinateTransformer.pageBox(page, PdfBoxType.art),
          const PdfBox(10, 10, 585, 832));
    });

    test('caixa invertida no arquivo é aceita', () {
      final document = PdfDocument();
      final page = PdfPage(document, pageFormat: const PdfPageFormat(595, 842));
      page.params['/MediaBox'] = PdfArray.fromNum(<double>[595, 842, 0, 0]);

      final transformer = PdfCoordinateTransformer.forPage(page);
      expect(transformer.box, const PdfBox(0, 0, 595, 842));
      expect(
        transformer.rectFromTopLeft(left: 0, top: 0, width: 10, height: 10)
            .bottom,
        closeTo(832, 1e-9),
      );
    });
  });

  group('página rotacionada — o outro caso que a conversão atual erra', () {
    test('90 graus troca largura por altura na exibição', () {
      final transformer = PdfCoordinateTransformer(
        box: PdfBox.fromSize(595, 842),
        rotation: PdfPageRotation.rotate90,
      );

      expect(transformer.displayWidth, closeTo(842, 1e-9));
      expect(transformer.displayHeight, closeTo(595, 1e-9));

      // O canto superior esquerdo do que se vê é o canto inferior esquerdo da
      // página não girada.
      final origem = transformer.pointFromTopLeft(0, 0);
      expect(origem.x, closeTo(0, 1e-9));
      expect(origem.y, closeTo(0, 1e-9));

      final rect = transformer.rectFromTopLeft(
          left: 0, top: 0, width: 100, height: 20);
      expect(rect.left, closeTo(0, 1e-9));
      expect(rect.bottom, closeTo(0, 1e-9));
      expect(rect.width, closeTo(20, 1e-9), reason: 'gira: 100 vira altura');
      expect(rect.height, closeTo(100, 1e-9));
    });

    test('a conversão antiga põe o carimbo no canto errado da página girada',
        () {
      final document = PdfDocument();
      final page = PdfPage(document,
          pageFormat: const PdfPageFormat(595, 842),
          rotate: PdfPageRotation.rotate90);
      final transformer = PdfCoordinateTransformer.forPage(page);

      final novo = transformer.rectFromTopLeft(
          left: 0, top: 0, width: 100, height: 20);
      final antigo = legacyRectFromTopLeft(page,
          left: 0, top: 0, width: 100, height: 20);

      // A antiga desenha no alto da página não girada, que depois da rotação
      // aparece na borda direita — e ainda com largura e altura trocadas.
      expect(antigo.left, 0);
      expect(antigo.bottom, closeTo(822, 1e-9));
      expect(antigo.width, 100);

      expect(novo.bottom, closeTo(0, 1e-9));
      expect(novo.width, closeTo(20, 1e-9));
      expect((novo.bottom - antigo.bottom).abs(), greaterThan(800));
    });

    test('180 graus espelha os dois eixos', () {
      final transformer = PdfCoordinateTransformer(
        box: PdfBox.fromSize(595, 842),
        rotation: PdfPageRotation.rotate180,
      );

      expect(transformer.displayWidth, closeTo(595, 1e-9));
      expect(transformer.displayHeight, closeTo(842, 1e-9));

      final origem = transformer.pointFromTopLeft(0, 0);
      expect(origem.x, closeTo(595, 1e-9));
      expect(origem.y, closeTo(0, 1e-9));

      final rect = transformer.rectFromTopLeft(
          left: 10, top: 10, width: 100, height: 20);
      expect(rect.left, closeTo(595 - 110, 1e-9));
      expect(rect.bottom, closeTo(10, 1e-9));
    });

    test('270 graus leva o topo visível para a direita da página', () {
      final transformer = PdfCoordinateTransformer(
        box: PdfBox.fromSize(595, 842),
        rotation: PdfPageRotation.rotate270,
      );

      expect(transformer.displayWidth, closeTo(842, 1e-9));
      expect(transformer.displayHeight, closeTo(595, 1e-9));

      final origem = transformer.pointFromTopLeft(0, 0);
      expect(origem.x, closeTo(595, 1e-9));
      expect(origem.y, closeTo(842, 1e-9));
    });

    test('rotação e origem deslocada juntas', () {
      final transformer = PdfCoordinateTransformer(
        box: const PdfBox(20, 30, 615, 872),
        rotation: PdfPageRotation.rotate90,
      );

      // Canto superior esquerdo do visível = canto inferior esquerdo da caixa.
      final origem = transformer.pointFromTopLeft(0, 0);
      expect(origem.x, closeTo(20, 1e-9));
      expect(origem.y, closeTo(30, 1e-9));

      final oposto =
          transformer.pointFromTopLeft(transformer.displayWidth, transformer.displayHeight);
      expect(oposto.x, closeTo(615, 1e-9));
      expect(oposto.y, closeTo(872, 1e-9));
    });

    test('ida e volta fecha em todas as rotações', () {
      for (final rotation in PdfPageRotation.values) {
        final transformer = PdfCoordinateTransformer(
          box: const PdfBox(20, 30, 615, 872),
          rotation: rotation,
        );

        for (final ponto in const <List<double>>[
          <double>[0, 0],
          <double>[13, 7],
          <double>[100, 500],
        ]) {
          final pdf = transformer.pointFromTopLeft(ponto[0], ponto[1]);
          final volta = transformer.pointToTopLeft(pdf.x, pdf.y);
          expect(volta.x, closeTo(ponto[0], 1e-9), reason: '$rotation');
          expect(volta.y, closeTo(ponto[1], 1e-9), reason: '$rotation');
        }

        final rect = transformer.rectFromTopLeft(
            left: 12, top: 34, width: 56, height: 78);
        final volta = transformer.rectToTopLeft(rect);
        expect(volta.left, closeTo(12, 1e-9), reason: '$rotation');
        expect(volta.top, closeTo(34, 1e-9), reason: '$rotation');
        expect(volta.width, closeTo(56, 1e-9), reason: '$rotation');
        expect(volta.height, closeTo(78, 1e-9), reason: '$rotation');
      }
    });
  });

  group('UserUnit', () {
    test('escala a distância entre o ponto de exibição e a unidade do usuário',
        () {
      final document = PdfDocument();
      final page = PdfPage(document, pageFormat: const PdfPageFormat(595, 842));
      page.params['/MediaBox'] = PdfArray.fromNum(<double>[0, 0, 595, 842]);
      page.params['/UserUnit'] = const PdfNum(2);

      final transformer = PdfCoordinateTransformer.forPage(page);
      expect(transformer.userUnit, 2);
      expect(transformer.displayWidth, closeTo(1190, 1e-9));
      expect(transformer.displayHeight, closeTo(1684, 1e-9));

      // 100 pontos de exibição valem 50 unidades do usuário.
      final rect = transformer.rectFromTopLeft(
          left: 100, top: 100, width: 200, height: 40);
      expect(rect.left, closeTo(50, 1e-9));
      expect(rect.width, closeTo(100, 1e-9));
      expect(rect.height, closeTo(20, 1e-9));
      expect(rect.bottom, closeTo(842 - 50 - 20, 1e-9));
    });

    test('valor ausente, zerado ou não numérico vale 1', () {
      final document = PdfDocument();
      final page = PdfPage(document, pageFormat: const PdfPageFormat(595, 842));
      expect(PdfCoordinateTransformer.pageUserUnit(page), 1);

      page.params['/UserUnit'] = const PdfNum(0);
      expect(PdfCoordinateTransformer.pageUserUnit(page), 1);

      page.params['/UserUnit'] = PdfArray.fromNum(<double>[2]);
      expect(PdfCoordinateTransformer.pageUserUnit(page), 1);
    });
  });

  group('displayTransform', () {
    test('sem rotação é só a translação até o canto do carimbo', () {
      final transformer = PdfCoordinateTransformer(
        box: PdfBox.fromSize(595, 842),
      );
      final matrix = transformer
          .displayTransform(const PdfTopLeftRect(40, 60, 200, 20));
      final storage = matrix.storage;

      expect(storage[0], closeTo(1, 1e-9));
      expect(storage[1], closeTo(0, 1e-9));
      expect(storage[4], closeTo(0, 1e-9));
      expect(storage[5], closeTo(1, 1e-9));
      expect(storage[12], closeTo(40, 1e-9), reason: 'e');
      expect(storage[13], closeTo(842 - 80, 1e-9), reason: 'f');
    });

    test('em 90 graus gira o conteúdo para ele aparecer em pé', () {
      final transformer = PdfCoordinateTransformer(
        box: PdfBox.fromSize(595, 842),
        rotation: PdfPageRotation.rotate90,
      );
      final matrix = transformer
          .displayTransform(const PdfTopLeftRect(10, 10, 100, 14));
      final storage = matrix.storage;

      // Matriz PDF [a b c d e f] = [0 1 -1 0 ...]: giro de 90° anti-horário
      // no espaço do usuário, que o leitor desfaz ao girar a página.
      expect(storage[0], closeTo(0, 1e-9), reason: 'a');
      expect(storage[1], closeTo(1, 1e-9), reason: 'b');
      expect(storage[4], closeTo(-1, 1e-9), reason: 'c');
      expect(storage[5], closeTo(0, 1e-9), reason: 'd');
      expect(storage[12], closeTo(24, 1e-9), reason: 'e');
      expect(storage[13], closeTo(10, 1e-9), reason: 'f');
    });

    test('com UserUnit a matriz também escala', () {
      final transformer = PdfCoordinateTransformer(
        box: PdfBox.fromSize(595, 842),
        userUnit: 2,
      );
      final matrix = transformer
          .displayTransform(const PdfTopLeftRect(0, 0, 100, 100));

      expect(matrix.storage[0], closeTo(0.5, 1e-9));
      expect(matrix.storage[5], closeTo(0.5, 1e-9));
    });
  });
}
