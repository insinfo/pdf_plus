import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/format/array.dart';
import 'package:pdf_plus/src/pdf/format/base.dart';
import 'package:pdf_plus/src/pdf/format/num.dart';
import 'package:test/test.dart';

void main() {
  group('PdfBox — o que o PdfPageFormat não consegue guardar', () {
    test('preserva os quatro números da caixa deslocada', () {
      const box = PdfBox(20, 30, 615, 872);

      expect(box.llx, 20);
      expect(box.lly, 30);
      expect(box.urx, 615);
      expect(box.ury, 872);

      // O PdfPageFormat guardaria só isto, perdendo a origem.
      expect(box.width, 595);
      expect(box.height, 842);

      // E a origem é justamente o que desloca todo o conteúdo.
      expect(box.left, 20);
      expect(box.bottom, 30);
    });

    test('fromLBWH, fromSize e fromRect concordam entre si', () {
      final fromCorners = PdfBox.fromLBWH(20, 30, 595, 842);
      expect(fromCorners, const PdfBox(20, 30, 615, 872));

      expect(PdfBox.fromSize(595, 842), const PdfBox(0, 0, 595, 842));

      expect(
        PdfBox.fromRect(const PdfRect(20, 30, 595, 842)),
        const PdfBox(20, 30, 615, 872),
      );

      // PdfRect não implementa `==`, então a comparação é campo a campo.
      final rect = const PdfBox(20, 30, 615, 872).toRect();
      expect(<double>[rect.left, rect.bottom, rect.width, rect.height],
          <double>[20, 30, 595, 842]);
    });
  });

  group('PdfBox — caixa invertida', () {
    test('reconhece que os cantos vieram fora de ordem', () {
      const inverted = PdfBox(595, 842, 0, 0);

      expect(inverted.isNormalized, isFalse);
      expect(const PdfBox(0, 0, 595, 842).isNormalized, isTrue);
    });

    test('normalized() devolve a mesma região com os cantos em ordem', () {
      const inverted = PdfBox(595, 842, 0, 0);

      expect(inverted.normalized(), const PdfBox(0, 0, 595, 842));
      expect(inverted.width, 595);
      expect(inverted.height, 842);
      expect(inverted.left, 0);
      expect(inverted.bottom, 0);
      expect(inverted.right, 595);
      expect(inverted.top, 842);
    });

    test('a inversão sobrevive a toList e toPdfArray', () {
      const inverted = PdfBox(595, 842, 0, 0);

      // Gravar a caixa de volta não pode "consertar" o arquivo por conta
      // própria: quem quiser a versão corrigida chama normalized() antes.
      expect(inverted.toList(), <double>[595, 842, 0, 0]);
      expect(
        inverted.toPdfArray().values.map((e) => e.value).toList(),
        <num>[595, 842, 0, 0],
      );
      expect(
        inverted.normalized().toList(),
        <double>[0, 0, 595, 842],
      );
    });

    test('normalized() em caixa já normalizada devolve a própria instância',
        () {
      const box = PdfBox(0, 0, 595, 842);
      expect(identical(box.normalized(), box), isTrue);
    });
  });

  group('PdfBox — construção a partir de listas e arrays', () {
    test('fromList aceita quatro números', () {
      expect(PdfBox.fromList(<double>[20, 30, 615, 872]),
          const PdfBox(20, 30, 615, 872));
      expect(PdfBox.fromList(<int>[0, 0, 612, 792]),
          const PdfBox(0, 0, 612, 792));
    });

    test('fromList recusa lista de tamanho errado ou com valor não finito', () {
      expect(() => PdfBox.fromList(<double>[0, 0, 612]), throwsArgumentError);
      expect(() => PdfBox.fromList(<double>[0, 0, 612, 792, 1]),
          throwsArgumentError);
      expect(() => PdfBox.fromList(<double>[0, 0, double.nan, 792]),
          throwsArgumentError);
      expect(() => PdfBox.fromList(<double>[0, 0, double.infinity, 792]),
          throwsArgumentError);
    });

    test('tryFromList devolve null no lugar de lançar', () {
      expect(PdfBox.tryFromList(null), isNull);
      expect(PdfBox.tryFromList(<double>[0, 0, 612]), isNull);
      expect(PdfBox.tryFromList(<double>[0, 0, 612, 792]),
          const PdfBox(0, 0, 612, 792));
    });

    test('fromArray lê o array de números do dicionário da página', () {
      final array = PdfArray.fromNum(<double>[20, 30, 615, 872]);
      expect(PdfBox.fromArray(array), const PdfBox(20, 30, 615, 872));
      expect(PdfBox.tryFromArray(array), const PdfBox(20, 30, 615, 872));
    });

    test('tryFromArray ignora o que não descreve uma caixa', () {
      expect(PdfBox.tryFromArray(null), isNull);
      expect(PdfBox.tryFromArray(PdfArray.fromNum(<double>[0, 0, 612])), isNull);
      expect(
        PdfBox.tryFromArray(PdfArray<PdfDataType>(<PdfDataType>[
          const PdfNum(0),
          const PdfNum(0),
          const PdfName('/Letter'),
          const PdfNum(792),
        ])),
        isNull,
      );
      // Uma caixa gravada como referência indireta só o object store resolve.
      expect(PdfBox.tryFromArray(const PdfNum(4)), isNull);
    });
  });

  group('PdfBox — geometria', () {
    test('intersect recorta a CropBox pela MediaBox', () {
      const media = PdfBox(0, 0, 595, 842);
      const crop = PdfBox(-10, 20, 400, 900);

      expect(crop.intersect(media), const PdfBox(0, 20, 400, 842));
      expect(media.intersect(crop), const PdfBox(0, 20, 400, 842));
    });

    test('intersect devolve null quando não há área comum', () {
      const a = PdfBox(0, 0, 100, 100);
      const b = PdfBox(200, 200, 300, 300);
      const touching = PdfBox(100, 0, 200, 100);

      expect(a.intersect(b), isNull);
      expect(a.intersect(touching), isNull, reason: 'encostar não é intersectar');
    });

    test('intersect normaliza as entradas invertidas', () {
      const inverted = PdfBox(400, 900, -10, 20);
      const media = PdfBox(0, 0, 595, 842);

      expect(inverted.intersect(media), const PdfBox(0, 20, 400, 842));
    });

    test('contains e containsPoint respondem sobre a caixa normalizada', () {
      const media = PdfBox(0, 0, 595, 842);
      const crop = PdfBox(20, 30, 400, 500);
      const outside = PdfBox(500, 800, 700, 900);

      expect(media.contains(crop), isTrue);
      expect(crop.contains(media), isFalse);
      expect(media.contains(outside), isFalse);
      expect(media.contains(media), isTrue, reason: 'a borda conta');

      expect(crop.containsPoint(21, 31), isTrue);
      expect(crop.containsPoint(20, 30), isTrue, reason: 'a borda conta');
      expect(crop.containsPoint(19, 31), isFalse);
      expect(const PdfBox(400, 500, 20, 30).containsPoint(21, 31), isTrue);
    });

    test('translate, inflate e deflate', () {
      const box = PdfBox(20, 30, 615, 872);

      expect(box.translate(10, -5), const PdfBox(30, 25, 625, 867));
      expect(box.inflate(5), const PdfBox(15, 25, 620, 877));
      expect(box.deflate(5), const PdfBox(25, 35, 610, 867));
      expect(const PdfBox(615, 872, 20, 30).translate(10, 0),
          const PdfBox(625, 872, 30, 30),
          reason: 'translate preserva a ordem original dos cantos');
    });

    test('centros, vazio e não vazio', () {
      const box = PdfBox(20, 30, 620, 830);

      expect(box.horizontalCenter, 320);
      expect(box.verticalCenter, 430);
      expect(box.isEmpty, isFalse);
      expect(box.isNotEmpty, isTrue);
      expect(const PdfBox(10, 10, 10, 40).isEmpty, isTrue);
      expect(PdfBox.zero.isEmpty, isTrue);
    });

    test('igualdade e hashCode distinguem caixas invertidas', () {
      const box = PdfBox(0, 0, 595, 842);
      const inverted = PdfBox(595, 842, 0, 0);

      expect(box, const PdfBox(0, 0, 595, 842));
      expect(box.hashCode, const PdfBox(0, 0, 595, 842).hashCode);
      expect(box == inverted, isFalse);
      expect(box, inverted.normalized());
      expect(box.toString(), 'PdfBox(0.0, 0.0, 595.0, 842.0)');
    });
  });

  group('PdfBoxType', () {
    test('cada tipo conhece a chave do dicionário da página', () {
      expect(PdfBoxType.media.key, '/MediaBox');
      expect(PdfBoxType.crop.key, '/CropBox');
      expect(PdfBoxType.bleed.key, '/BleedBox');
      expect(PdfBoxType.trim.key, '/TrimBox');
      expect(PdfBoxType.art.key, '/ArtBox');
    });
  });
}
