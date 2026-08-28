import 'dart:math' as math;

import 'package:meta/meta.dart';

import 'package:pdf_plus/src/utils/vector_math/vector_math_64.dart';

import '../format/array.dart';
import '../format/num.dart';
import '../obj/page.dart';
import '../point.dart';
import '../rect.dart';
import 'pdf_box.dart';

/// Retângulo em coordenadas "top-left", o sistema em que o usuário pensa.
///
/// A origem fica no canto superior esquerdo da área visível da página, `x`
/// cresce para a direita e `y` cresce para baixo. As unidades são pontos de
/// exibição (1/72 de polegada na página impressa), já considerando o
/// `/UserUnit`.
@immutable
class PdfTopLeftRect {
  /// Cria o retângulo a partir da borda esquerda, do topo e do tamanho.
  const PdfTopLeftRect(this.left, this.top, this.width, this.height);

  /// Distância entre a borda esquerda visível e a borda esquerda do retângulo.
  final double left;

  /// Distância entre o topo visível e o topo do retângulo.
  final double top;

  /// Largura do retângulo.
  final double width;

  /// Altura do retângulo.
  final double height;

  /// Borda direita.
  double get right => left + width;

  /// Borda inferior.
  double get bottom => top + height;

  @override
  bool operator ==(Object other) =>
      other is PdfTopLeftRect &&
      other.left == left &&
      other.top == top &&
      other.width == width &&
      other.height == height;

  @override
  int get hashCode => Object.hash(left, top, width, height);

  @override
  String toString() => 'PdfTopLeftRect($left, $top, $width, $height)';
}

/// Conversão única entre coordenadas "top-left" e o espaço do usuário do PDF.
///
/// O espaço do PDF tem origem no canto inferior esquerdo da caixa da página —
/// que **não** é necessariamente `(0, 0)` — e `y` crescendo para cima. Quem
/// usa a biblioteca quase sempre pensa no sistema oposto: origem no canto
/// superior esquerdo do que aparece na tela, `y` para baixo. Esta classe é o
/// único lugar que deve saber traduzir entre os dois, levando em conta:
///
/// - a **origem da caixa**: `/MediaBox [20 30 615 872]` desloca tudo em
///   `(20, 30)`;
/// - a **`/CropBox`**, quando presente: é ela, e não a `/MediaBox`, que define
///   o que o leitor mostra (a especificação manda usar a interseção das duas);
/// - o **`/Rotate`** de 0, 90, 180 ou 270 graus, que gira a página no sentido
///   horário na exibição e troca largura por altura em 90 e 270;
/// - o **`/UserUnit`**, que escala a unidade do espaço do usuário.
///
/// As duas conversões que existem hoje na biblioteca —
/// `PdfDocument._rectFromTopLeft` e `PdfSignatureBounds.toPdfRect` — fazem
/// apenas `bottom = pageFormat.height - top - height`. Isso acerta somente a
/// página não girada, com caixa começando em `(0, 0)`, sem `/CropBox` e com
/// `/UserUnit` igual a 1. Este transformador é o substituto previsto no
/// roteiro (item D5) para os dois.
@immutable
class PdfCoordinateTransformer {
  /// Cria o transformador para uma caixa, uma rotação e um `/UserUnit`.
  ///
  /// A caixa é normalizada na construção, de modo que uma entrada invertida
  /// como `[595 842 0 0]` produz o mesmo resultado de `[0 0 595 842]`.
  PdfCoordinateTransformer({
    required PdfBox box,
    this.rotation = PdfPageRotation.none,
    this.userUnit = 1.0,
  })  : box = box.normalized(),
        assert(userUnit > 0, 'O /UserUnit precisa ser positivo.');

  /// Cria o transformador de uma página, nova ou carregada.
  ///
  /// [reference] escolhe a caixa de referência; o padrão é [PdfBoxType.crop],
  /// que é o que o leitor mostra. Quando a caixa pedida não existe, cai para a
  /// `/CropBox` e, por fim, para a `/MediaBox`.
  factory PdfCoordinateTransformer.forPage(
    PdfPage page, {
    PdfBoxType reference = PdfBoxType.crop,
  }) {
    return PdfCoordinateTransformer(
      box: pageBox(page, reference),
      rotation: page.rotate,
      userUnit: pageUserUnit(page),
    );
  }

  /// A caixa de referência, já normalizada.
  final PdfBox box;

  /// A rotação de exibição da página.
  final PdfPageRotation rotation;

  /// O `/UserUnit` da página: quantos pontos vale uma unidade do usuário.
  final double userUnit;

  /// Rotação em graus, no sentido horário da exibição.
  int get rotationDegrees => rotation.index * 90;

  /// Se a rotação troca largura por altura.
  bool get isQuarterTurned =>
      rotation == PdfPageRotation.rotate90 ||
      rotation == PdfPageRotation.rotate270;

  /// Largura da página como ela aparece, em pontos de exibição.
  double get displayWidth =>
      (isQuarterTurned ? box.height : box.width) * userUnit;

  /// Altura da página como ela aparece, em pontos de exibição.
  double get displayHeight =>
      (isQuarterTurned ? box.width : box.height) * userUnit;

  /// Converte um ponto "top-left" para o espaço do usuário.
  PdfPoint pointFromTopLeft(double x, double y) {
    // Primeiro sai do ponto de exibição para a unidade do usuário.
    final xr = x / userUnit;
    final yr = y / userUnit;

    // Depois desfaz a rotação, chegando ao sistema top-left da página não
    // girada, com origem no canto superior esquerdo da caixa.
    final double px;
    final double py;
    switch (rotation) {
      case PdfPageRotation.none:
        px = xr;
        py = yr;
      case PdfPageRotation.rotate90:
        px = yr;
        py = box.height - xr;
      case PdfPageRotation.rotate180:
        px = box.width - xr;
        py = box.height - yr;
      case PdfPageRotation.rotate270:
        px = box.width - yr;
        py = xr;
    }

    // Por fim aplica a origem da caixa e inverte o eixo y.
    return PdfPoint(box.left + px, box.top - py);
  }

  /// Converte um ponto do espaço do usuário para coordenadas "top-left".
  PdfPoint pointToTopLeft(double x, double y) {
    final px = x - box.left;
    final py = box.top - y;

    final double xr;
    final double yr;
    switch (rotation) {
      case PdfPageRotation.none:
        xr = px;
        yr = py;
      case PdfPageRotation.rotate90:
        xr = box.height - py;
        yr = px;
      case PdfPageRotation.rotate180:
        xr = box.width - px;
        yr = box.height - py;
      case PdfPageRotation.rotate270:
        xr = py;
        yr = box.width - px;
    }

    return PdfPoint(xr * userUnit, yr * userUnit);
  }

  /// Converte um retângulo "top-left" para um [PdfRect] em espaço do usuário.
  ///
  /// Como as rotações são múltiplos de 90 graus, o retângulo continua
  /// alinhado aos eixos; em 90 e 270 graus largura e altura trocam de lugar,
  /// que é justamente o que os dois conversores atuais erram.
  PdfRect rectFromTopLeft({
    required double left,
    required double top,
    required double width,
    required double height,
  }) {
    final a = pointFromTopLeft(left, top);
    final b = pointFromTopLeft(left + width, top + height);
    return PdfRect.fromLBRT(
      math.min(a.x, b.x),
      math.min(a.y, b.y),
      math.max(a.x, b.x),
      math.max(a.y, b.y),
    );
  }

  /// Versão de [rectFromTopLeft] que recebe o retângulo já montado.
  PdfRect rectFromTopLeftRect(PdfTopLeftRect rect) => rectFromTopLeft(
        left: rect.left,
        top: rect.top,
        width: rect.width,
        height: rect.height,
      );

  /// Converte um retângulo do espaço do usuário para coordenadas "top-left".
  PdfTopLeftRect rectToTopLeft(PdfRect rect) {
    final a = pointToTopLeft(rect.left, rect.top);
    final b = pointToTopLeft(rect.right, rect.bottom);
    final left = math.min(a.x, b.x);
    final top = math.min(a.y, b.y);
    return PdfTopLeftRect(
      left,
      top,
      (a.x - b.x).abs(),
      (a.y - b.y).abs(),
    );
  }

  /// Converte uma caixa "top-left" para uma [PdfBox] em espaço do usuário.
  PdfBox boxFromTopLeft({
    required double left,
    required double top,
    required double width,
    required double height,
  }) =>
      PdfBox.fromRect(rectFromTopLeft(
        left: left,
        top: top,
        width: width,
        height: height,
      ));

  /// Matriz `cm` que instala um sistema de coordenadas local alinhado com a
  /// exibição.
  ///
  /// A origem do sistema local fica no canto inferior esquerdo do retângulo
  /// visível informado, `x` cresce para a direita **da tela**, `y` cresce para
  /// cima **da tela** e a unidade é o ponto de exibição. É o que permite
  /// desenhar um carimbo na horizontal mesmo em uma página com `/Rotate 90`:
  /// o conteúdo é girado no espaço do usuário exatamente o quanto o leitor vai
  /// girar de volta.
  Matrix4 displayTransform(PdfTopLeftRect rect) {
    final origin = pointFromTopLeft(rect.left, rect.bottom);
    final scale = 1 / userUnit;
    // A exibição gira no sentido horário; para o conteúdo aparecer em pé, ele
    // precisa girar o mesmo tanto no sentido anti-horário do espaço do usuário.
    final angle = rotationDegrees * math.pi / 180;
    return Matrix4.identity()
      ..translateByDouble(origin.x, origin.y, 0, 1)
      ..rotateZ(angle)
      ..scaleByDouble(scale, scale, 1, 1);
  }

  /// A caixa [type] de [page], com as regras de herança de caixa aplicadas.
  ///
  /// Uma caixa ausente cai para a `/CropBox` e depois para a `/MediaBox`; a
  /// `/CropBox` é interseccionada com a `/MediaBox`, como manda a
  /// especificação. Uma caixa gravada como referência indireta é ignorada:
  /// resolvê-la exige o object store da fase F1.
  static PdfBox pageBox(PdfPage page, [PdfBoxType type = PdfBoxType.media]) {
    final media = _mediaBox(page);
    if (type == PdfBoxType.media) return media;

    final crop = _clipToMedia(_declaredBox(page, PdfBoxType.crop), media);
    if (type == PdfBoxType.crop) return crop;

    final specific = _clipToMedia(_declaredBox(page, type), media);
    return specific == media ? crop : specific;
  }

  /// O `/UserUnit` de [page], ou 1 quando ausente ou inválido.
  static double pageUserUnit(PdfPage page) {
    final value = page.params[_userUnitKey];
    if (value is! PdfNum) return 1;
    final unit = value.value.toDouble();
    if (!unit.isFinite || unit <= 0) return 1;
    return unit;
  }

  /// Nome da chave `/UserUnit`, ainda ausente de `PdfNameTokens`.
  static const String _userUnitKey = '/UserUnit';

  /// A `/MediaBox` efetiva da página.
  ///
  /// A página materializada pelo parser não guarda `/MediaBox` em `params` —
  /// a chave é filtrada e reescrita no `prepare()` a partir de `pageFormat` ou
  /// de `mediaBoxOverride`. Por isso a busca segue essa mesma ordem.
  static PdfBox _mediaBox(PdfPage page) {
    final declared = PdfBox.tryFromArray(page.params[PdfBoxType.media.key]);
    if (declared != null && declared.normalized().isNotEmpty) {
      return declared.normalized();
    }

    final override = PdfBox.tryFromList(page.mediaBoxOverride);
    if (override != null && override.normalized().isNotEmpty) {
      return override.normalized();
    }

    final format = page.pageFormat;
    if (format.width.isFinite && format.height.isFinite) {
      return PdfBox.fromSize(format.width, format.height);
    }
    return PdfBox.fromSize(1, 1);
  }

  static PdfBox? _declaredBox(PdfPage page, PdfBoxType type) {
    final value = page.params[type.key];
    if (value is! PdfArray) return null;
    return PdfBox.tryFromArray(value)?.normalized();
  }

  static PdfBox _clipToMedia(PdfBox? box, PdfBox media) {
    if (box == null || box.isEmpty) return media;
    return box.intersect(media) ?? media;
  }
}
