import 'dart:math' as math;

import 'package:meta/meta.dart';

import '../format/array.dart';
import '../format/base.dart';
import '../format/num.dart';
import '../pdf_names.dart';
import '../rect.dart';

/// As cinco caixas de página definidas pela especificação PDF.
///
/// A ordem declarada é a de contenção usual: `/ArtBox`, `/TrimBox` e
/// `/BleedBox` ficam dentro de `/CropBox`, que fica dentro de `/MediaBox`.
enum PdfBoxType {
  /// `/MediaBox` — o suporte físico. É a única caixa obrigatória.
  media(PdfNameTokens.mediaBox),

  /// `/CropBox` — a região visível. Ausente, vale a `/MediaBox`.
  crop(PdfNameTokens.cropbox),

  /// `/BleedBox` — a região de sangria para produção gráfica.
  bleed('/BleedBox'),

  /// `/TrimBox` — a região do papel já refilado.
  trim('/TrimBox'),

  /// `/ArtBox` — a região de conteúdo significativo.
  art('/ArtBox');

  const PdfBoxType(this.key);

  /// Nome da chave no dicionário da página, incluindo a barra inicial.
  ///
  /// `/BleedBox`, `/TrimBox` e `/ArtBox` ainda não existem em
  /// [PdfNameTokens]; quando forem acrescentados lá, estas constantes devem
  /// passar a referenciá-los.
  final String key;
}

/// Retângulo de página preservando os quatro números do arquivo.
///
/// Um `PdfPageFormat` só carrega largura e altura, de modo que não consegue
/// representar uma caixa cuja origem não seja `(0, 0)` — o caso de qualquer
/// PDF com `/MediaBox [20 30 615 872]`. [PdfBox] guarda `llx`, `lly`, `urx` e
/// `ury` exatamente como estão no documento, inclusive quando os cantos vêm
/// invertidos (`[595 842 0 0]`), o que a especificação permite e os
/// leitores normalizam.
///
/// Todas as consultas geométricas ([left], [width], [intersect], [contains])
/// respondem sobre a versão normalizada; só [llx], [lly], [urx], [ury],
/// [toList] e [toPdfArray] preservam a ordem original.
@immutable
class PdfBox {
  /// Cria a caixa a partir dos quatro valores crus, na ordem do arquivo.
  const PdfBox(this.llx, this.lly, this.urx, this.ury);

  /// Cria a caixa a partir do canto inferior esquerdo e do tamanho.
  factory PdfBox.fromLBWH(
    double left,
    double bottom,
    double width,
    double height,
  ) =>
      PdfBox(left, bottom, left + width, bottom + height);

  /// Cria a caixa com origem em `(0, 0)` e o tamanho informado.
  factory PdfBox.fromSize(double width, double height) =>
      PdfBox(0, 0, width, height);

  /// Cria a caixa correspondente a um [PdfRect] em espaço do usuário.
  factory PdfBox.fromRect(PdfRect rect) =>
      PdfBox(rect.left, rect.bottom, rect.right, rect.top);

  /// Cria a caixa a partir de uma lista de quatro números.
  ///
  /// Lança [ArgumentError] quando a lista não tem exatamente quatro valores
  /// finitos. Para entrada vinda de arquivo, prefira [tryFromList].
  factory PdfBox.fromList(List<num> values) {
    final box = tryFromList(values);
    if (box == null) {
      throw ArgumentError.value(
          values, 'values', 'Uma caixa PDF exige quatro números finitos.');
    }
    return box;
  }

  /// Cria a caixa a partir de um [PdfArray] de quatro números.
  ///
  /// Lança [ArgumentError] quando o array não descreve uma caixa válida.
  factory PdfBox.fromArray(PdfArray array) {
    final box = tryFromArray(array);
    if (box == null) {
      throw ArgumentError.value(
          array, 'array', 'Uma caixa PDF exige quatro números finitos.');
    }
    return box;
  }

  /// Versão tolerante de [PdfBox.fromList]: devolve `null` no lugar de lançar.
  static PdfBox? tryFromList(List<num>? values) {
    if (values == null || values.length != 4) return null;
    for (final value in values) {
      final asDouble = value.toDouble();
      if (asDouble.isNaN || asDouble.isInfinite) return null;
    }
    return PdfBox(
      values[0].toDouble(),
      values[1].toDouble(),
      values[2].toDouble(),
      values[3].toDouble(),
    );
  }

  /// Versão tolerante de [PdfBox.fromArray].
  ///
  /// Aceita qualquer [PdfDataType]; devolve `null` para o que não for um
  /// array de quatro números — inclusive para uma referência indireta, que
  /// só o object store sabe resolver.
  static PdfBox? tryFromArray(PdfDataType? value) {
    if (value is! PdfArray) return null;
    if (value.values.length != 4) return null;
    final numbers = <num>[];
    for (final item in value.values) {
      if (item is! PdfNum) return null;
      numbers.add(item.value);
    }
    return tryFromList(numbers);
  }

  /// Coordenada x do primeiro canto, como está no arquivo.
  final double llx;

  /// Coordenada y do primeiro canto, como está no arquivo.
  final double lly;

  /// Coordenada x do segundo canto, como está no arquivo.
  final double urx;

  /// Coordenada y do segundo canto, como está no arquivo.
  final double ury;

  /// A caixa vazia na origem.
  static const PdfBox zero = PdfBox(0, 0, 0, 0);

  /// Se os cantos já estão em ordem crescente.
  bool get isNormalized => llx <= urx && lly <= ury;

  /// A mesma caixa com os cantos em ordem crescente.
  ///
  /// `PdfBox(595, 842, 0, 0).normalized()` devolve `PdfBox(0, 0, 595, 842)`.
  PdfBox normalized() =>
      isNormalized ? this : PdfBox(left, bottom, right, top);

  /// Menor coordenada x.
  double get left => math.min(llx, urx);

  /// Menor coordenada y.
  double get bottom => math.min(lly, ury);

  /// Maior coordenada x.
  double get right => math.max(llx, urx);

  /// Maior coordenada y.
  double get top => math.max(lly, ury);

  /// Largura, sempre positiva.
  double get width => right - left;

  /// Altura, sempre positiva.
  double get height => top - bottom;

  /// Centro horizontal.
  double get horizontalCenter => left + width / 2;

  /// Centro vertical.
  double get verticalCenter => bottom + height / 2;

  /// Se a caixa não tem área.
  bool get isEmpty => width <= 0 || height <= 0;

  /// Se a caixa tem área.
  bool get isNotEmpty => !isEmpty;

  /// Se [other] está inteiramente contida nesta caixa.
  bool contains(PdfBox other) =>
      other.left >= left &&
      other.bottom >= bottom &&
      other.right <= right &&
      other.top <= top;

  /// Se o ponto `(x, y)` está dentro desta caixa, bordas inclusive.
  bool containsPoint(double x, double y) =>
      x >= left && x <= right && y >= bottom && y <= top;

  /// Interseção com [other], ou `null` quando não há sobreposição com área.
  ///
  /// É a operação usada para aplicar a regra da especificação de que a
  /// `/CropBox` efetiva é a interseção dela com a `/MediaBox`.
  PdfBox? intersect(PdfBox other) {
    final l = math.max(left, other.left);
    final b = math.max(bottom, other.bottom);
    final r = math.min(right, other.right);
    final t = math.min(top, other.top);
    if (l >= r || b >= t) return null;
    return PdfBox(l, b, r, t);
  }

  /// Move a caixa por `(dx, dy)`, preservando a ordem dos cantos.
  PdfBox translate(double dx, double dy) =>
      PdfBox(llx + dx, lly + dy, urx + dx, ury + dy);

  /// Afasta as bordas por [delta] a partir da caixa normalizada.
  PdfBox inflate(double delta) =>
      PdfBox(left - delta, bottom - delta, right + delta, top + delta);

  /// Aproxima as bordas por [delta] a partir da caixa normalizada.
  PdfBox deflate(double delta) => inflate(-delta);

  /// A caixa normalizada como [PdfRect].
  PdfRect toRect() => PdfRect(left, bottom, width, height);

  /// Os quatro valores na ordem do arquivo.
  List<double> toList() => <double>[llx, lly, urx, ury];

  /// Os quatro valores como o array que vai para o dicionário da página.
  ///
  /// A saída preserva a ordem original: normalize antes se quiser gravar a
  /// caixa já corrigida.
  PdfArray<PdfNum> toPdfArray() => PdfArray.fromNum(toList());

  @override
  bool operator ==(Object other) =>
      other is PdfBox &&
      other.llx == llx &&
      other.lly == lly &&
      other.urx == urx &&
      other.ury == ury;

  @override
  int get hashCode => Object.hash(llx, lly, urx, ury);

  @override
  String toString() => 'PdfBox($llx, $lly, $urx, $ury)';
}
