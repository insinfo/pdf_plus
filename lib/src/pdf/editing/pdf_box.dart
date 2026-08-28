import 'dart:math' as math;

import 'package:meta/meta.dart';

import '../format/array.dart';
import '../format/base.dart';
import '../format/num.dart';
import '../pdf_names.dart';
import '../rect.dart';

/// The five page boxes defined by the PDF specification.
///
/// The declaration order follows the usual containment: `/ArtBox`, `/TrimBox`
/// and `/BleedBox` sit inside `/CropBox`, which sits inside `/MediaBox`.
enum PdfBoxType {
  /// `/MediaBox` — the physical medium. It is the only mandatory box.
  media(PdfNameTokens.mediaBox),

  /// `/CropBox` — the visible region. When absent, `/MediaBox` applies.
  crop(PdfNameTokens.cropbox),

  /// `/BleedBox` — the bleed region for print production.
  bleed(PdfNameTokens.bleedBox),

  /// `/TrimBox` — the region of the paper once trimmed.
  trim(PdfNameTokens.trimBox),

  /// `/ArtBox` — the region of meaningful content.
  art(PdfNameTokens.artBox);

  const PdfBoxType(this.key);

  /// Key name in the page dictionary, including the leading slash.
  final String key;
}

/// Page rectangle preserving the four numbers from the file.
///
/// A `PdfPageFormat` only carries a width and a height, so it cannot express
/// a box whose origin is not `(0, 0)` — the case of any PDF with
/// `/MediaBox [20 30 615 872]`. [PdfBox] keeps `llx`, `lly`, `urx` and `ury`
/// exactly as they are in the document, including when the corners come
/// inverted (`[595 842 0 0]`), which the specification allows and readers
/// normalize.
///
/// Every geometric query ([left], [width], [intersect], [contains]) answers
/// over the normalized version; only [llx], [lly], [urx], [ury], [toList] and
/// [toPdfArray] preserve the original order.
@immutable
class PdfBox {
  /// Creates the box from the four raw values, in file order.
  const PdfBox(this.llx, this.lly, this.urx, this.ury);

  /// Creates the box from the lower-left corner and the size.
  factory PdfBox.fromLBWH(
    double left,
    double bottom,
    double width,
    double height,
  ) =>
      PdfBox(left, bottom, left + width, bottom + height);

  /// Creates the box with origin at `(0, 0)` and the given size.
  factory PdfBox.fromSize(double width, double height) =>
      PdfBox(0, 0, width, height);

  /// Creates the box matching a [PdfRect] in user space.
  factory PdfBox.fromRect(PdfRect rect) =>
      PdfBox(rect.left, rect.bottom, rect.right, rect.top);

  /// Creates the box from a list of four numbers.
  ///
  /// Throws [ArgumentError] when the list does not hold exactly four finite
  /// values. For input coming from a file, prefer [tryFromList].
  factory PdfBox.fromList(List<num> values) {
    final box = tryFromList(values);
    if (box == null) {
      throw ArgumentError.value(
          values, 'values', 'Uma caixa PDF exige quatro números finitos.');
    }
    return box;
  }

  /// Creates the box from a [PdfArray] of four numbers.
  ///
  /// Throws [ArgumentError] when the array does not describe a valid box.
  factory PdfBox.fromArray(PdfArray array) {
    final box = tryFromArray(array);
    if (box == null) {
      throw ArgumentError.value(
          array, 'array', 'Uma caixa PDF exige quatro números finitos.');
    }
    return box;
  }

  /// Lenient version of [PdfBox.fromList]: returns `null` instead of throwing.
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

  /// Lenient version of [PdfBox.fromArray].
  ///
  /// Accepts any [PdfDataType]; returns `null` for anything that is not an
  /// array of four numbers — including an indirect reference, which only the
  /// object store knows how to resolve.
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

  /// X coordinate of the first corner, as it is in the file.
  final double llx;

  /// Y coordinate of the first corner, as it is in the file.
  final double lly;

  /// X coordinate of the second corner, as it is in the file.
  final double urx;

  /// Y coordinate of the second corner, as it is in the file.
  final double ury;

  /// The empty box at the origin.
  static const PdfBox zero = PdfBox(0, 0, 0, 0);

  /// Whether the corners are already in increasing order.
  bool get isNormalized => llx <= urx && lly <= ury;

  /// The same box with the corners in increasing order.
  ///
  /// `PdfBox(595, 842, 0, 0).normalized()` returns `PdfBox(0, 0, 595, 842)`.
  PdfBox normalized() =>
      isNormalized ? this : PdfBox(left, bottom, right, top);

  /// Smallest x coordinate.
  double get left => math.min(llx, urx);

  /// Smallest y coordinate.
  double get bottom => math.min(lly, ury);

  /// Largest x coordinate.
  double get right => math.max(llx, urx);

  /// Largest y coordinate.
  double get top => math.max(lly, ury);

  /// Width, always positive.
  double get width => right - left;

  /// Height, always positive.
  double get height => top - bottom;

  /// Horizontal center.
  double get horizontalCenter => left + width / 2;

  /// Vertical center.
  double get verticalCenter => bottom + height / 2;

  /// Whether the box has no area.
  bool get isEmpty => width <= 0 || height <= 0;

  /// Whether the box has area.
  bool get isNotEmpty => !isEmpty;

  /// Whether [other] is entirely contained in this box.
  bool contains(PdfBox other) =>
      other.left >= left &&
      other.bottom >= bottom &&
      other.right <= right &&
      other.top <= top;

  /// Whether the point `(x, y)` is inside this box, edges included.
  bool containsPoint(double x, double y) =>
      x >= left && x <= right && y >= bottom && y <= top;

  /// Intersection with [other], or `null` when there is no overlap with area.
  ///
  /// This is the operation used to apply the specification rule that the
  /// effective `/CropBox` is its intersection with the `/MediaBox`.
  PdfBox? intersect(PdfBox other) {
    final l = math.max(left, other.left);
    final b = math.max(bottom, other.bottom);
    final r = math.min(right, other.right);
    final t = math.min(top, other.top);
    if (l >= r || b >= t) return null;
    return PdfBox(l, b, r, t);
  }

  /// Moves the box by `(dx, dy)`, preserving the corner order.
  PdfBox translate(double dx, double dy) =>
      PdfBox(llx + dx, lly + dy, urx + dx, ury + dy);

  /// Pushes the edges out by [delta], starting from the normalized box.
  PdfBox inflate(double delta) =>
      PdfBox(left - delta, bottom - delta, right + delta, top + delta);

  /// Pulls the edges in by [delta], starting from the normalized box.
  PdfBox deflate(double delta) => inflate(-delta);

  /// The normalized box as a [PdfRect].
  PdfRect toRect() => PdfRect(left, bottom, width, height);

  /// The four values in file order.
  List<double> toList() => <double>[llx, lly, urx, ury];

  /// The four values as the array that goes into the page dictionary.
  ///
  /// The output preserves the original order: normalize first if you want to
  /// write the already-corrected box.
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
