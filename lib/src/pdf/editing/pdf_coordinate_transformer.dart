import 'dart:math' as math;

import 'package:meta/meta.dart';

import 'package:pdf_plus/src/utils/vector_math/vector_math_64.dart';

import '../format/array.dart';
import '../format/num.dart';
import '../obj/page.dart';
import '../pdf_names.dart';
import '../point.dart';
import '../rect.dart';
import 'pdf_box.dart';

/// Rectangle in "top-left" coordinates, the system the user thinks in.
///
/// The origin sits at the upper-left corner of the visible area of the page,
/// `x` grows to the right and `y` grows downwards. The units are display
/// points (1/72 inch on the printed page), already accounting for the
/// `/UserUnit`.
@immutable
class PdfTopLeftRect {
  /// Creates the rectangle from the left edge, the top and the size.
  const PdfTopLeftRect(this.left, this.top, this.width, this.height);

  /// Distance between the visible left edge and the left edge of the rect.
  final double left;

  /// Distance between the visible top and the top of the rectangle.
  final double top;

  /// Width of the rectangle.
  final double width;

  /// Height of the rectangle.
  final double height;

  /// Right edge.
  double get right => left + width;

  /// Bottom edge.
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

/// Single conversion between "top-left" coordinates and the PDF user space.
///
/// The PDF space has its origin at the lower-left corner of the page box —
/// which is **not** necessarily `(0, 0)` — with `y` growing upwards. Whoever
/// uses the library almost always thinks in the opposite system: origin at the
/// upper-left corner of what shows on screen, `y` downwards. This class is the
/// only place that should know how to translate between the two, taking into
/// account:
///
/// - the **box origin**: `/MediaBox [20 30 615 872]` shifts everything by
///   `(20, 30)`;
/// - the **`/CropBox`**, when present: it is the one, not the `/MediaBox`,
///   that defines what the reader shows (the specification requires using the
///   intersection of the two);
/// - the **`/Rotate`** of 0, 90, 180 or 270 degrees, which rotates the page
///   clockwise on display and swaps width for height at 90 and 270;
/// - the **`/UserUnit`**, which scales the unit of the user space.
///
/// It replaces the two conversions the library used to carry —
/// `PdfDocument._rectFromTopLeft` and `PdfSignatureBounds.toPdfRect` — which
/// only did `bottom = pageFormat.height - top - height`. That is right only for
/// an unrotated page, with a box starting at `(0, 0)`, without a `/CropBox` and
/// with `/UserUnit` equal to 1; both now delegate here (roadmap item D5).
@immutable
class PdfCoordinateTransformer {
  /// Creates the transformer for a box, a rotation and a `/UserUnit`.
  ///
  /// The box is normalized on construction, so an inverted input such as
  /// `[595 842 0 0]` produces the same result as `[0 0 595 842]`.
  PdfCoordinateTransformer({
    required PdfBox box,
    this.rotation = PdfPageRotation.none,
    this.userUnit = 1.0,
  })  : box = box.normalized(),
        assert(userUnit > 0, 'The /UserUnit must be positive.');

  /// Creates the transformer of a page, new or loaded.
  ///
  /// [reference] picks the reference box; the default is [PdfBoxType.crop],
  /// which is what the reader shows. When the requested box does not exist, it
  /// falls back to the `/CropBox` and, finally, to the `/MediaBox`.
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

  /// The reference box, already normalized.
  final PdfBox box;

  /// The display rotation of the page.
  final PdfPageRotation rotation;

  /// The `/UserUnit` of the page: how many points one user unit is worth.
  final double userUnit;

  /// Rotation in degrees, clockwise on display.
  int get rotationDegrees => rotation.index * 90;

  /// Whether the rotation swaps width for height.
  bool get isQuarterTurned =>
      rotation == PdfPageRotation.rotate90 ||
      rotation == PdfPageRotation.rotate270;

  /// Width of the page as it appears, in display points.
  double get displayWidth =>
      (isQuarterTurned ? box.height : box.width) * userUnit;

  /// Height of the page as it appears, in display points.
  double get displayHeight =>
      (isQuarterTurned ? box.width : box.height) * userUnit;

  /// Converts a "top-left" point to the user space.
  PdfPoint pointFromTopLeft(double x, double y) {
    // First move from the display point to the user unit.
    final xr = x / userUnit;
    final yr = y / userUnit;

    // Then undo the rotation, reaching the top-left system of the unrotated
    // page, with origin at the upper-left corner of the box.
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

    // Finally apply the box origin and flip the y axis.
    return PdfPoint(box.left + px, box.top - py);
  }

  /// Converts a point from the user space to "top-left" coordinates.
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

  /// Converts a "top-left" rectangle to a [PdfRect] in user space.
  ///
  /// Since the rotations are multiples of 90 degrees, the rectangle stays
  /// axis-aligned; at 90 and 270 degrees width and height swap places, which
  /// is exactly what the two current converters get wrong.
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

  /// Version of [rectFromTopLeft] that takes the rectangle already built.
  PdfRect rectFromTopLeftRect(PdfTopLeftRect rect) => rectFromTopLeft(
        left: rect.left,
        top: rect.top,
        width: rect.width,
        height: rect.height,
      );

  /// Converts a rectangle from the user space to "top-left" coordinates.
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

  /// Converts a "top-left" box to a [PdfBox] in user space.
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

  /// `cm` matrix that installs a local coordinate system aligned with the
  /// display.
  ///
  /// The origin of the local system sits at the lower-left corner of the given
  /// visible rectangle, `x` grows to the right **of the screen**, `y` grows up
  /// **the screen** and the unit is the display point. This is what allows
  /// drawing a horizontal stamp even on a page with `/Rotate 90`: the content
  /// is rotated in user space by exactly as much as the reader will rotate it
  /// back.
  Matrix4 displayTransform(PdfTopLeftRect rect) {
    final origin = pointFromTopLeft(rect.left, rect.bottom);
    final scale = 1 / userUnit;
    // The display rotates clockwise; for the content to appear upright, it has
    // to rotate the same amount counter-clockwise in the user space.
    final angle = rotationDegrees * math.pi / 180;
    return Matrix4.identity()
      ..translateByDouble(origin.x, origin.y, 0, 1)
      ..rotateZ(angle)
      ..scaleByDouble(scale, scale, 1, 1);
  }

  /// The [type] box of [page], with the box inheritance rules applied.
  ///
  /// A missing box falls back to the `/CropBox` and then to the `/MediaBox`;
  /// the `/CropBox` is intersected with the `/MediaBox`, as the specification
  /// requires. A box written as an indirect reference is ignored: resolving it
  /// requires the object store from phase F1.
  static PdfBox pageBox(PdfPage page, [PdfBoxType type = PdfBoxType.media]) {
    final media = _mediaBox(page);
    if (type == PdfBoxType.media) return media;

    final crop = _clipToMedia(_declaredBox(page, PdfBoxType.crop), media);
    if (type == PdfBoxType.crop) return crop;

    final specific = _clipToMedia(_declaredBox(page, type), media);
    return specific == media ? crop : specific;
  }

  /// The `/UserUnit` of [page], or 1 when absent or invalid.
  static double pageUserUnit(PdfPage page) {
    final value = page.params[PdfNameTokens.userUnit];
    if (value is! PdfNum) return 1;
    final unit = value.value.toDouble();
    if (!unit.isFinite || unit <= 0) return 1;
    return unit;
  }


  /// The effective `/MediaBox` of the page.
  ///
  /// The page materialized by the parser does not keep `/MediaBox` in `params`
  /// — the key is filtered out and rewritten in `prepare()` from `pageFormat`
  /// or from `mediaBoxOverride`. That is why the lookup follows this same
  /// order.
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
