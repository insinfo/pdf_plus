import 'dart:math' as math;

import '../color.dart';
import '../colors.dart';
import '../document.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/indirect.dart';
import '../graphics.dart';
import '../obj/font.dart';
import '../obj/image.dart';
import '../obj/object_stream.dart';
import '../obj/page.dart';
import '../pdf_names.dart';
import '../point.dart';
import 'object_graph/pdf_object_store.dart';
import 'pdf_box.dart';
import 'pdf_coordinate_transformer.dart';

/// Which layer the stamp is drawn on.
enum PdfStampLayer {
  /// After the original content: covers what was already on the page.
  overlay,

  /// Before the original content: sits underneath, as a watermark.
  underlay,
}

/// Where the stamp anchors within the visible area of the page.
enum PdfStampAnchor {
  /// Upper-left corner.
  topLeft,

  /// Center of the top.
  topCenter,

  /// Upper-right corner.
  topRight,

  /// Middle of the left edge.
  centerLeft,

  /// Center of the page.
  center,

  /// Middle of the right edge.
  centerRight,

  /// Lower-left corner.
  bottomLeft,

  /// Center of the footer.
  bottomCenter,

  /// Lower-right corner.
  bottomRight,
}

/// Stamp positioned by the [PdfCoordinateTransformer].
///
/// The subclass reports the size in [measure] and draws in [paint] on a local
/// system with origin at the lower-left corner of the stamp, `y` axis upwards
/// and unit equal to the display point. The editor takes care of rotating and
/// shifting that system to the right place in the user space, including on
/// pages with `/Rotate`, a shifted `/CropBox` or a `/UserUnit` other than 1.
abstract class PdfStamp {
  /// Configures the anchoring, the margins and the layer of the stamp.
  const PdfStamp({
    this.anchor = PdfStampAnchor.bottomRight,
    this.marginX = 24,
    this.marginY = 24,
    this.position,
    this.rotationDegrees = 0,
    this.layer = PdfStampLayer.overlay,
  });

  /// Reference corner or edge within the visible area.
  final PdfStampAnchor anchor;

  /// Horizontal distance between the stamp and the edge, in display points.
  final double marginX;

  /// Vertical distance between the stamp and the edge, in display points.
  final double marginY;

  /// Explicit upper-left corner, in "top-left" coordinates.
  ///
  /// When given, [anchor], [marginX] and [marginY] are ignored.
  final PdfPoint? position;

  /// Rotation of the stamp itself, in degrees counter-clockwise on display.
  ///
  /// Meant for the diagonal watermark. The rotation happens around the center
  /// of the stamp and does not change the area used to anchor it.
  final double rotationDegrees;

  /// Whether the stamp goes over or under the original content.
  final PdfStampLayer layer;

  /// Size of the stamp, in display points.
  PdfPoint measure(PdfDocument document);

  /// Draws the stamp on the local system described in the class documentation.
  void paint(PdfGraphics canvas, PdfPoint size);

  /// Area taken up by the stamp, in "top-left" coordinates.
  PdfTopLeftRect resolveRect(
    PdfCoordinateTransformer transformer,
    PdfPoint size,
  ) {
    final origin = position;
    if (origin != null) {
      return PdfTopLeftRect(origin.x, origin.y, size.x, size.y);
    }

    final available = PdfPoint(
      transformer.displayWidth,
      transformer.displayHeight,
    );

    final double left;
    switch (anchor) {
      case PdfStampAnchor.topLeft:
      case PdfStampAnchor.centerLeft:
      case PdfStampAnchor.bottomLeft:
        left = marginX;
      case PdfStampAnchor.topCenter:
      case PdfStampAnchor.center:
      case PdfStampAnchor.bottomCenter:
        left = (available.x - size.x) / 2;
      case PdfStampAnchor.topRight:
      case PdfStampAnchor.centerRight:
      case PdfStampAnchor.bottomRight:
        left = available.x - size.x - marginX;
    }

    final double top;
    switch (anchor) {
      case PdfStampAnchor.topLeft:
      case PdfStampAnchor.topCenter:
      case PdfStampAnchor.topRight:
        top = marginY;
      case PdfStampAnchor.centerLeft:
      case PdfStampAnchor.center:
      case PdfStampAnchor.centerRight:
        top = (available.y - size.y) / 2;
      case PdfStampAnchor.bottomLeft:
      case PdfStampAnchor.bottomCenter:
      case PdfStampAnchor.bottomRight:
        top = available.y - size.y - marginY;
    }

    return PdfTopLeftRect(left, top, size.x, size.y);
  }
}

/// Cache of the default stamp font, per document.
///
/// `PdfFont.helvetica` creates a new object on every call; without the cache,
/// a Bates numbering of two hundred pages would write two hundred equal fonts.
final Expando<PdfFont> _defaultStampFonts = Expando<PdfFont>('pdfStampFont');

/// Single-line text stamp.
class PdfTextStamp extends PdfStamp {
  /// Creates the text stamp.
  const PdfTextStamp({
    required this.text,
    this.font,
    this.fontSize = 10,
    this.color = PdfColors.black,
    this.background,
    this.borderColor,
    this.borderWidth = 0.5,
    this.padding = 0,
    super.anchor,
    super.marginX,
    super.marginY,
    super.position,
    super.rotationDegrees,
    super.layer,
  });

  /// The text to stamp.
  final String text;

  /// The font; when null, a Helvetica shared by the document.
  final PdfFont? font;

  /// Font size, in display points.
  final double fontSize;

  /// Text color.
  final PdfColor color;

  /// Background color of the stamp rectangle, or null for a transparent one.
  final PdfColor? background;

  /// Border color of the stamp rectangle, or null to draw no border.
  final PdfColor? borderColor;

  /// Border thickness.
  final double borderWidth;

  /// Space between the text and the edges of the rectangle.
  final double padding;

  /// The effective font of this stamp inside [document].
  PdfFont resolveFont(PdfDocument document) =>
      font ?? (_defaultStampFonts[document] ??= PdfFont.helvetica(document));

  @override
  PdfPoint measure(PdfDocument document) {
    final resolved = resolveFont(document);
    final width = resolved.stringMetrics(text).advanceWidth * fontSize;
    final height = resolved.emptyLineHeight * fontSize;
    return PdfPoint(width + padding * 2, height + padding * 2);
  }

  @override
  void paint(PdfGraphics canvas, PdfPoint size) {
    final resolved = resolveFont(canvas.document);

    if (background != null) {
      canvas.setFillColor(background);
      canvas.drawRect(0, 0, size.x, size.y);
      canvas.fillPath();
    }

    if (borderColor != null && borderWidth > 0) {
      canvas.setStrokeColor(borderColor);
      canvas.setLineWidth(borderWidth);
      canvas.drawRect(0, 0, size.x, size.y);
      canvas.strokePath();
    }

    canvas.setFillColor(color);
    // The baseline sits above the bottom edge by the depth of the font
    // descenders, otherwise letters such as "g" would come out clipped.
    canvas.drawString(
      resolved,
      fontSize,
      text,
      padding,
      padding + (-resolved.descent) * fontSize,
    );
  }
}

/// Image stamp.
class PdfImageStamp extends PdfStamp {
  /// Creates the image stamp.
  ///
  /// Without [width] and [height], the image takes one display point per
  /// pixel. Giving only one of the two derives the other from the original
  /// aspect ratio.
  const PdfImageStamp({
    required this.image,
    this.width,
    this.height,
    super.anchor,
    super.marginX,
    super.marginY,
    super.position,
    super.rotationDegrees,
    super.layer,
  });

  /// The image, already registered in the document.
  final PdfImage image;

  /// Wanted width, in display points.
  final double? width;

  /// Wanted height, in display points.
  final double? height;

  @override
  PdfPoint measure(PdfDocument document) {
    final naturalWidth = image.width.toDouble();
    final naturalHeight = image.height.toDouble();
    final w = width;
    final h = height;
    if (w != null && h != null) return PdfPoint(w, h);
    if (w != null) {
      return PdfPoint(w, naturalWidth == 0 ? 0 : naturalHeight * w / naturalWidth);
    }
    if (h != null) {
      return PdfPoint(
          naturalHeight == 0 ? 0 : naturalWidth * h / naturalHeight, h);
    }
    return PdfPoint(naturalWidth, naturalHeight);
  }

  @override
  void paint(PdfGraphics canvas, PdfPoint size) {
    canvas.drawImage(image, 0, 0, size.x, size.y);
  }
}

/// Overlay and underlay of content on a page, new or loaded.
///
/// ## The technique
///
/// The original content is **never touched**. The editor adds two streams to
/// the page and assembles the `/Contents` in this order:
///
/// ```text
/// [ underlays ] [ "q" ] [ original content ] [ "Q" + overlays ]
/// ```
///
/// The leading `q` and the trailing `Q` isolate the graphics state: any `cm`,
/// color, clip or line width the page left open at the outer level is
/// discarded before the stamp, and the stamp does not leak state into what
/// comes after. It is the same technique as PDFBox's `AppendMode` and the one
/// SEI uses on case PDFs (merge roadmap, §10, item 7), and it preserves the
/// byte-for-byte fidelity of the original stream — important for a document
/// that is still going to be checked against its source.
///
/// ## What needed care
///
/// `PdfPage.prepare()` always puts the existing `/Contents` **before** the
/// streams created by `getGraphics()`, so there is no way to get a prefix
/// stream just by stacking new content. The editor solves that by rewriting
/// the page `/Contents` as an array with the prefix reference in front; since
/// `prepare()` reinserts that array at the start and then calls `uniq()`,
/// which keeps the first occurrence, the final order is the wanted one and
/// saving twice neither duplicates nor reorders anything. On a new page, which
/// does not have a `/Contents` yet, the order is that of the
/// `PdfPage.contents` list itself and the editor only moves the prefix stream
/// to its start.
///
/// The consequence is that drawing done directly with `page.getGraphics()`
/// **before** creating the editor ends up inside the isolated block, together
/// with the original content; drawing done **after** lands past the stamp.
/// Whoever needs a predictable order should do all the drawing through the
/// editor.
///
/// ## Known limits
///
/// - **Resources.** The `/Resources` merging is still the one from
///   `PdfGraphicStream.prepare()`. The editor only makes sure it has a direct
///   dictionary to merge into (see `_ensureDirectResources`); it still does
///   not resolve name collisions in `/Font`, `/XObject`, `/ExtGState`,
///   `/Pattern`, `/Shading`, `/ColorSpace` and `/Properties`. In practice the
///   collision is unlikely, because the name of the new resources derives from
///   the object number, which in a loaded document starts after the last one
///   in the file. The complete handling is the `PdfResourceManager` from F4.
/// - **Transparency.** A stamp with opacity would require registering an
///   `/ExtGState` on the page, and today `prepare()` **replaces** an existing
///   direct `/ExtGState` with the reference from the document registry,
///   breaking the original content. That is why there is no opacity option:
///   the watermark is made with a light color and [PdfStamp.rotationDegrees].
/// - **`replaceContent`.** Swapping the page content requires discarding the
///   loaded `/Contents` and depends on the page collection from F3.
class PdfPageContentEditor {
  /// Creates the editor for [page].
  ///
  /// [reference] picks the box that defines the visible area used to position
  /// stamps; the default is the `/CropBox`, which is what the reader shows.
  PdfPageContentEditor(
    this.page, {
    this.reference = PdfBoxType.crop,
  }) : transformer =
            PdfCoordinateTransformer.forPage(page, reference: reference);

  /// The edited page.
  final PdfPage page;

  /// The box used as the visible area.
  final PdfBoxType reference;

  /// Coordinate converter of this page.
  final PdfCoordinateTransformer transformer;

  /// The document that owns the page.
  PdfDocument get document => page.pdfDocument;

  PdfObjectStream? _suffix;
  PdfGraphics? _suffixGraphics;
  int _underlayCount = 0;

  /// Draws over the original content.
  ///
  /// The callback receives a [PdfGraphics] in the user space of the page,
  /// already inside a `q ... Q` of its own. To position from the top of the
  /// page, use [transformer].
  void drawOverlay(void Function(PdfGraphics canvas) build) {
    _ensureWrap();
    final canvas = _suffixGraphics!;
    canvas.saveContext();
    build(canvas);
    canvas.restoreContext();
    page.altered = true;
  }

  /// Draws under the original content.
  ///
  /// Useful for a watermark: the page content stays legible on top. Successive
  /// calls stack in the order they were made, the first one furthest back.
  void drawUnderlay(void Function(PdfGraphics canvas) build) {
    _ensureWrap();
    final canvas = page.getGraphics();
    final stream = page.contents.last as PdfObjectStream;
    canvas.saveContext();
    build(canvas);
    canvas.restoreContext();
    _insertContent(stream, _underlayCount);
    _underlayCount++;
    page.altered = true;
  }

  /// Applies [stamp] to the page, on the layer it declares.
  void drawStamp(PdfStamp stamp) {
    final size = stamp.measure(document);
    final rect = stamp.resolveRect(transformer, size);
    final matrix = transformer.displayTransform(rect);

    if (stamp.rotationDegrees != 0) {
      // Rotate around the center of the stamp, without moving the anchor.
      final cx = size.x / 2;
      final cy = size.y / 2;
      matrix
        ..translateByDouble(cx, cy, 0, 1)
        ..rotateZ(stamp.rotationDegrees * math.pi / 180)
        ..translateByDouble(-cx, -cy, 0, 1);
    }

    void build(PdfGraphics canvas) {
      canvas.setTransform(matrix);
      stamp.paint(canvas, size);
    }

    if (stamp.layer == PdfStampLayer.underlay) {
      drawUnderlay(build);
    } else {
      drawOverlay(build);
    }
  }

  /// The distinct pages of [document], in document order.
  ///
  /// A loaded document registers each page twice in `pdfPageList.pages`: once
  /// by the `PdfPage` constructor and once by the parser's `mergeDocument`.
  /// Until the page collection from phase F3 exists, stamping directly over
  /// the list would draw twice on the same page and ignore half the document.
  static List<PdfPage> distinctPages(PdfDocument document) {
    final seen = <PdfPage>[];
    for (final page in document.pdfPageList.pages) {
      if (seen.any((e) => identical(e, page))) continue;
      seen.add(page);
    }
    return seen;
  }

  /// Brings the page `/Resources` into the page dictionary when it lives in an
  /// indirect object nobody materialized.
  ///
  /// `PdfGraphicStream.prepare()` knows how to merge the new resources into a
  /// direct dictionary and into an **already materialized** indirect object;
  /// when the target is a reference that still lives only in the original
  /// bytes — the case of most loaded PDFs — it replaces the reference with the
  /// new dictionary and the page loses the fonts and images it had. Copying
  /// the original dictionary into the page, preserving the indirect references
  /// of the resources themselves, avoids the loss without touching the
  /// original object, which may be shared with other pages.
  ///
  /// It is a local patch: the definitive place for this is the
  /// `PdfResourceManager` planned for F4, which still requires changing
  /// `PdfGraphicStream`.
  void _ensureDirectResources() {
    final resources = page.params[PdfNameTokens.resources];
    if (resources is! PdfIndirect) return;

    final store = PdfObjectStore.forDocument(document);
    if (store.containsId(PdfObjectId.fromIndirect(resources))) return;

    final original = store.resolveDict(resources);
    if (original == null) return;

    // Shallow copy: the values keep pointing to the same objects.
    page.params[PdfNameTokens.resources] =
        PdfDict<PdfDataType>.values(Map<String, PdfDataType>.of(original.values));
  }

  /// Creates the pair of streams that wraps the original content.
  void _ensureWrap() {
    if (_suffix != null) return;

    _ensureDirectResources();

    // Without this, `prepare()` discards the new streams of a page whose
    // content has not been changed yet by any drawing operation.
    page.altered = true;

    page.getGraphics();
    final prefix = page.contents.last as PdfObjectStream;
    prefix.buf.putString('q\n');

    final suffixGraphics = page.getGraphics();
    final suffix = page.contents.last as PdfObjectStream;
    suffix.buf.putString('Q\n');

    _suffix = suffix;
    _suffixGraphics = suffixGraphics;

    _insertContent(prefix, _underlayCount);
  }

  /// Puts [stream] at position [position] of the page content, counting from
  /// the start — that is, before the original content.
  void _insertContent(PdfObjectStream stream, int position) {
    final existing = page.params[PdfNameTokens.contents];

    if (existing == null) {
      // New page: the contents list is what dictates the order.
      page.contents.remove(stream);
      page.contents.insert(math.min(position, page.contents.length), stream);
      return;
    }

    final values = <PdfDataType>[];
    if (existing is PdfArray) {
      values.addAll(existing.values);
    } else {
      values.add(existing);
    }
    values.removeWhere((e) => e is PdfIndirect && e == stream.ref());
    values.insert(math.min(position, values.length), stream.ref());
    page.params[PdfNameTokens.contents] = PdfArray<PdfDataType>(values);
  }
}
