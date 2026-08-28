import '../format/array.dart';
import '../obj/page.dart';
import '../page_format.dart';
import '../parsing/parser_objects.dart';
import '../parsing/parser_pages.dart';
import '../parsing/pdf_parser_types.dart';
import '../pdf_names.dart';
import 'pdf_import_context.dart';
import 'pdf_object_importer.dart';

/// Imports pages from a source document into the destination document.
///
/// Handles what is lost when a page is detached from the tree it lived in:
/// attributes inherited from ancestor `/Pages` nodes and the box geometry.
class PdfPageImporter {
  PdfPageImporter(this.context, this.objects);

  final PdfImportContext context;
  final PdfObjectImporter objects;

  /// Page keys that are not copied straight across.
  static const _skippedKeys = <String>{
    PdfNameTokens.parent, // relinked to the destination tree
    PdfNameTokens.type, // already set by the model
    PdfNameTokens.mediaBox, // handled by the geometry
    PdfNameTokens.rotate, // ditto
    PdfNameTokens.annots, // imported on the second pass
  };

  /// Keys discarded when the structure tree is not merged.
  static const _structureKeys = <String>{
    PdfNameTokens.structParents,
    PdfNameTokens.beads,
  };

  /// Creates in the destination the page described by [pageRef].
  PdfPage import(PdfRefToken pageRef, PdfDictToken pageDict) {
    final geometry = _geometryOf(pageDict);

    final page = PdfPage(
      context.destination,
      pageFormat: geometry.format,
      rotate: geometry.rotation,
    );
    page.mediaBoxOverride = geometry.mediaBox;

    // Registered before converting the content: an annotation of the page
    // itself references the page back through `/P`.
    context.pageMap[pageRef.obj] = page;

    final skipped = <String>{
      ..._skippedKeys,
      if (context.options.dropStructureTree) ..._structureKeys,
    };

    pageDict.values.forEach((key, value) {
      if (skipped.contains(key)) return;
      final converted = objects.convert(value);
      if (converted != null) {
        page.params[key] = converted;
      }
    });

    if (!geometry.rotationIsExact) {
      // Rotation outside the multiples of 90: keep the original value instead
      // of normalizing it to zero.
      final raw = objects.convert(geometry.rawRotation);
      if (raw != null) page.params[PdfNameTokens.rotate] = raw;
    }

    _materializeInherited(page, pageDict);
    _applyBoxes(page);

    return page;
  }

  /// Brings onto the page what it used to inherit from the ancestor nodes.
  void _materializeInherited(PdfPage page, PdfDictToken pageDict) {
    if (!page.params.containsKey(PdfNameTokens.resources)) {
      final resources = context.source.resolvePageResources(pageDict);
      if (resources != null) {
        // Direct, not indirect: this is the form `PdfGraphicStream.prepare`
        // knows how to merge when something is drawn on top.
        page.params[PdfNameTokens.resources] = objects.convertDict(resources);
      }
    }

    for (final key in const <String>[
      PdfNameTokens.cropbox,
      PdfNameTokens.userUnit,
    ]) {
      if (page.params.containsKey(key)) continue;
      final inherited = context.source.inheritedPageAttribute(pageDict, key);
      if (inherited == null) continue;
      final converted = objects.convert(inherited);
      if (converted != null) page.params[key] = converted;
    }
  }

  /// Drops page boxes that are not a four-number array.
  ///
  /// A malformed `/CropBox` is worse than an absent one: the viewer would
  /// clip the page by it. The boxes that survive keep the coordinates they
  /// had in the source, which share the `/MediaBox` origin preserved by
  /// [PdfPage.mediaBoxOverride].
  void _applyBoxes(PdfPage page) {
    for (final key in const <String>[
      PdfNameTokens.cropbox,
      PdfNameTokens.bleedBox,
      PdfNameTokens.trimBox,
      PdfNameTokens.artBox,
    ]) {
      final value = page.params[key];
      if (value is! PdfArray) continue;
      if (value.values.length != 4) {
        page.params.values.remove(key);
      }
    }
  }

  _PageGeometry _geometryOf(PdfDictToken pageDict) {
    final box = context.source.resolvePageMediaBox(pageDict);
    final rawRotation =
        context.source.inheritedPageAttribute(pageDict, PdfNameTokens.rotate);
    final rotationValue = PdfParserObjects.asInt(rawRotation) ?? 0;
    final rotationIsExact = rotationValue % 90 == 0;

    final normalized = _normalizeBox(box);
    final format = normalized == null
        ? PdfPageFormat.standard
        : PdfPageFormat(
            normalized[2] - normalized[0], normalized[3] - normalized[1]);

    final hasOffset = normalized != null &&
        (normalized[0] != 0 || normalized[1] != 0);

    return _PageGeometry(
      format: format,
      rotation: PdfParserPages.pageRotationFromValue(rawRotation),
      rotationIsExact: rotationIsExact,
      rawRotation: rawRotation,
      mediaBox: hasOffset ? normalized : null,
    );
  }

  /// Sorts the box corners: PDF allows `[urx ury llx lly]`.
  List<double>? _normalizeBox(List<double>? box) {
    if (box == null || box.length < 4) return null;
    final x0 = box[0] < box[2] ? box[0] : box[2];
    final y0 = box[1] < box[3] ? box[1] : box[3];
    final x1 = box[0] < box[2] ? box[2] : box[0];
    final y1 = box[1] < box[3] ? box[3] : box[1];
    if (x1 - x0 <= 0 || y1 - y0 <= 0) return null;
    return <double>[x0, y0, x1, y1];
  }
}

class _PageGeometry {
  const _PageGeometry({
    required this.format,
    required this.rotation,
    required this.rotationIsExact,
    required this.rawRotation,
    required this.mediaBox,
  });

  final PdfPageFormat format;
  final PdfPageRotation rotation;
  final bool rotationIsExact;
  final dynamic rawRotation;

  /// Explicit box, when the origin is not (0,0).
  final List<double>? mediaBox;
}

