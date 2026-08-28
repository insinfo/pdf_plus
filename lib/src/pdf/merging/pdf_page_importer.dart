import '../format/array.dart';
import '../obj/page.dart';
import '../page_format.dart';
import '../parsing/parser_objects.dart';
import '../parsing/parser_pages.dart';
import '../parsing/pdf_parser_types.dart';
import '../pdf_names.dart';
import 'pdf_import_context.dart';
import 'pdf_object_importer.dart';

/// Importa páginas de um documento de origem para o documento de destino.
///
/// Trata o que se perde ao destacar uma página da árvore em que ela vivia:
/// atributos herdados de nós `/Pages` ancestrais e a geometria da caixa.
class PdfPageImporter {
  PdfPageImporter(this.context, this.objects);

  final PdfImportContext context;
  final PdfObjectImporter objects;

  /// Chaves da página que não são copiadas diretamente.
  static const _skippedKeys = <String>{
    PdfNameTokens.parent, // religado à árvore do destino
    PdfNameTokens.type, // já definido pelo modelo
    PdfNameTokens.mediaBox, // tratado pela geometria
    PdfNameTokens.rotate, // idem
    PdfNameTokens.annots, // importado na segunda passagem
  };

  /// Chaves descartadas quando a árvore de marcação estrutural não é mesclada.
  static const _structureKeys = <String>{
    PdfNameTokens.structParents,
    PdfNameTokens.beads,
  };

  /// Cria no destino a página descrita por [pageRef].
  PdfPage import(PdfRefToken pageRef, PdfDictToken pageDict) {
    final geometry = _geometryOf(pageDict);

    final page = PdfPage(
      context.destination,
      pageFormat: geometry.format,
      rotate: geometry.rotation,
    );
    page.mediaBoxOverride = geometry.mediaBox;

    // Registrado antes de converter o conteúdo: uma anotação da própria página
    // referencia a página de volta por `/P`.
    context.pageMap[pageRef.obj] = page;

    final skipped = <String>{
      ..._skippedKeys,
      if (context.options.dropStructureTree) ..._structureKeys,
      if (geometry.rotationIsExact) PdfNameTokens.rotate,
    };

    pageDict.values.forEach((key, value) {
      if (skipped.contains(key)) return;
      final converted = objects.convert(value);
      if (converted != null) {
        page.params[key] = converted;
      }
    });

    if (!geometry.rotationIsExact) {
      // Rotação fora dos múltiplos de 90: preserva o valor original em vez de
      // normalizar para zero.
      final raw = objects.convert(geometry.rawRotation);
      if (raw != null) page.params[PdfNameTokens.rotate] = raw;
    }

    _materializeInherited(page, pageDict);
    _applyBoxes(page);

    return page;
  }

  /// Traz para a página o que ela herdava dos nós ancestrais.
  void _materializeInherited(PdfPage page, PdfDictToken pageDict) {
    if (!page.params.containsKey(PdfNameTokens.resources)) {
      final resources = context.source.resolvePageResources(pageDict);
      if (resources != null) {
        // Direto, não indireto: é o formato que `PdfGraphicStream.prepare`
        // sabe mesclar quando algo for desenhado por cima.
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

  /// Normaliza as caixas da página para a mesma origem do `/MediaBox`.
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

  /// Ordena os cantos da caixa: o PDF permite `[urx ury llx lly]`.
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

  /// Caixa explícita, quando a origem não é (0,0).
  final List<double>? mediaBox;
}

