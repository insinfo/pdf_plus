import 'dart:convert';
import 'dart:typed_data';

import '../format/array.dart';
import '../format/dict.dart';
import '../format/null_value.dart';
import '../obj/page_label.dart';
import '../parsing/parser_objects.dart';
import '../parsing/parser_tokens.dart';
import '../parsing/pdf_parser_types.dart';
import '../pdf_names.dart';
import 'pdf_import_context.dart';
import 'pdf_object_importer.dart';

/// Merges what lives in the document catalog: layers, page numbering,
/// metadata and attachments.
class PdfCatalogMerger {
  PdfCatalogMerger(this.context, this.objects);

  final PdfImportContext context;
  final PdfObjectImporter objects;

  void mergeSource({required bool isFirstSource}) {
    final root = context.source.rootDict;
    if (root == null) return;

    if (context.options.importLayers) _mergeOptionalContent(root);
    if (context.options.importPageLabels) _mergePageLabels(root);
    if (context.options.importAttachments) _mergeAttachments(root);
    if (context.options.dropStructureTree) {
      // Nothing to do: `/StructParents` was already removed from the pages
      // and the tree is not copied. The warning is worth one per tagged
      // document.
      if (root.values.containsKey(PdfNameTokens.structTreeRoot)) {
        context.warn(
          'árvore de marcação estrutural (tagged PDF) descartada',
        );
      }
    } else if (isFirstSource) {
      // The pages kept `/StructParents`; without the root of the tree those
      // keys would point nowhere.
      _copyOnce(root, PdfNameTokens.structTreeRoot);
      _copyOnce(root, PdfNameTokens.markInfo);
    } else if (root.values.containsKey(PdfNameTokens.structTreeRoot)) {
      context.warn(
        'árvore de marcação estrutural descartada: só a da primeira origem é '
        'preservada',
      );
    }

    if (isFirstSource) {
      _copyOnce(root, PdfNameTokens.lang);
      if (context.options.importXmpMetadata) {
        _copyOnce(root, PdfNameTokens.metadata);
      }
      if (context.options.copyDocumentInfoFromFirst) _copyInfo();
    }
  }

  /// Hook called once, at the end of the merge.
  ///
  /// Empty today: every catalog structure is resolved as each source is
  /// imported. It stays as the place for anything that ever needs all the
  /// sources at once.
  void finish() {}

  // ---------------------------------------------------------------------------
  // Layers (optional content groups)
  // ---------------------------------------------------------------------------

  void _mergeOptionalContent(PdfDictToken root) {
    final source =
        context.source.resolve(root.values[PdfNameTokens.ocProperties]);
    if (source is! PdfDictToken) return;

    final catalogParams = context.destination.catalog.params;
    final existing = catalogParams[PdfNameTokens.ocProperties];
    final target = existing is PdfDict ? existing : PdfDict();
    if (existing is! PdfDict) {
      catalogParams[PdfNameTokens.ocProperties] = target;
    }

    _appendArray(
      target: target,
      key: PdfNameTokens.ocgs,
      source: context.source.resolve(source.values[PdfNameTokens.ocgs]),
    );

    final sourceDefault = context.source.resolve(source.values[PdfNameTokens.d]);
    if (sourceDefault is! PdfDictToken) return;

    final currentDefault = target[PdfNameTokens.d];
    final defaultConfig =
        currentDefault is PdfDict ? currentDefault : PdfDict();
    if (currentDefault is! PdfDict) target[PdfNameTokens.d] = defaultConfig;

    for (final key in const <String>[
      PdfNameTokens.order,
      PdfNameTokens.layersOn,
      PdfNameTokens.layersOff,
    ]) {
      _appendArray(
        target: defaultConfig,
        key: key,
        source: context.source.resolve(sourceDefault.values[key]),
      );
    }

    // The configuration name belongs to the destination; inheriting the
    // source one would be confusing.
    defaultConfig.values.remove(PdfNameTokens.name);
  }

  void _appendArray({
    required PdfDict target,
    required String key,
    required dynamic source,
  }) {
    if (source is! PdfArrayToken || source.values.isEmpty) return;
    final converted = objects.convertArrayCompact(source);
    if (converted.values.isEmpty) return;

    final existing = target[key];
    if (existing is PdfArray) {
      existing.values.addAll(converted.values);
    } else {
      target[key] = converted;
    }
  }

  // ---------------------------------------------------------------------------
  // Page numbering
  // ---------------------------------------------------------------------------

  void _mergePageLabels(PdfDictToken root) {
    final labels =
        context.source.resolve(root.values[PdfNameTokens.pagelabels]);
    if (labels is! PdfDictToken) return;

    final nums = context.source.resolve(labels.values[PdfNameTokens.nums]);
    if (nums is! PdfArrayToken) return;

    final offset = context.pagesBeforeSource;
    final target = context.destination.pageLabels;
    final first = _firstImportedSourcePage();

    // The ranges are indexed by their starting page; the source order is not
    // trusted, they are sorted below.
    final ranges = <int, PdfDictToken>{};
    for (var i = 0; i + 1 < nums.values.length; i += 2) {
      final index = PdfParserObjects.asInt(nums.values[i]);
      final entry = context.source.resolve(nums.values[i + 1]);
      if (index == null || entry is! PdfDictToken) continue;
      ranges[index] = entry;
    }
    if (ranges.isEmpty) return;

    final starts = ranges.keys.toList()..sort();

    // The range already in effect on the first imported page is clipped: it
    // now starts on that page, with the numbering advanced by however much was
    // left out. Without this, importing a range from the middle of the document
    // would leave the first pages without a label.
    int? covering;
    for (final start in starts) {
      if (start <= first) {
        covering = start;
      } else {
        break;
      }
    }

    if (covering != null && covering != first) {
      final label = _pageLabelFrom(ranges[covering]!, skipped: first - covering);
      if (label != null) target.labels[offset] = label;
    }

    for (final start in starts) {
      if (start < first) continue;
      if (!context.importedSourcePages.contains(start)) continue;

      final label = _pageLabelFrom(ranges[start]!);
      if (label == null) continue;

      final destIndex = offset + start - first;
      if (destIndex < 0) continue;
      target.labels[destIndex] = label;
    }
  }

  int _firstImportedSourcePage() {
    if (context.importedSourcePages.isEmpty) return 0;
    return context.importedSourcePages.reduce((a, b) => a < b ? a : b);
  }

  /// Converts a `/Nums` entry into the page label model.
  ///
  /// [skipped] is how many pages of the range were left out of the import: the
  /// numbering starts that much further ahead.
  PdfPageLabel? _pageLabelFrom(PdfDictToken entry, {int skipped = 0}) {
    final style = PdfParserObjects.asName(entry.values[PdfNameTokens.s]);
    final prefixToken = context.source.resolve(entry.values[PdfNameTokens.p]);
    final prefix =
        prefixToken is PdfStringToken ? _decode(prefixToken.bytes) : null;
    final start =
        (PdfParserObjects.asInt(entry.values[PdfNameTokens.st]) ?? 1) + skipped;

    switch (style) {
      case '/D':
        return PdfPageLabel.arabic(prefix: prefix, subsequent: start);
      case '/r':
        return PdfPageLabel.romanLower(prefix: prefix, subsequent: start);
      case '/R':
        return PdfPageLabel.romanUpper(prefix: prefix, subsequent: start);
      case '/a':
        return PdfPageLabel.lettersLower(prefix: prefix, subsequent: start);
      case '/A':
        return PdfPageLabel.lettersUpper(prefix: prefix, subsequent: start);
      default:
        if (prefix == null) return null;
        return PdfPageLabel(prefix);
    }
  }

  // ---------------------------------------------------------------------------
  // Attachments and metadata
  // ---------------------------------------------------------------------------

  void _mergeAttachments(PdfDictToken root) {
    final names = context.source.resolve(root.values[PdfNameTokens.names]);
    if (names is! PdfDictToken) return;

    final files =
        context.source.resolve(names.values[PdfNameTokens.embeddedfiles]);
    if (files is! PdfDictToken) return;

    final entries = context.source.resolve(files.values[PdfNameTokens.names]);
    if (entries is! PdfArrayToken || entries.values.isEmpty) return;

    final target = context.destination.pdfNames;
    final existing = target.params[PdfNameTokens.embeddedfiles];
    final container = existing is PdfDict ? existing : PdfDict();
    if (existing is! PdfDict) {
      target.params[PdfNameTokens.embeddedfiles] = container;
    }

    final list = container[PdfNameTokens.names];
    final array = list is PdfArray ? list : PdfArray();
    if (list is! PdfArray) container[PdfNameTokens.names] = array;

    array.values.addAll(objects.convertArrayCompact(entries).values);
  }

  void _copyOnce(PdfDictToken root, String key) {
    final catalogParams = context.destination.catalog.params;
    if (catalogParams.containsKey(key)) return;
    // A key missing in the source does not become `null` in the destination:
    // `convert(null)` returns `PdfNull`, and writing that would only add noise
    // to the catalog.
    if (!root.values.containsKey(key)) return;
    final converted = objects.convert(root.values[key]);
    if (converted == null || converted is PdfNull) return;
    catalogParams[key] = converted;
  }

  void _copyInfo() {
    final infoObj = context.source.trailer.infoObj;
    if (infoObj == null) return;
    final info = context.source.getObject(infoObj);
    if (info == null || info.value is! PdfDictToken) return;
    final dict = info.value as PdfDictToken;

    String? read(String key) {
      final value = context.source.resolve(dict.values[key]);
      if (value is PdfStringToken) return _decode(value.bytes);
      return null;
    }

    context.destination.updateInfo(
      title: read(PdfNameTokens.title),
      author: read(PdfNameTokens.author),
      creator: read(PdfNameTokens.creator),
      subject: read(PdfNameTokens.subject),
      keywords: read(PdfNameTokens.keywords),
      producer: read(PdfNameTokens.producer),
    );
  }

  String _decode(List<int> bytes) {
    try {
      return PdfParserTokens.decodePdfString(Uint8List.fromList(bytes));
    } catch (_) {
      return utf8.decode(bytes, allowMalformed: true);
    }
  }
}


