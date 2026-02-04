//C:\MyDartProjects\pdf_plus\lib\src\pdf\parsing\pdf_document_parser.dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:archive/archive.dart';

import '../document.dart';
import '../document_parser.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/bool.dart';
import '../format/dict.dart';
import '../format/indirect.dart';
import '../format/name.dart';
import '../format/null_value.dart';
import '../format/num.dart';
import '../format/string.dart';
import '../format/object_base.dart';
import '../io/pdf_random_access_reader.dart';
import '../obj/catalog.dart';
import '../obj/page.dart';
import '../obj/page_list.dart';
import '../page_format.dart';
import 'pdf_document_info.dart';
import 'pdf_parser_constants.dart';
import 'pdf_parser_types.dart';

/// Parser concreto para leitura de PDF existente.
///
/// Foco: robustez com PDFs do mundo real, incluindo arquivos com problemas
/// estruturais comuns (ex.: saídas antigas do iText).
class PdfDocumentParser extends PdfDocumentParserBase {
  PdfDocumentParser(
    Uint8List bytes, {
    bool enableCache = true,
    int cacheBlockSize = 256 * 1024,
    int cacheMaxBlocks = 32,
    bool allowRepair = false,
  })  : _allowRepair = allowRepair,
        super.fromBytes(
          bytes,
          enableCache: enableCache,
          cacheBlockSize: cacheBlockSize,
          cacheMaxBlocks: cacheMaxBlocks,
        );

  PdfDocumentParser.fromReader(
    PdfRandomAccessReader reader, {
    bool enableCache = true,
    int cacheBlockSize = 256 * 1024,
    int cacheMaxBlocks = 32,
    bool allowRepair = false,
  })  : _allowRepair = allowRepair,
        super(
          reader,
          enableCache: enableCache,
          cacheBlockSize: cacheBlockSize,
          cacheMaxBlocks: cacheMaxBlocks,
        );

  int? _cachedSize;
  int? _cachedXrefOffset;
  bool _xrefParsed = false;
  bool _repairAttempted = false;
  bool _fullScanIndexBuilt = false;
  bool _objStmIndexed = false;
  final bool _allowRepair;
  final Map<int, XrefEntry> _xrefEntries = <int, XrefEntry>{};
  TrailerInfo? _trailerInfo;
  final Map<int, ParsedIndirectObject> _objectCache =
      <int, ParsedIndirectObject>{};
  final Map<int, ParsedIndirectObject> _objectCacheNoStream =
      <int, ParsedIndirectObject>{};

  @override
  int get size {
    _ensureXrefParsed();
    _cachedSize ??= _computeSizeFromReader(reader, _trailerInfo);
    return _cachedSize!;
  }

  @override
  int get xrefOffset {
    _cachedXrefOffset ??= _computeXrefOffsetFromReader(reader);
    return _cachedXrefOffset!;
  }

  @override
  PdfVersion get version => PdfVersion.pdf_1_4;

  PdfDocumentInfo extractInfo({int? maxPages}) {
    _ensureXrefParsed();

    final trailer =
        _trailerInfo ?? _readTrailerInfoFromReader(reader, xrefOffset);
    final rootObjId = trailer.rootObj;
    if (rootObjId == null) {
      return const PdfDocumentInfo(
        version: '1.4',
        pageCount: 0,
        mediaBoxes: <PdfPageMediaBoxInfo>[],
        images: <PdfImageInfo>[],
      );
    }

    final rootObj = _getObjectNoStream(rootObjId) ?? _getObject(rootObjId);
    if (rootObj == null || rootObj.value is! PdfDictToken) {
      return const PdfDocumentInfo(
        version: '1.4',
        pageCount: 0,
        mediaBoxes: <PdfPageMediaBoxInfo>[],
        images: <PdfImageInfo>[],
      );
    }

    final rootDict = rootObj.value as PdfDictToken;
    final pagesRef = asRef(rootDict.values[PdfKeys.pages]);
    var pageRefs = pagesRef != null
        ? _collectPageRefs(pagesRef, maxPages: maxPages)
        : <PdfRefToken>[];

    if ((_repairAttempted || pageRefs.isEmpty) && _allowRepair) {
      pageRefs = _collectPageRefsByScan(maxPages: maxPages);
    }

    final mediaBoxes = <PdfPageMediaBoxInfo>[];
    final images = <PdfImageInfo>[];
    final useScanImages = _repairAttempted;
    for (int i = 0; i < pageRefs.length; i++) {
      final pageRef = pageRefs[i];
      final pageObj =
          _getObjectNoStream(pageRef.obj) ?? _getObject(pageRef.obj);
      if (pageObj == null || pageObj.value is! PdfDictToken) continue;
      final pageDict = pageObj.value as PdfDictToken;

      final mediaBox = _resolvePageMediaBox(pageDict);
      if (mediaBox != null) {
        mediaBoxes.add(PdfPageMediaBoxInfo(
          pageIndex: i + 1,
          pageRef: PdfIndirectRef(pageRef.obj, pageRef.gen),
          box: mediaBox,
        ));
      }

      if (!useScanImages) {
        final resDict = _resolvePageResources(pageDict);
        final xObject =
            resDict != null ? resDict.values[PdfKeys.xObject] : null;
        final xObjectDict = _resolveDictFromValueNoStream(xObject);
        if (xObjectDict != null) {
          final usedXObjects = _extractXObjectNamesFromContent(pageDict);
          for (final entry in xObjectDict.values.entries) {
            if (usedXObjects.isNotEmpty && !usedXObjects.contains(entry.key)) {
              continue;
            }
            final ref = asRef(entry.value);
            if (ref == null) continue;
            final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
            if (obj == null || obj.value is! PdfDictToken) continue;
            final dict = obj.value as PdfDictToken;
            final subtype = asName(dict.values['/Subtype']);
            if (subtype != '/Image') continue;

            final filter = _asFilterName(dict.values[PdfKeys.filter]);
            final colorSpace = _asColorSpaceName(dict.values['/ColorSpace']);
            images.add(PdfImageInfo(
              pageIndex: i + 1,
              pageRef: PdfIndirectRef(pageRef.obj, pageRef.gen),
              imageRef: PdfIndirectRef(ref.obj, ref.gen),
              width: asInt(dict.values['/Width']),
              height: asInt(dict.values['/Height']),
              bitsPerComponent: asInt(dict.values['/BitsPerComponent']),
              colorSpace: colorSpace,
              filter: filter,
            ));
          }
        }
      }
    }

    if (images.isEmpty && _allowRepair && pageRefs.isNotEmpty) {
      images.addAll(extractImages(includeUnusedXObjects: true));
    }

    final infoMap =
        trailer.infoObj != null ? _readInfoDict(trailer.infoObj!) : null;
    final infoEntry =
        trailer.infoObj != null ? _xrefEntries[trailer.infoObj!] : null;

    return PdfDocumentInfo(
      version: version.name.replaceAll('pdf_', '').replaceAll('_', '.'),
      infoRef: trailer.infoObj != null
          ? PdfIndirectRef(trailer.infoObj!, infoEntry?.gen ?? 0)
          : null,
      infoDict: infoMap,
      pageCount: pageRefs.length,
      mediaBoxes: mediaBoxes,
      images: images,
    );
  }

  /// Extrai imagens do PDF com suporte a faixa de páginas.
  ///
  /// Se [includeUnusedXObjects] for true, considera todos os XObjects da
  /// página, sem checar se foram usados no content stream.
  List<PdfImageInfo> extractImages({
    int? fromPage,
    int? toPage,
    bool includeUnusedXObjects = false,
  }) {
    _ensureXrefParsed();

    final trailer =
        _trailerInfo ?? _readTrailerInfoFromReader(reader, xrefOffset);
    final rootObjId = trailer.rootObj;
    if (rootObjId == null) return const <PdfImageInfo>[];

    final rootObj = _getObjectNoStream(rootObjId) ?? _getObject(rootObjId);
    if (rootObj == null || rootObj.value is! PdfDictToken) {
      return const <PdfImageInfo>[];
    }

    final rootDict = rootObj.value as PdfDictToken;
    final pagesRef = asRef(rootDict.values[PdfKeys.pages]);
    var pageRefs = pagesRef != null
        ? _collectPageRefs(pagesRef, maxPages: toPage)
        : <PdfRefToken>[];

    if ((_repairAttempted || pageRefs.isEmpty) && _allowRepair) {
      pageRefs = _collectPageRefsByScan(maxPages: toPage);
    }

    final images = <PdfImageInfo>[];

    for (int i = 0; i < pageRefs.length; i++) {
      final pageIndex = i + 1;
      if (fromPage != null && pageIndex < fromPage) continue;
      if (toPage != null && pageIndex > toPage) continue;

      final pageRef = pageRefs[i];
      final pageObj =
          _getObjectNoStream(pageRef.obj) ?? _getObject(pageRef.obj);
      if (pageObj == null || pageObj.value is! PdfDictToken) continue;
      final pageDict = pageObj.value as PdfDictToken;

      final resDict = _resolvePageResources(pageDict);
      final xObject = resDict != null ? resDict.values[PdfKeys.xObject] : null;
      final xObjectDict = _resolveDictFromValueNoStream(xObject);
      if (xObjectDict == null) continue;

      final usedXObjects = includeUnusedXObjects
          ? const <String>[]
          : _extractXObjectNamesFromContent(pageDict);

      for (final entry in xObjectDict.values.entries) {
        if (!includeUnusedXObjects &&
            usedXObjects.isNotEmpty &&
            !usedXObjects.contains(entry.key)) {
          continue;
        }
        final ref = asRef(entry.value);
        if (ref == null) continue;
        final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
        if (obj == null || obj.value is! PdfDictToken) continue;
        final dict = obj.value as PdfDictToken;
        final subtype = asName(dict.values['/Subtype']);
        if (subtype != '/Image') continue;

        final filter = _asFilterName(dict.values[PdfKeys.filter]);
        final colorSpace = _asColorSpaceName(dict.values['/ColorSpace']);
        images.add(PdfImageInfo(
          pageIndex: pageIndex,
          pageRef: PdfIndirectRef(pageRef.obj, pageRef.gen),
          imageRef: PdfIndirectRef(ref.obj, ref.gen),
          width: asInt(dict.values['/Width']),
          height: asInt(dict.values['/Height']),
          bitsPerComponent: asInt(dict.values['/BitsPerComponent']),
          colorSpace: colorSpace,
          filter: filter,
        ));
      }
    }

    if (images.isEmpty && _allowRepair && pageRefs.isNotEmpty) {
      final scanned = _collectImagesByScan();
      if (scanned.length == pageRefs.length) {
        for (var i = 0; i < scanned.length; i++) {
          final pageIndex = i + 1;
          if (fromPage != null && pageIndex < fromPage) continue;
          if (toPage != null && pageIndex > toPage) continue;
          final pageRef = pageRefs[i];
          final img = scanned[i];
          images.add(PdfImageInfo(
            pageIndex: pageIndex,
            pageRef: PdfIndirectRef(pageRef.obj, pageRef.gen),
            imageRef: img.imageRef,
            width: img.width,
            height: img.height,
            bitsPerComponent: img.bitsPerComponent,
            colorSpace: img.colorSpace,
            filter: img.filter,
          ));
        }
      } else {
        final firstPageRef = pageRefs.first;
        for (var i = 0; i < scanned.length; i++) {
          final pageIndex = i + 1;
          if (fromPage != null && pageIndex < fromPage) continue;
          if (toPage != null && pageIndex > toPage) continue;
          final img = scanned[i];
          images.add(PdfImageInfo(
            pageIndex: pageIndex,
            pageRef: PdfIndirectRef(firstPageRef.obj, firstPageRef.gen),
            imageRef: img.imageRef,
            width: img.width,
            height: img.height,
            bitsPerComponent: img.bitsPerComponent,
            colorSpace: img.colorSpace,
            filter: img.filter,
          ));
        }
      }
    }

    return images;
  }

  /// Lê os bytes brutos do stream de um objeto indireto.
  /// Útil para extração de imagens (retorna o stream sem decodificar filtros).
  Uint8List? readStreamData(PdfIndirectRef ref) {
    final obj = _getObject(ref.obj);
    return obj?.streamData;
  }

  /// Extrai informações de campos de assinatura (/FT /Sig).
  List<PdfSignatureFieldInfo> extractSignatureFields() {
    final editContext = extractSignatureFieldEditContext();
    if (editContext.fields.isNotEmpty) {
      return editContext.fields
          .map((field) => field.info)
          .toList(growable: false);
    }
    try {
      _ensureXrefParsed();
      final trailer =
          _trailerInfo ?? _readTrailerInfoFromReader(reader, xrefOffset);
      final rootObjId = trailer.rootObj;
      if (rootObjId == null) return const <PdfSignatureFieldInfo>[];

      final rootObj = _getObjectNoStream(rootObjId) ?? _getObject(rootObjId);
      if (rootObj == null || rootObj.value is! PdfDictToken) {
        return const <PdfSignatureFieldInfo>[];
      }
      final rootDict = rootObj.value as PdfDictToken;
      final acroForm =
          _resolveDictFromValueNoStream(rootDict.values[PdfKeys.acroForm]) ??
              _resolveDictFromValueFull(rootDict.values[PdfKeys.acroForm]);
      if (acroForm == null) return const <PdfSignatureFieldInfo>[];

      final fieldsVal = acroForm.values[PdfKeys.fields];
      final fields = _resolveArrayFromValue(fieldsVal) ??
          _resolveArrayFromValueFull(fieldsVal);
      if (fields == null) return const <PdfSignatureFieldInfo>[];

      final out = <PdfSignatureFieldInfo>[];
      final visited = <int>{};
      final pageIndexByObj = _buildPageIndexByObj(rootDict);
      for (int i = 0; i < fields.values.length; i++) {
        final item = fields.values[i];
        _collectSignatureFields(
          item,
          out,
          visited,
          pageIndexByObj: pageIndexByObj,
        );
      }
      return out;
    } catch (_) {
      return extractSignatureFieldsFromBytes(reader.readAll());
    }
  }

  /// Extrai informações completas para edição de campos de assinatura.
  ///
  /// Retorna referências e dicionários para permitir operações como renomear
  /// e remover campos usando update incremental.
  PdfSignatureFieldEditContext extractSignatureFieldEditContext() {
    try {
      _ensureXrefParsed();
      final trailer =
          _trailerInfo ?? _readTrailerInfoFromReader(reader, xrefOffset);
      final rootObjId = trailer.rootObj;
      if (rootObjId == null) {
        return const PdfSignatureFieldEditContext(
            fields: <PdfSignatureFieldObjectInfo>[]);
      }

      final rootObj = _getObjectNoStream(rootObjId) ?? _getObject(rootObjId);
      if (rootObj == null || rootObj.value is! PdfDictToken) {
        return const PdfSignatureFieldEditContext(
            fields: <PdfSignatureFieldObjectInfo>[]);
      }
      final rootDict = rootObj.value as PdfDictToken;

      final acroFormVal = rootDict.values[PdfKeys.acroForm];
      final acroFormRefToken = asRef(acroFormVal);
      final acroFormToken = _resolveDictFromValueNoStream(acroFormVal) ??
          _resolveDictFromValueFull(acroFormVal);
      if (acroFormToken == null) {
        return const PdfSignatureFieldEditContext(
            fields: <PdfSignatureFieldObjectInfo>[]);
      }

      final acroFormDict = toPdfDict(acroFormToken);
      final acroFormRef = acroFormRefToken != null
          ? PdfIndirectRef(acroFormRefToken.obj, acroFormRefToken.gen)
          : null;

      final fieldsVal = acroFormToken.values[PdfKeys.fields];
      final fieldsRefToken = asRef(fieldsVal);
      final fieldsToken = _resolveArrayFromValue(fieldsVal) ??
          _resolveArrayFromValueFull(fieldsVal);
      if (fieldsToken == null) {
        return PdfSignatureFieldEditContext(
          fields: const <PdfSignatureFieldObjectInfo>[],
          acroFormRef: acroFormRef,
          acroFormDict: acroFormDict,
          fieldsRef: fieldsRefToken != null
              ? PdfIndirectRef(fieldsRefToken.obj, fieldsRefToken.gen)
              : null,
          fieldsArray: null,
        );
      }

      final fieldsArray = toPdfArray(fieldsToken);
      final out = <PdfSignatureFieldObjectInfo>[];
      final visited = <int>{};
      final pageIndexByObj = _buildPageIndexByObj(rootDict);
      for (int i = 0; i < fieldsToken.values.length; i++) {
        final item = fieldsToken.values[i];
        _collectSignatureFieldObjects(
          item,
          out,
          visited,
          fieldIndex: i,
          pageIndexByObj: pageIndexByObj,
        );
      }

      return PdfSignatureFieldEditContext(
        fields: out,
        acroFormRef: acroFormRef,
        acroFormDict: acroFormDict,
        fieldsRef: fieldsRefToken != null
            ? PdfIndirectRef(fieldsRefToken.obj, fieldsRefToken.gen)
            : null,
        fieldsArray: fieldsArray,
      );
    } catch (_) {
      return const PdfSignatureFieldEditContext(
          fields: <PdfSignatureFieldObjectInfo>[]);
    }
  }

  List<PdfRefToken> _collectPageRefs(
    PdfRefToken rootRef, {
    int? maxPages,
  }) {
    final pages = <PdfRefToken>[];
    final stack = <PdfRefToken>[rootRef];
    final visited = <int>{};

    while (stack.isNotEmpty) {
      final ref = stack.removeLast();
      if (visited.contains(ref.obj)) continue;
      visited.add(ref.obj);

      final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
      if (obj == null || obj.value is! PdfDictToken) continue;
      final dict = obj.value as PdfDictToken;
      final type = asName(dict.values[PdfKeys.type]);

      if (type == '/Page' || dict.values.containsKey(PdfKeys.contents)) {
        pages.add(ref);
        if (maxPages != null && pages.length >= maxPages) break;
        continue;
      }

      if (type == PdfKeys.pages || dict.values.containsKey(PdfKeys.kids)) {
        final kids = dict.values[PdfKeys.kids];
        if (kids is PdfArrayToken) {
          for (final item in kids.values) {
            final kidRef = asRef(item);
            if (kidRef != null) stack.add(kidRef);
          }
        }
      }
    }

    return pages;
  }

  PdfDictToken? _resolvePageResources(PdfDictToken pageDict) {
    final direct =
        _resolveDictFromValueNoStream(pageDict.values[PdfKeys.resources]);
    PdfDictToken? parentRes;
    var parentVal = pageDict.values['/Parent'];
    for (int depth = 0; depth < 32; depth++) {
      final parentRef = asRef(parentVal);
      if (parentRef == null) break;
      final parentObj =
          _getObjectNoStream(parentRef.obj) ?? _getObject(parentRef.obj);
      if (parentObj == null || parentObj.value is! PdfDictToken) break;
      final parentDict = parentObj.value as PdfDictToken;
      parentRes =
          _resolveDictFromValueNoStream(parentDict.values[PdfKeys.resources]);
      if (parentRes != null) break;
      parentVal = parentDict.values['/Parent'];
    }

    if (direct == null) return parentRes;
    if (parentRes == null) return direct;
    return _mergeResourceDicts(parentRes, direct);
  }

  PdfDictToken _mergeResourceDicts(
    PdfDictToken parentRes,
    PdfDictToken childRes,
  ) {
    final merged = <String, dynamic>{}
      ..addAll(parentRes.values)
      ..addAll(childRes.values);

    final parentXObj =
        _resolveDictFromValueNoStream(parentRes.values[PdfKeys.xObject]);
    final childXObj =
        _resolveDictFromValueNoStream(childRes.values[PdfKeys.xObject]);
    if (parentXObj != null || childXObj != null) {
      final xValues = <String, dynamic>{};
      if (parentXObj != null) xValues.addAll(parentXObj.values);
      if (childXObj != null) xValues.addAll(childXObj.values);
      merged[PdfKeys.xObject] = PdfDictToken(xValues);
    }

    return PdfDictToken(merged);
  }

  List<double>? _resolvePageMediaBox(PdfDictToken pageDict) {
    final direct = asNumArray(pageDict.values[PdfKeys.mediaBox]) ??
        asNumArray(pageDict.values['/CropBox']);
    if (direct != null) return direct;
    var parentVal = pageDict.values['/Parent'];
    for (int depth = 0; depth < 32; depth++) {
      final parentRef = asRef(parentVal);
      if (parentRef == null) break;
      final parentObj =
          _getObjectNoStream(parentRef.obj) ?? _getObject(parentRef.obj);
      if (parentObj == null || parentObj.value is! PdfDictToken) break;
      final parentDict = parentObj.value as PdfDictToken;
      final box = asNumArray(parentDict.values[PdfKeys.mediaBox]) ??
          asNumArray(parentDict.values['/CropBox']);
      if (box != null) return box;
      parentVal = parentDict.values['/Parent'];
    }
    return null;
  }

  List<PdfRefToken> _collectPageRefsByScan({int? maxPages}) {
    _ensureFullScanIndexBuilt();
    final ids = _xrefEntries.keys.toList()..sort();
    final out = <PdfRefToken>[];
    for (final objId in ids) {
      final obj = _getObjectNoStream(objId) ?? _getObject(objId);
      if (obj == null || obj.value is! PdfDictToken) continue;
      final dict = obj.value as PdfDictToken;
      final type = asName(dict.values[PdfKeys.type]);
      final looksLikePage = type == '/Page' ||
          (dict.values.containsKey(PdfKeys.mediaBox) &&
              dict.values.containsKey(PdfKeys.contents));
      if (!looksLikePage) continue;
      out.add(PdfRefToken(obj.objId, obj.gen));
      if (maxPages != null && out.length >= maxPages) break;
    }
    return out;
  }

  List<ImageScanInfo> _collectImagesByScan() {
    _ensureFullScanIndexBuilt();
    final entries = <({int offset, ImageScanInfo info})>[];
    for (final entry in _xrefEntries.entries) {
      if (entry.value.type != XrefType.inUse) continue;
      final objId = entry.key;
      final obj = _getObjectNoStream(objId) ?? _getObject(objId);
      if (obj == null || obj.value is! PdfDictToken) continue;
      final dict = obj.value as PdfDictToken;
      final subtype = asName(dict.values['/Subtype']);
      if (subtype != '/Image') continue;
      final filter = _asFilterName(dict.values[PdfKeys.filter]);
      final colorSpace = _asColorSpaceName(dict.values['/ColorSpace']);
      entries.add((
        offset: entry.value.offset,
        info: ImageScanInfo(
          imageRef: PdfIndirectRef(obj.objId, obj.gen),
          width: asInt(dict.values['/Width']),
          height: asInt(dict.values['/Height']),
          bitsPerComponent: asInt(dict.values['/BitsPerComponent']),
          colorSpace: colorSpace,
          filter: filter,
        ),
      ));
    }
    entries.sort((a, b) => a.offset.compareTo(b.offset));
    return entries.map((e) => e.info).toList();
  }

  PdfDictToken? _resolveDictFromValueNoStream(dynamic value) {
    if (value is PdfDictToken) return value;
    final ref = asRef(value);
    if (ref == null) return null;
    final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
    if (obj == null || obj.value is! PdfDictToken) return null;
    return obj.value as PdfDictToken;
  }

  PdfDictToken? _resolveDictFromValueFull(dynamic value) {
    if (value is PdfDictToken) return value;
    final ref = asRef(value);
    if (ref == null) return null;
    final obj = _getObject(ref.obj) ?? _getObjectNoStream(ref.obj);
    if (obj == null || obj.value is! PdfDictToken) return null;
    return obj.value as PdfDictToken;
  }

  PdfArrayToken? _resolveArrayFromValue(dynamic value) {
    if (value is PdfArrayToken) return value;
    final ref = asRef(value);
    if (ref == null) return null;
    final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
    if (obj == null || obj.value is! PdfArrayToken) return null;
    return obj.value as PdfArrayToken;
  }

  PdfArrayToken? _resolveArrayFromValueFull(dynamic value) {
    if (value is PdfArrayToken) return value;
    final ref = asRef(value);
    if (ref == null) return null;
    final obj = _getObject(ref.obj) ?? _getObjectNoStream(ref.obj);
    if (obj == null || obj.value is! PdfArrayToken) return null;
    return obj.value as PdfArrayToken;
  }

  void _collectSignatureFields(
    dynamic value,
    List<PdfSignatureFieldInfo> out,
    Set<int> visited, {
    String? inheritedName,
    String? inheritedFieldType,
    Map<int, int>? pageIndexByObj,
  }) {
    if (value is PdfRefToken) {
      if (!visited.add(value.obj)) return;
      final obj = _getObjectNoStream(value.obj) ?? _getObject(value.obj);
      if (obj == null || obj.value is! PdfDictToken) return;
      _collectSignatureFields(
        obj.value,
        out,
        visited,
        inheritedName: inheritedName,
        inheritedFieldType: inheritedFieldType,
        pageIndexByObj: pageIndexByObj,
      );
      return;
    }

    if (value is! PdfDictToken) return;
    final dict = value;

    final ownName = _asString(dict.values['/T']);
    final resolvedName = ownName ?? inheritedName;

    final kidsVal = dict.values[PdfKeys.kids];
    final kids = _resolveArrayFromValue(kidsVal);
    if (kids != null) {
      for (final kid in kids.values) {
        _collectSignatureFields(
          kid,
          out,
          visited,
          inheritedName: resolvedName,
          inheritedFieldType: asName(dict.values['/FT']) ?? inheritedFieldType,
          pageIndexByObj: pageIndexByObj,
        );
      }
    }

    final fieldType = asName(dict.values['/FT']) ?? inheritedFieldType;
    final fieldName = resolvedName;

    dynamic sigVal = dict.values['/V'];
    if (sigVal is PdfRefToken) {
      final sigObj = _getObjectNoStream(sigVal.obj) ?? _getObject(sigVal.obj);
      sigVal = sigObj?.value;
    }

    if (sigVal is! PdfDictToken) {
      if (fieldType != PdfKeys.sig) return;
      final pageRef = _findPageRefFromField(dict);
      final pageIndex = (pageRef != null && pageIndexByObj != null)
          ? pageIndexByObj[pageRef.obj]
          : null;
      final rect = _findRectFromField(dict);
      out.add(PdfSignatureFieldInfo(
        fieldName: fieldName,
        pageRef:
            pageRef != null ? PdfIndirectRef(pageRef.obj, pageRef.gen) : null,
        pageIndex: pageIndex,
        rect: rect,
        signatureDictionaryPresent: false,
      ));
      return;
    }

    if (fieldType != PdfKeys.sig &&
        asName(sigVal.values[PdfKeys.type]) != PdfKeys.sig) {
      return;
    }

    final reason = _asString(sigVal.values[PdfKeys.reason]) ??
        _asString(dict.values[PdfKeys.reason]);
    final location = _asString(sigVal.values[PdfKeys.location]) ??
        _asString(dict.values[PdfKeys.location]);
    final name = _asString(sigVal.values[PdfKeys.name]) ??
        _asString(dict.values[PdfKeys.name]);
    final signingTime = _asString(sigVal.values[PdfKeys.m]) ??
        _asString(dict.values[PdfKeys.m]);
    final filter = asName(sigVal.values[PdfKeys.filter]) ??
        asName(dict.values[PdfKeys.filter]);
    final subFilter = asName(sigVal.values[PdfKeys.subFilter]);
    final byteRange = asIntArray(sigVal.values[PdfKeys.byteRange]);
    final pageRef = _findPageRefFromField(dict);
    final pageIndex = (pageRef != null && pageIndexByObj != null)
        ? pageIndexByObj[pageRef.obj]
        : null;
    final rect = _findRectFromField(dict);

    out.add(PdfSignatureFieldInfo(
      fieldName: fieldName,
      reason: reason,
      location: location,
      name: name,
      signingTimeRaw: signingTime,
      filter: filter,
      subFilter: subFilter,
      byteRange: byteRange,
      pageRef:
          pageRef != null ? PdfIndirectRef(pageRef.obj, pageRef.gen) : null,
      pageIndex: pageIndex,
      rect: rect,
      signatureDictionaryPresent: true,
    ));
  }

  void _collectSignatureFieldObjects(
    dynamic value,
    List<PdfSignatureFieldObjectInfo> out,
    Set<int> visited, {
    String? inheritedName,
    int? fieldIndex,
    String? inheritedFieldType,
    Map<int, int>? pageIndexByObj,
  }) {
    PdfIndirectRef? fieldRef;
    PdfDictToken? fieldDictToken;

    if (value is PdfRefToken) {
      if (!visited.add(value.obj)) return;
      fieldRef = PdfIndirectRef(value.obj, value.gen);
      final obj = _getObjectNoStream(value.obj) ?? _getObject(value.obj);
      if (obj == null || obj.value is! PdfDictToken) return;
      fieldDictToken = obj.value as PdfDictToken;
    } else if (value is PdfDictToken) {
      fieldDictToken = value;
    } else {
      return;
    }

    final dict = fieldDictToken;

    final ownName = _asString(dict.values['/T']);
    final resolvedName = ownName ?? inheritedName;

    final kidsVal = dict.values[PdfKeys.kids];
    final kids = _resolveArrayFromValue(kidsVal);
    if (kids != null) {
      for (final kid in kids.values) {
        _collectSignatureFieldObjects(
          kid,
          out,
          visited,
          inheritedName: resolvedName,
          fieldIndex: fieldIndex,
          inheritedFieldType: asName(dict.values['/FT']) ?? inheritedFieldType,
          pageIndexByObj: pageIndexByObj,
        );
      }
    }

    final fieldType = asName(dict.values['/FT']) ?? inheritedFieldType;
    final fieldName = resolvedName;

    dynamic sigVal = dict.values['/V'];
    PdfIndirectRef? sigRef;
    PdfDictToken? sigDictToken;
    if (sigVal is PdfRefToken) {
      sigRef = PdfIndirectRef(sigVal.obj, sigVal.gen);
      final sigObj = _getObjectNoStream(sigVal.obj) ?? _getObject(sigVal.obj);
      if (sigObj != null && sigObj.value is PdfDictToken) {
        sigDictToken = sigObj.value as PdfDictToken;
      }
    } else if (sigVal is PdfDictToken) {
      sigDictToken = sigVal;
    }

    if (fieldType != PdfKeys.sig &&
        asName(sigDictToken?.values[PdfKeys.type]) != PdfKeys.sig) {
      return;
    }

    final reason = sigDictToken != null
        ? (_asString(sigDictToken.values[PdfKeys.reason]) ??
            _asString(dict.values[PdfKeys.reason]))
        : _asString(dict.values[PdfKeys.reason]);
    final location = sigDictToken != null
        ? (_asString(sigDictToken.values[PdfKeys.location]) ??
            _asString(dict.values[PdfKeys.location]))
        : _asString(dict.values[PdfKeys.location]);
    final name = sigDictToken != null
        ? (_asString(sigDictToken.values[PdfKeys.name]) ??
            _asString(dict.values[PdfKeys.name]))
        : _asString(dict.values[PdfKeys.name]);
    var signingTime = sigDictToken != null
        ? (_asString(sigDictToken.values[PdfKeys.m]) ??
            _asString(dict.values[PdfKeys.m]))
        : _asString(dict.values[PdfKeys.m]);
    if (signingTime == null && sigRef != null) {
      signingTime = _tryReadPdfDateFromObject(sigRef.obj, sigRef.gen);
    }
    var filter = sigDictToken != null
        ? (asName(sigDictToken.values[PdfKeys.filter]) ??
            asName(dict.values[PdfKeys.filter]))
        : asName(dict.values[PdfKeys.filter]);
    var subFilter = sigDictToken != null
        ? asName(sigDictToken.values[PdfKeys.subFilter])
        : null;
    if (subFilter == null && sigRef != null) {
      subFilter = _tryReadNameFromObject(sigRef.obj, sigRef.gen, 'SubFilter');
    }
    if (filter == null && sigRef != null) {
      filter = _tryReadNameFromObject(sigRef.obj, sigRef.gen, 'Filter');
    }
    var byteRange = sigDictToken != null
        ? asIntArray(sigDictToken.values[PdfKeys.byteRange])
        : null;
    if (byteRange == null && sigRef != null) {
      byteRange = _tryReadByteRangeFromObject(sigRef.obj, sigRef.gen);
    }
    final pageRef = _findPageRefFromField(dict);
    final pageIndex = (pageRef != null && pageIndexByObj != null)
        ? pageIndexByObj[pageRef.obj]
        : null;
    final rect = _findRectFromField(dict);

    out.add(PdfSignatureFieldObjectInfo(
      info: PdfSignatureFieldInfo(
        fieldName: fieldName,
        reason: reason,
        location: location,
        name: name,
        signingTimeRaw: signingTime,
        filter: filter,
        subFilter: subFilter,
        byteRange: byteRange,
        pageRef:
            pageRef != null ? PdfIndirectRef(pageRef.obj, pageRef.gen) : null,
        pageIndex: pageIndex,
        rect: rect,
        signatureDictionaryPresent: sigDictToken != null || sigRef != null,
      ),
      fieldRef: fieldRef,
      fieldDict: toPdfDict(dict),
      fieldIndex: fieldRef == null ? fieldIndex : null,
      isDirect: fieldRef == null,
      signatureRef: sigRef,
      signatureDict: sigDictToken != null ? toPdfDict(sigDictToken) : null,
    ));
  }

  Map<int, int> _buildPageIndexByObj(PdfDictToken rootDict) {
    final pagesRef = asRef(rootDict.values[PdfKeys.pages]);
    if (pagesRef == null) return const <int, int>{};
    final pageRefs = _collectPageRefs(pagesRef);
    final out = <int, int>{};
    for (int i = 0; i < pageRefs.length; i++) {
      out[pageRefs[i].obj] = i + 1;
    }
    return out;
  }

  PdfRefToken? _findPageRefFromField(PdfDictToken dict) {
    final direct = asRef(dict.values[PdfKeys.p]);
    if (direct != null) return direct;
    final kids = _resolveArrayFromValue(dict.values[PdfKeys.kids]);
    if (kids == null) return null;
    for (final kid in kids.values) {
      final kidDict = _resolveDictFromValueNoStream(kid);
      if (kidDict == null) continue;
      final p = asRef(kidDict.values[PdfKeys.p]);
      if (p != null) return p;
    }
    return null;
  }

  List<double>? _findRectFromField(PdfDictToken dict) {
    final direct = asNumArray(dict.values[PdfKeys.rect]);
    if (direct != null) return direct;
    final kids = _resolveArrayFromValue(dict.values[PdfKeys.kids]);
    if (kids == null) return null;
    for (final kid in kids.values) {
      final kidDict = _resolveDictFromValueNoStream(kid);
      if (kidDict == null) continue;
      final rect = asNumArray(kidDict.values[PdfKeys.rect]);
      if (rect != null) return rect;
    }
    return null;
  }

  List<int>? _tryReadByteRangeFromObject(int objId, int gen) {
    try {
      final bytes = reader.readAll();
      final header = ascii.encode('$objId $gen obj');
      final start = indexOfSequence(bytes, header, 0, bytes.length);
      if (start == -1) return null;

      final endObjToken = ascii.encode('endobj');
      final searchStart = start + header.length;
      final endObj =
          indexOfSequence(bytes, endObjToken, searchStart, bytes.length);
      final end = endObj == -1 ? bytes.length : endObj;

      const byteRangeToken = <int>[
        0x2F, // /
        0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65, // ByteRange
      ];
      final pos = indexOfSequence(bytes, byteRangeToken, searchStart, end);
      if (pos == -1) return null;

      int i = pos + byteRangeToken.length;
      i = skipPdfWsAndComments(bytes, i, end);
      while (i < end && bytes[i] != 0x5B /* [ */) {
        i++;
      }
      if (i >= end) return null;
      i++;

      final values = <int>[];
      for (int k = 0; k < 4; k++) {
        i = skipPdfWsAndComments(bytes, i, end);
        final parsed = readInt(bytes, i, end);
        values.add(parsed.value);
        i = parsed.nextIndex;
      }
      return values;
    } catch (_) {
      return null;
    }
  }

  String? _tryReadPdfDateFromObject(int objId, int gen) {
    try {
      final bytes = reader.readAll();
      final header = ascii.encode('$objId $gen obj');
      final start = indexOfSequence(bytes, header, 0, bytes.length);
      if (start == -1) return null;

      final endObjToken = ascii.encode('endobj');
      final searchStart = start + header.length;
      final endObj =
          indexOfSequence(bytes, endObjToken, searchStart, bytes.length);
      final end = endObj == -1 ? bytes.length : endObj;

      const token = <int>[0x2F, 0x4D]; // /M
      final pos = indexOfSequence(bytes, token, searchStart, end);
      if (pos == -1) return null;

      int i = pos + token.length;
      i = skipPdfWsAndComments(bytes, i, end);
      if (i >= end) return null;

      if (bytes[i] == 0x28 /* ( */) {
        final parsed = readLiteralString(bytes, i, end);
        if (parsed.bytes.isEmpty) return null;
        return ascii.decode(parsed.bytes);
      }
      if (bytes[i] == 0x3C /* < */) {
        final parsed = readHexString(bytes, i, end);
        if (parsed.bytes.isEmpty) return null;
        return ascii.decode(parsed.bytes);
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  String? _tryReadNameFromObject(int objId, int gen, String key) {
    try {
      final bytes = reader.readAll();
      final header = ascii.encode('$objId $gen obj');
      final start = indexOfSequence(bytes, header, 0, bytes.length);
      if (start == -1) return null;

      final endObjToken = ascii.encode('endobj');
      final searchStart = start + header.length;
      final endObj =
          indexOfSequence(bytes, endObjToken, searchStart, bytes.length);
      final end = endObj == -1 ? bytes.length : endObj;

      final token = ascii.encode('/$key');
      final pos = indexOfSequence(bytes, token, searchStart, end);
      if (pos == -1) return null;

      int i = pos + token.length;
      i = skipPdfWsAndComments(bytes, i, end);
      if (i >= end) return null;
      if (bytes[i] != 0x2F /* / */) return null;
      i++;

      final startName = i;
      while (i < end) {
        final b = bytes[i];
        if (isWhitespace(b) ||
            b == 0x2F ||
            b == 0x3E ||
            b == 0x3C ||
            b == 0x5B ||
            b == 0x5D) {
          break;
        }
        i++;
      }
      if (i <= startName) return null;
      final name = ascii.decode(bytes.sublist(startName, i));
      return '/$name';
    } catch (_) {
      return null;
    }
  }

  String? _asFilterName(dynamic value) {
    final resolved = _resolveValueNoStream(value);
    PdfNameToken? name;
    if (resolved is PdfNameToken) {
      name = resolved;
    } else if (resolved is PdfArrayToken && resolved.values.isNotEmpty) {
      final first = resolved.values.first;
      if (first is PdfNameToken) name = first;
    }
    if (name == null) return null;
    switch (name.value) {
      case '/DCTDecode':
        return 'DCT';
      case '/JPXDecode':
        return 'JPX';
      case '/JBIG2Decode':
        return 'JBIG2';
      case '/FlateDecode':
        return 'Flate';
      default:
        return name.value.startsWith('/')
            ? name.value.substring(1)
            : name.value;
    }
  }

  String? _asColorSpaceName(dynamic value) {
    final resolved = _resolveValueNoStream(value);
    if (resolved is PdfNameToken) {
      return _normalizeColorSpaceName(resolved.value);
    }
    if (resolved is PdfArrayToken && resolved.values.isNotEmpty) {
      final first = resolved.values.first;
      if (first is PdfNameToken) {
        return _normalizeColorSpaceName(first.value);
      }
    }
    return null;
  }

  String _normalizeColorSpaceName(String name) {
    final raw = name.startsWith('/') ? name.substring(1) : name;
    switch (raw) {
      case 'DeviceRGB':
        return 'DevRGB';
      case 'DeviceGray':
        return 'DevGray';
      case 'DeviceCMYK':
        return 'DevCMYK';
      default:
        return raw;
    }
  }

  List<String> _asFilterNames(dynamic value) {
    final resolved = _resolveValueNoStream(value);
    final out = <String>[];
    if (resolved is PdfNameToken) {
      out.add(_normalizeFilterName(resolved.value));
    } else if (resolved is PdfArrayToken) {
      for (final item in resolved.values) {
        if (item is PdfNameToken) {
          out.add(_normalizeFilterName(item.value));
        }
      }
    }
    return out;
  }

  String _normalizeFilterName(String name) {
    final raw = name.startsWith('/') ? name.substring(1) : name;
    switch (raw) {
      case 'FlateDecode':
        return 'Flate';
      case 'ASCII85Decode':
        return 'ASCII85';
      case 'LZWDecode':
        return 'LZW';
      default:
        return raw;
    }
  }

  Uint8List _decodeAscii85(Uint8List data) {
    final out = <int>[];
    int count = 0;
    int value = 0;
    for (int i = 0; i < data.length; i++) {
      final b = data[i];
      if (b == 0x7E) break; // ~ end
      if (b == 0x7A) {
        // z
        if (count != 0) continue;
        out.addAll(const [0, 0, 0, 0]);
        continue;
      }
      if (b <= 0x20) continue;
      if (b < 0x21 || b > 0x75) continue;
      value = value * 85 + (b - 0x21);
      count++;
      if (count == 5) {
        out.add((value >> 24) & 0xFF);
        out.add((value >> 16) & 0xFF);
        out.add((value >> 8) & 0xFF);
        out.add(value & 0xFF);
        value = 0;
        count = 0;
      }
    }
    if (count > 0) {
      for (int i = count; i < 5; i++) {
        value = value * 85 + 84;
      }
      for (int i = 0; i < count - 1; i++) {
        out.add((value >> (24 - 8 * i)) & 0xFF);
      }
    }
    return Uint8List.fromList(out);
  }

  List<String> _extractXObjectNamesFromContent(PdfDictToken pageDict) {
    final out = <String>[];
    final seen = <String>{};
    final contentVal = pageDict.values[PdfKeys.contents];
    if (contentVal == null) return out;

    final refs = <PdfRefToken>[];
    if (contentVal is PdfRefToken) {
      refs.add(contentVal);
    } else if (contentVal is PdfArrayToken) {
      for (final item in contentVal.values) {
        final ref = asRef(item);
        if (ref != null) refs.add(ref);
      }
    }

    const maxScanSize = 1024 * 1024;
    for (final ref in refs) {
      final obj = _getObject(ref.obj);
      if (obj == null || obj.value is! PdfDictToken) {
        continue;
      }
      final dict = obj.value as PdfDictToken;
      Uint8List? data = obj.streamData;
      if (data == null) {
        data = _readStreamDataForScan(ref, maxScanSize);
      }
      if (data == null) continue;
      if (data.length > maxScanSize) continue;

      var dataBytes = data;

      final filters = _asFilterNames(dict.values[PdfKeys.filter]);
      if (filters.isNotEmpty) {
        for (final filter in filters.reversed) {
          if (filter == 'ASCII85') {
            dataBytes = _decodeAscii85(dataBytes);
          } else if (filter == 'Flate') {
            if (dataBytes.length > _maxStreamDecodeSize) break;
            dataBytes =
                Uint8List.fromList(ZLibDecoder().decodeBytes(dataBytes));
          }
        }
      }

      int i = 0;
      while (i < dataBytes.length) {
        if (dataBytes[i] == 0x2F /* / */) {
          final name = readName(dataBytes, i, dataBytes.length);
          i = name.nextIndex;
          final afterName =
              skipPdfWsAndComments(dataBytes, i, dataBytes.length);
          if (afterName + 1 < dataBytes.length &&
              dataBytes[afterName] == 0x44 &&
              dataBytes[afterName + 1] == 0x6F) {
            if (seen.add(name.value)) {
              out.add(name.value);
            }
          }
          i = afterName + 2;
          continue;
        }
        i++;
      }
    }

    return out;
  }

  Uint8List? _readStreamDataForScan(PdfRefToken ref, int maxBytes) {
    final entry = _xrefEntries[ref.obj];
    if (entry == null || entry.type != XrefType.inUse) return null;

    final len = reader.length;
    if (entry.offset < 0 || entry.offset >= len) return null;
    final headerSize = 64 * 1024;
    final windowSize = headerSize + maxBytes;
    final size =
        entry.offset + windowSize > len ? (len - entry.offset) : windowSize;
    if (size <= 0) return null;

    final window = reader.readRange(entry.offset, size);
    final streamPos = _findStreamStart(window, 0);
    if (streamPos == null) return null;
    var dataStart = streamPos;
    if (dataStart < window.length && window[dataStart] == 0x0D) {
      dataStart++;
    }
    if (dataStart < window.length && window[dataStart] == 0x0A) {
      dataStart++;
    }

    final endPos = indexOfSequenceBmh(
      window,
      endStreamToken,
      dataStart,
      window.length,
    );
    final dataEnd = endPos != -1
        ? endPos
        : (dataStart + maxBytes <= window.length
            ? dataStart + maxBytes
            : window.length);
    if (dataEnd <= dataStart) return null;
    return window.sublist(dataStart, dataEnd);
  }

  dynamic _resolveValueNoStream(dynamic value) {
    if (value is PdfRefToken) {
      final obj = _getObjectNoStream(value.obj) ?? _getObject(value.obj);
      return obj?.value;
    }
    return value;
  }

  Map<String, String>? _readInfoDict(int infoObjId) {
    final obj = _getObjectNoStream(infoObjId) ?? _getObject(infoObjId);
    if (obj == null || obj.value is! PdfDictToken) return null;
    final dict = obj.value as PdfDictToken;
    final out = <String, String>{};
    for (final entry in dict.values.entries) {
      out[entry.key] = _valueToString(entry.value);
    }
    return out;
  }

  String _valueToString(dynamic value) {
    if (value is PdfNameToken) return value.value;
    if (value is PdfStringToken) return decodePdfString(value.bytes);
    if (value is int || value is double) return value.toString();
    if (value is bool) return value ? 'true' : 'false';
    if (value is PdfRefToken) return '${value.obj} ${value.gen} R';
    return value.toString();
  }

  String? _asString(dynamic value) {
    if (value is PdfStringToken) return decodePdfString(value.bytes);
    if (value is PdfNameToken) return value.value;
    if (value is int || value is double || value is bool) {
      return value.toString();
    }
    if (value is PdfRefToken) return '${value.obj} ${value.gen} R';
    return null;
  }

  List<int>? asIntArray(dynamic value) {
    final resolved = _resolveValueNoStream(value);
    if (resolved is PdfArrayToken) {
      final nums = <int>[];
      for (final v in resolved.values) {
        if (v is int) {
          nums.add(v);
        } else if (v is double) {
          nums.add(v.toInt());
        }
      }
      if (nums.isNotEmpty) return nums;
    }
    return null;
  }

  @override
  void mergeDocument(PdfDocument pdfDocument) {
    _ensureXrefParsed();

    final trailer =
        _trailerInfo ?? _readTrailerInfoFromReader(reader, xrefOffset);
    if (trailer.rootObj == null) {
      pdfDocument.catalog = PdfCatalog(pdfDocument, PdfPageList(pdfDocument));
      return;
    }

    final rootObj = _getObject(trailer.rootObj!);
    if (rootObj == null || rootObj.value is! PdfDictToken) {
      pdfDocument.catalog = PdfCatalog(pdfDocument, PdfPageList(pdfDocument));
      return;
    }

    final rootDict = rootObj.value as PdfDictToken;
    final pagesRef = asRef(rootDict.values[PdfKeys.pages]);

    final pageList = PdfPageList(
      pdfDocument,
      objser: pagesRef?.obj,
      objgen: pagesRef?.gen ?? 0,
    );

    pdfDocument.catalog = PdfCatalog(
      pdfDocument,
      pageList,
      objser: rootObj.objId,
      objgen: rootObj.gen,
    );

    mergeDictIntoPdfDict(
      pdfDocument.catalog.params,
      rootDict,
      ignoreKeys: const {PdfKeys.pages, PdfKeys.type},
    );

    if (pagesRef != null) {
      final pages = _loadPages(pagesRef, pdfDocument);
      pageList.pages.addAll(pages);
    }
  }

  ParsedIndirectObject? _getObject(int objId) {
    final cached = _objectCache[objId];
    if (cached != null) return cached;

    _ensureXrefParsed();
    var entry = _xrefEntries[objId];
    if (entry == null) {
      if (!_allowRepair) return null;
      _ensureFullScanIndexBuilt();
      entry = _xrefEntries[objId];
      if (entry == null) return null;
    }

    ParsedIndirectObject? parsed;
    if (entry.type == XrefType.inUse) {
      try {
        parsed = readIndirectObjectAtFromReader(reader, entry.offset, this);
      } catch (_) {
        return null;
      }
    } else if (entry.type == XrefType.compressed) {
      try {
        parsed = readCompressedObject(objId, entry, this);
      } catch (_) {
        return null;
      }
    }

    if (parsed != null) {
      _objectCache[objId] = parsed;
    }
    return parsed;
  }

  ParsedIndirectObject? _getObjectNoStream(int objId) {
    final cached = _objectCacheNoStream[objId];
    if (cached != null) return cached;

    _ensureXrefParsed();
    var entry = _xrefEntries[objId];
    if (entry == null) {
      if (!_allowRepair) return null;
      _ensureFullScanIndexBuilt();
      entry = _xrefEntries[objId];
      if (entry == null) return null;
    }

    ParsedIndirectObject? parsed;
    if (entry.type == XrefType.inUse) {
      try {
        parsed = readIndirectObjectAtFromReaderNoStream(reader, entry.offset);
      } catch (_) {
        return null;
      }
    } else if (entry.type == XrefType.compressed) {
      try {
        parsed = readCompressedObject(objId, entry, this);
      } catch (_) {
        return null;
      }
    }

    if (parsed != null) {
      _objectCacheNoStream[objId] = parsed;
    }
    return parsed;
  }

  List<PdfPage> _loadPages(PdfRefToken pagesRef, PdfDocument pdfDocument) {
    final pages = <PdfPage>[];
    final visited = <int>{};
    _collectPages(pagesRef, pdfDocument, pages, visited);
    return pages;
  }

  void _collectPages(
    PdfRefToken ref,
    PdfDocument pdfDocument,
    List<PdfPage> pages,
    Set<int> visited,
  ) {
    if (visited.contains(ref.obj)) return;
    visited.add(ref.obj);

    final obj = _getObject(ref.obj);
    if (obj == null || obj.value is! PdfDictToken) return;
    final dict = obj.value as PdfDictToken;
    final type = asName(dict.values[PdfKeys.type]);

    if (type == '/Page' || dict.values.containsKey(PdfKeys.contents)) {
      final page = _buildPageFromDict(obj, dict, pdfDocument);
      if (page != null) pages.add(page);
      return;
    }

    final kids = dict.values[PdfKeys.kids];
    if (kids is PdfArrayToken) {
      for (final item in kids.values) {
        final kidRef = asRef(item);
        if (kidRef != null) {
          _collectPages(kidRef, pdfDocument, pages, visited);
        }
      }
    }
  }

  PdfPage? _buildPageFromDict(
    ParsedIndirectObject pageObj,
    PdfDictToken dict,
    PdfDocument pdfDocument,
  ) {
    final mediaBox = asNumArray(dict.values[PdfKeys.mediaBox]) ??
        asNumArray(dict.values['/CropBox']);
    final format = pageFormatFromBox(mediaBox);
    final rotate = pageRotationFromValue(dict.values['/Rotate']);

    final page = PdfPage(
      pdfDocument,
      objser: pageObj.objId,
      objgen: pageObj.gen,
      pageFormat: format ?? PdfPageFormat.standard,
      rotate: rotate,
    );

    final filtered = toPdfDict(
      dict,
      ignoreKeys: const {'/Parent', PdfKeys.type, PdfKeys.mediaBox, '/Rotate'},
    );

    // Resolve /Annots se for referência indireta para permitir append
    final annotsValue = dict.values[PdfKeys.annots];
    if (annotsValue is PdfRefToken) {
      final annotsObj = _getObject(annotsValue.obj);
      if (annotsObj != null && annotsObj.value is PdfArrayToken) {
        filtered.values[PdfKeys.annots] =
            toPdfArray(annotsObj.value as PdfArrayToken);
      }
    }

    page.params.values.addAll(filtered.values);
    return page;
  }

  void _ensureXrefParsed() {
    if (_xrefParsed) return;
    _xrefParsed = true;
    _parseXrefChain();
  }

  void _ensureFullScanIndexBuilt() {
    if (_fullScanIndexBuilt) return;
    _fullScanIndexBuilt = true;

    final maxObjId =
        _repairXrefByScanFromReader(reader, _xrefEntries, (rootObj) {
      if (rootObj != null) {
        _trailerInfo =
            _mergeTrailerInfo(_trailerInfo, TrailerInfo(rootObj: rootObj));
      }
    });

    if ((_trailerInfo?.size == null || _trailerInfo!.size! <= 0) &&
        maxObjId > 0) {
      _trailerInfo =
          _mergeTrailerInfo(_trailerInfo, TrailerInfo(size: maxObjId + 1));
    }

    _indexObjectStreams();
  }

  void _parseXrefChain() {
    final visited = <int>{};
    int offset = _computeXrefOffsetFromReader(reader);

    while (offset > 0 && offset < reader.length && !visited.contains(offset)) {
      visited.add(offset);

      TrailerInfo? info;
      try {
        info = _parseXrefAtOffsetFromReader(reader, offset, _xrefEntries);
      } catch (_) {
        break;
      }
      if (info != null) {
        _trailerInfo = _mergeTrailerInfo(_trailerInfo, info);
        if (info.prev != null && info.prev! > 0) {
          offset = info.prev!;
          continue;
        }
      }
      break;
    }

    if (_allowRepair &&
        _trailerInfo?.rootObj == null &&
        _xrefEntries.isNotEmpty) {
      final tailRoot = _findRootFromTailFromReader(reader);
      if (tailRoot != null) {
        _trailerInfo =
            _mergeTrailerInfo(_trailerInfo, TrailerInfo(rootObj: tailRoot.obj));
      }
    }

    if (_allowRepair &&
        _trailerInfo?.infoObj == null &&
        _xrefEntries.isNotEmpty) {
      final tailInfo = _findInfoFromTailFromReader(reader);
      if (tailInfo != null) {
        _trailerInfo =
            _mergeTrailerInfo(_trailerInfo, TrailerInfo(infoObj: tailInfo.obj));
      }
    }

    if (_allowRepair &&
        (_xrefEntries.isEmpty || _trailerInfo?.rootObj == null) &&
        !_repairAttempted) {
      _repairAttempted = true;
      final maxObjId =
          _repairXrefByScanFromReader(reader, _xrefEntries, (rootObj) {
        if (rootObj != null) {
          _trailerInfo =
              _mergeTrailerInfo(_trailerInfo, TrailerInfo(rootObj: rootObj));
        }
      });
      if (maxObjId > 0) {
        _trailerInfo =
            _mergeTrailerInfo(_trailerInfo, TrailerInfo(size: maxObjId + 1));
      }
      _fullScanIndexBuilt = true;
      _indexObjectStreams();
    }

    if (_allowRepair &&
        _trailerInfo?.infoObj == null &&
        _xrefEntries.isNotEmpty) {
      final tailInfo = _findInfoFromTailFromReader(reader);
      if (tailInfo != null) {
        _trailerInfo =
            _mergeTrailerInfo(_trailerInfo, TrailerInfo(infoObj: tailInfo.obj));
      }
    }
  }

  void _indexObjectStreams() {
    if (_objStmIndexed) return;
    _objStmIndexed = true;

    final ids = _xrefEntries.keys.toList()..sort();
    for (final objId in ids) {
      final entry = _xrefEntries[objId];
      if (entry == null || entry.type != XrefType.inUse) continue;
      ParsedIndirectObject? obj;
      try {
        obj = _getObject(objId);
      } catch (_) {
        continue;
      }
      if (obj == null || obj.value is! PdfDictToken) continue;
      final dict = obj.value as PdfDictToken;
      final type = asName(dict.values[PdfKeys.type]);
      if (type != '/ObjStm') continue;
      if (obj.streamData == null) continue;

      final n = asInt(dict.values[PdfKeys.n]);
      if (n == null || n <= 0) continue;

      Uint8List data = obj.streamData!;
      final filter = asName(dict.values[PdfKeys.filter]);
      if (filter == '/FlateDecode') {
        if (data.length > _maxStreamDecodeSize) continue;
        data = Uint8List.fromList(ZLibDecoder().decodeBytes(data));
      }

      final header = readObjectStreamHeader(data, n);
      if (header == null) continue;
      for (final embeddedId in header.index.keys) {
        final existing = _xrefEntries[embeddedId];
        if (existing == null) {
          _xrefEntries[embeddedId] = XrefEntry(
            offset: objId,
            gen: 0,
            type: XrefType.compressed,
          );
        }
      }
    }
  }
}

const int _maxStreamDecodeSize = 256 * 1024 * 1024;

const List<int> endStreamToken = <int>[
  0x65,
  0x6E,
  0x64,
  0x73,
  0x74,
  0x72,
  0x65,
  0x61,
  0x6D
];

int _findStartXref(Uint8List bytes) {
  const token = <int>[0x73, 0x74, 0x61, 0x72, 0x74, 0x78, 0x72, 0x65, 0x66];

  // Procura do fim para o começo, limitando a janela para robustez/perf.
  final int windowStart = bytes.length > 4 * 1024 ? bytes.length - 4 * 1024 : 0;
  final int pos = lastIndexOfSequence(bytes, token, windowStart, bytes.length);
  if (pos == -1) return 0;

  int i = pos + token.length;
  i = skipPdfWsAndComments(bytes, i, bytes.length);
  final parsed = readInt(bytes, i, bytes.length);
  return parsed.value;
}

int _findStartXrefFromReader(PdfRandomAccessReader reader) {
  const token = <int>[0x73, 0x74, 0x61, 0x72, 0x74, 0x78, 0x72, 0x65, 0x66];
  final len = reader.length;
  final windowSize = len > 4 * 1024 ? 4 * 1024 : len;
  final windowStart = len - windowSize;
  final window = reader.readRange(windowStart, windowSize);
  final pos = lastIndexOfSequence(window, token, 0, window.length);
  if (pos == -1) return 0;

  int i = pos + token.length;
  i = skipPdfWsAndComments(window, i, window.length);
  final parsed = readInt(window, i, window.length);
  return parsed.value;
}

int _computeXrefOffset(Uint8List bytes) {
  final startXref = _findStartXref(bytes);
  if (startXref > 0 && startXref < bytes.length) {
    return startXref;
  }

  // Fallback: procurar a última ocorrência de 'xref'
  const xrefToken = <int>[0x78, 0x72, 0x65, 0x66]; // xref
  final windowStart =
      bytes.length > 1024 * 1024 ? bytes.length - 1024 * 1024 : 0;
  final pos = lastIndexOfSequence(bytes, xrefToken, windowStart, bytes.length);
  if (pos != -1) {
    return pos;
  }

  return 0;
}

int _computeXrefOffsetFromReader(PdfRandomAccessReader reader) {
  final len = reader.length;
  final startXref = _findStartXrefFromReader(reader);
  if (startXref > 0 && startXref < len) {
    return startXref;
  }

  const xrefToken = <int>[0x78, 0x72, 0x65, 0x66];
  final windowSize = len > 1024 * 1024 ? 1024 * 1024 : len;
  final windowStart = len - windowSize;
  final window = reader.readRange(windowStart, windowSize);
  final pos = lastIndexOfSequence(window, xrefToken, 0, window.length);
  if (pos != -1) {
    return windowStart + pos;
  }
  return 0;
}

int _computeSize(Uint8List bytes, TrailerInfo? trailerInfo) {
  if (trailerInfo?.size != null && trailerInfo!.size! > 0) {
    return trailerInfo.size!;
  }
  if (trailerInfo == null) {
    final info = _readTrailerInfo(bytes, _computeXrefOffset(bytes));
    if (info.size != null && info.size! > 0) {
      return info.size!;
    }
  }
  return _maxObjectId(bytes) + 1;
}

int _computeSizeFromReader(
  PdfRandomAccessReader reader,
  TrailerInfo? trailerInfo,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return _computeSize(reader.readAll(), trailerInfo);
  }
  if (trailerInfo?.size != null && trailerInfo!.size! > 0) {
    return trailerInfo.size!;
  }

  final info =
      _readTrailerInfoFromReader(reader, _computeXrefOffsetFromReader(reader));
  if (info.size != null && info.size! > 0) {
    return info.size!;
  }

  return _maxObjectIdFromReader(reader) + 1;
}

String decodePdfString(Uint8List bytes) {
  if (bytes.length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF) {
    final codeUnits = <int>[];
    for (int i = 2; i + 1 < bytes.length; i += 2) {
      codeUnits.add((bytes[i] << 8) | bytes[i + 1]);
    }
    return String.fromCharCodes(codeUnits);
  }
  return String.fromCharCodes(bytes);
}

TrailerInfo _mergeTrailerInfo(TrailerInfo? a, TrailerInfo b) {
  if (a == null) return b;
  return TrailerInfo(
    size: a.size ?? b.size,
    prev: a.prev ?? b.prev,
    rootObj: a.rootObj ?? b.rootObj,
    infoObj: a.infoObj ?? b.infoObj,
    id: a.id ?? b.id,
  );
}

TrailerInfo _readTrailerInfo(Uint8List bytes, int startXref) {
  // 1) Se startXref aponta para xref table, buscar trailer após a tabela
  // 2) Se startXref aponta para xref stream, parsear dicionário do objeto
  // 3) Caso falhe, buscar último 'trailer' no arquivo

  if (startXref > 0 && startXref < bytes.length) {
    final infoFromXref = _tryReadTrailerNearOffset(bytes, startXref);
    if (infoFromXref.size != null || infoFromXref.prev != null) {
      return infoFromXref;
    }
  }

  final infoFromTrailer = _tryReadLastTrailer(bytes);
  if (infoFromTrailer.size != null || infoFromTrailer.prev != null) {
    return infoFromTrailer;
  }

  return TrailerInfo();
}

TrailerInfo _readTrailerInfoFromReader(
  PdfRandomAccessReader reader,
  int startXref,
) {
  if (startXref > 0 && startXref < reader.length) {
    final windowSize = reader.length - startXref > 1024 * 1024
        ? 1024 * 1024
        : reader.length - startXref;
    if (windowSize > 0) {
      final window = reader.readRange(startXref, windowSize);
      final infoFromXref = _tryReadTrailerNearOffset(window, 0);
      if (infoFromXref.size != null || infoFromXref.prev != null) {
        return infoFromXref;
      }
    }
  }

  final tailSize = reader.length > 1024 * 1024 ? 1024 * 1024 : reader.length;
  final tail = reader.readRange(reader.length - tailSize, tailSize);
  final infoFromTrailer = _tryReadLastTrailer(tail);
  if (infoFromTrailer.size != null || infoFromTrailer.prev != null) {
    return infoFromTrailer;
  }

  return TrailerInfo();
}

TrailerInfo _tryReadTrailerNearOffset(Uint8List bytes, int offset) {
  // Skip ws
  int i = skipPdfWsAndComments(bytes, offset, bytes.length);

  // xref table?
  if (matchToken(bytes, i, const <int>[0x78, 0x72, 0x65, 0x66])) {
    // procurar 'trailer' depois de xref
    final trailerInfo = _scanForTrailerDict(bytes, i + 4, bytes.length);
    if (trailerInfo.size != null || trailerInfo.prev != null) {
      return trailerInfo;
    }
  }

  // xref stream? (obj ... << /Type /XRef ... >>)
  final xrefStreamInfo = _tryReadXrefStreamDict(bytes, i);
  if (xrefStreamInfo.size != null || xrefStreamInfo.prev != null) {
    return xrefStreamInfo;
  }

  return TrailerInfo();
}

TrailerInfo _tryReadLastTrailer(Uint8List bytes) {
  const trailerToken = <int>[
    0x74,
    0x72,
    0x61,
    0x69,
    0x6C,
    0x65,
    0x72
  ]; // trailer
  final windowStart =
      bytes.length > 1024 * 1024 ? bytes.length - 1024 * 1024 : 0;
  final pos =
      lastIndexOfSequence(bytes, trailerToken, windowStart, bytes.length);
  if (pos == -1) {
    return TrailerInfo();
  }
  return _scanForTrailerDict(bytes, pos + trailerToken.length, bytes.length);
}

TrailerInfo _scanForTrailerDict(Uint8List bytes, int start, int end) {
  int i = skipPdfWsAndComments(bytes, start, end);
  // buscar '<<'
  for (; i + 1 < end; i++) {
    if (bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
      break;
    }
  }
  if (i + 1 >= end) {
    return TrailerInfo();
  }

  final dict = _parseTrailerDict(bytes, i, end);
  return TrailerInfo(
    size: dict.size,
    prev: dict.prev,
    rootObj: dict.rootObj,
    infoObj: dict.infoObj,
    id: dict.id,
  );
}

TrailerInfo _tryReadXrefStreamDict(Uint8List bytes, int offset) {
  // Verifica padrão: "<obj> <gen> obj" seguido de "<<" com /Type /XRef
  final header = _tryReadIndirectObjectHeader(bytes, offset, bytes.length);
  if (header == null) {
    return TrailerInfo();
  }

  final dict = _parseXrefStreamDict(bytes, header.dictStart, bytes.length);
  if (dict.type == '/XRef') {
    return TrailerInfo(
      size: dict.size,
      prev: dict.prev,
      rootObj: dict.rootObj,
      infoObj: dict.infoObj,
      id: dict.id,
    );
  }
  return TrailerInfo();
}

IndirectHeader? _tryReadIndirectObjectHeader(
  Uint8List bytes,
  int start,
  int end,
) {
  int i = skipPdfWsAndComments(bytes, start, end);
  if (i >= end || !isDigit(bytes[i])) return null;
  final obj = readInt(bytes, i, end);
  i = obj.nextIndex;
  i = skipPdfWsAndComments(bytes, i, end);
  if (i >= end || !isDigit(bytes[i])) return null;
  final gen = readInt(bytes, i, end);
  i = gen.nextIndex;
  i = skipPdfWsAndComments(bytes, i, end);
  if (!matchToken(bytes, i, const <int>[0x6F, 0x62, 0x6A])) return null; // obj
  i += 3;
  i = skipPdfWsAndComments(bytes, i, end);
  if (i + 1 >= end || bytes[i] != 0x3C || bytes[i + 1] != 0x3C) return null;
  final dictEnd = _findDictEnd(bytes, i, end);
  if (dictEnd == -1) return null;
  return IndirectHeader(i, dictEnd);
}

({String value, int nextIndex}) readName(Uint8List bytes, int i, int end) {
  final buffer = StringBuffer();
  buffer.writeCharCode(bytes[i]);
  i++;
  while (i < end) {
    final b = bytes[i];
    if (isWhitespace(b) ||
        b == 0x3C ||
        b == 0x3E ||
        b == 0x2F ||
        b == 0x28 ||
        b == 0x29 ||
        b == 0x5B ||
        b == 0x5D ||
        b == 0x7B ||
        b == 0x7D ||
        b == 0x25) {
      break;
    }
    if (b == 0x23 /* # */ && i + 2 < end) {
      final h1 = bytes[i + 1];
      final h2 = bytes[i + 2];
      if (isHexDigit(h1) && isHexDigit(h2)) {
        final v = (hexValue(h1) << 4) | hexValue(h2);
        buffer.writeCharCode(v);
        i += 3;
        continue;
      }
    }
    buffer.writeCharCode(b);
    i++;
  }
  return (value: buffer.toString(), nextIndex: i);
}

bool matchToken(Uint8List bytes, int index, List<int> token) {
  if (index + token.length > bytes.length) return false;
  for (int i = 0; i < token.length; i++) {
    if (bytes[index + i] != token[i]) return false;
  }
  return true;
}

TrailerInfo? _parseXrefAtOffset(
  Uint8List bytes,
  int offset,
  Map<int, XrefEntry> entries,
) {
  int i = skipPdfWsAndComments(bytes, offset, bytes.length);

  // xref table?
  if (matchToken(bytes, i, const <int>[0x78, 0x72, 0x65, 0x66])) {
    return _parseXrefTable(bytes, i + 4, entries);
  }

  // xref stream?
  return _parseXrefStream(bytes, i, entries);
}

TrailerInfo? _parseXrefAtOffsetFromReader(
  PdfRandomAccessReader reader,
  int offset,
  Map<int, XrefEntry> entries,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return _parseXrefAtOffset(reader.readAll(), offset, entries);
  }

  final len = reader.length;
  const windowSizes = <int>[
    256 * 1024,
    1024 * 1024,
    4 * 1024 * 1024,
    16 * 1024 * 1024
  ];
  for (final size in windowSizes) {
    if (offset < 0 || offset >= len) return null;
    final windowSize = (offset + size > len) ? (len - offset) : size;
    final window = reader.readRange(offset, windowSize);
    int i = skipPdfWsAndComments(window, 0, window.length);

    if (matchToken(window, i, const <int>[0x78, 0x72, 0x65, 0x66])) {
      final info = _parseXrefTableFromWindow(window, entries, reader);
      if (info != null) return info;
    } else {
      final info = _parseXrefStreamFromWindow(window, offset, entries, reader);
      if (info != null) return info;
    }
  }

  return null;
}

void _setXrefEntryIfAbsent(
  Map<int, XrefEntry> entries,
  int objId,
  XrefEntry entry,
) {
  entries.putIfAbsent(objId, () => entry);
}

TrailerInfo? _parseXrefTableFromWindow(
  Uint8List bytes,
  Map<int, XrefEntry> entries,
  PdfRandomAccessReader reader,
) {
  int i = 0;

  while (i < bytes.length) {
    i = skipPdfWsAndComments(bytes, i, bytes.length);
    if (i >= bytes.length) break;

    if (matchToken(
        bytes, i, const <int>[0x74, 0x72, 0x61, 0x69, 0x6C, 0x65, 0x72])) {
      return _scanForTrailerDict(bytes, i + 7, bytes.length);
    }

    if (!isDigit(bytes[i])) {
      i++;
      continue;
    }

    final startObj = readInt(bytes, i, bytes.length);
    i = startObj.nextIndex;
    i = skipPdfWsAndComments(bytes, i, bytes.length);
    if (i >= bytes.length || !isDigit(bytes[i])) {
      continue;
    }
    final count = readInt(bytes, i, bytes.length);
    i = count.nextIndex;

    for (int j = 0; j < count.value; j++) {
      i = skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length) break;

      final off = readInt(bytes, i, bytes.length);
      i = off.nextIndex;
      i = skipPdfWsAndComments(bytes, i, bytes.length);
      final gen = readInt(bytes, i, bytes.length);
      i = gen.nextIndex;
      i = skipPdfWsAndComments(bytes, i, bytes.length);

      final flag = bytes[i];
      i++;
      if (flag == 0x6E /* n */) {
        final objId = startObj.value + j;
        final fixed = _fixOffsetReader(reader, objId, gen.value, off.value);
        _setXrefEntryIfAbsent(
          entries,
          objId,
          XrefEntry(
            offset: fixed,
            gen: gen.value,
            type: XrefType.inUse,
          ),
        );
      } else if (flag == 0x66 /* f */) {
        final objId = startObj.value + j;
        _setXrefEntryIfAbsent(
          entries,
          objId,
          XrefEntry(
            offset: off.value,
            gen: gen.value,
            type: XrefType.free,
          ),
        );
      }

      while (i < bytes.length && bytes[i] != 0x0A && bytes[i] != 0x0D) {
        i++;
      }
    }
  }

  return null;
}

TrailerInfo? _parseXrefStreamFromWindow(
  Uint8List bytes,
  int baseOffset,
  Map<int, XrefEntry> entries,
  PdfRandomAccessReader reader,
) {
  final header = _tryReadIndirectObjectHeader(bytes, 0, bytes.length);
  if (header == null) return null;

  final dict = _parseXrefStreamDict(bytes, header.dictStart, bytes.length);
  if (dict.type != '/XRef') return null;

  Uint8List? stream =
      extractStream(bytes, header.dictEnd, bytes.length, dict.length);
  if (stream == null && dict.length != null) {
    final streamStart = _findStreamStart(bytes, header.dictEnd);
    if (streamStart != null) {
      final abs = baseOffset + streamStart;
      stream = reader.readRange(abs, dict.length!);
    }
  }

  if (stream == null && dict.length == null) {
    final streamStart = _findStreamStart(bytes, header.dictEnd);
    if (streamStart != null) {
      final absStart = baseOffset + streamStart;
      final endAbs =
          _skipUnknownLengthStreamReader(reader, absStart, reader.length);
      if (endAbs != null) {
        final dataEnd = endAbs - endStreamToken.length;
        final len = dataEnd - absStart;
        if (len > 0 && absStart + len <= reader.length) {
          stream = reader.readRange(absStart, len);
        }
      }
    }
  }

  if (stream == null) {
    return TrailerInfo(
      size: dict.size,
      prev: dict.prev,
      rootObj: dict.rootObj,
      infoObj: dict.infoObj,
      id: dict.id,
    );
  }

  Uint8List data = stream;
  if (dict.filter == '/FlateDecode') {
    if (stream.length > _maxStreamDecodeSize) {
      return TrailerInfo(
        size: dict.size,
        prev: dict.prev,
        rootObj: dict.rootObj,
        infoObj: dict.infoObj,
        id: dict.id,
      );
    }
    data = Uint8List.fromList(ZLibDecoder().decodeBytes(stream));
  }

  final w = dict.w;
  if (w == null || w.length < 3) {
    return TrailerInfo(
      size: dict.size,
      prev: dict.prev,
      rootObj: dict.rootObj,
      infoObj: dict.infoObj,
      id: dict.id,
    );
  }

  final index = dict.index ?? <int>[0, dict.size ?? 0];
  int pos = 0;
  for (int k = 0; k + 1 < index.length; k += 2) {
    final startObj = index[k];
    final count = index[k + 1];
    for (int j = 0; j < count; j++) {
      final type = _readField(data, pos, w[0]);
      pos += w[0];
      final f1 = _readField(data, pos, w[1]);
      pos += w[1];
      final f2 = _readField(data, pos, w[2]);
      pos += w[2];

      final objId = startObj + j;
      if (type == 0) {
        continue;
      } else if (type == 1) {
        final fixed = _fixOffsetReader(reader, objId, f2, f1);
        _setXrefEntryIfAbsent(
          entries,
          objId,
          XrefEntry(
            offset: fixed,
            gen: f2,
            type: XrefType.inUse,
          ),
        );
      } else if (type == 2) {
        _setXrefEntryIfAbsent(
          entries,
          objId,
          XrefEntry(
            offset: f1,
            gen: f2,
            type: XrefType.compressed,
          ),
        );
      }
    }
  }

  return TrailerInfo(
    size: dict.size,
    prev: dict.prev,
    rootObj: dict.rootObj,
    infoObj: dict.infoObj,
    id: dict.id,
  );
}

int? _findStreamStart(Uint8List bytes, int dictEnd) {
  int i = dictEnd;
  i = skipPdfWsAndComments(bytes, i, bytes.length);
  if (!matchToken(bytes, i, const <int>[0x73, 0x74, 0x72, 0x65, 0x61, 0x6D])) {
    return null;
  }
  i += 6;
  if (i < bytes.length && bytes[i] == 0x0D) i++;
  if (i < bytes.length && bytes[i] == 0x0A) i++;
  return i;
}

int _fixOffsetReader(
  PdfRandomAccessReader reader,
  int objId,
  int gen,
  int offset,
) {
  if (offset < 0) {
    final corrected = offset + 0x100000000;
    if (_isValidObjAtOffsetReader(reader, objId, gen, corrected))
      return corrected;
  }
  if (_isValidObjAtOffsetReader(reader, objId, gen, offset)) return offset;

  const radius = 1024;
  final start = offset - radius < 0 ? 0 : offset - radius;
  final end = offset + radius > reader.length ? reader.length : offset + radius;
  final found = _findObjectHeaderReader(reader, objId, gen, start, end);
  return found ?? offset;
}

bool _isValidObjAtOffsetReader(
  PdfRandomAccessReader reader,
  int objId,
  int gen,
  int offset,
) {
  if (offset < 0 || offset >= reader.length) return false;
  final win = reader.readRange(offset, 64);
  int i = skipPdfWsAndComments(win, 0, win.length);
  if (i >= win.length || !isDigit(win[i])) return false;
  final obj = readInt(win, i, win.length);
  if (obj.value != objId) return false;
  i = skipPdfWsAndComments(win, obj.nextIndex, win.length);
  if (i >= win.length || !isDigit(win[i])) return false;
  final genRead = readInt(win, i, win.length);
  if (genRead.value != gen) return false;
  i = skipPdfWsAndComments(win, genRead.nextIndex, win.length);
  return matchToken(win, i, const <int>[0x6F, 0x62, 0x6A]);
}

int? _findObjectHeaderReader(
  PdfRandomAccessReader reader,
  int objId,
  int gen,
  int start,
  int end,
) {
  final window = reader.readRange(start, end - start);
  final found = _findObjectHeader(window, objId, gen, 0, window.length);
  if (found == null) return null;
  return start + found;
}

TrailerInfo? _parseXrefTable(
  Uint8List bytes,
  int start,
  Map<int, XrefEntry> entries,
) {
  int i = start;

  while (i < bytes.length) {
    i = skipPdfWsAndComments(bytes, i, bytes.length);
    if (i >= bytes.length) break;

    if (matchToken(
        bytes, i, const <int>[0x74, 0x72, 0x61, 0x69, 0x6C, 0x65, 0x72])) {
      return _scanForTrailerDict(bytes, i + 7, bytes.length);
    }

    if (!isDigit(bytes[i])) {
      i++;
      continue;
    }

    final startObj = readInt(bytes, i, bytes.length);
    i = startObj.nextIndex;
    i = skipPdfWsAndComments(bytes, i, bytes.length);
    if (!isDigit(bytes[i])) {
      continue;
    }
    final count = readInt(bytes, i, bytes.length);
    i = count.nextIndex;

    for (int j = 0; j < count.value; j++) {
      i = skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length) break;

      final off = readInt(bytes, i, bytes.length);
      i = off.nextIndex;
      i = skipPdfWsAndComments(bytes, i, bytes.length);
      final gen = readInt(bytes, i, bytes.length);
      i = gen.nextIndex;
      i = skipPdfWsAndComments(bytes, i, bytes.length);

      final flag = bytes[i];
      i++;
      if (flag == 0x6E /* n */) {
        final objId = startObj.value + j;
        final fixed = _fixOffset(bytes, objId, gen.value, off.value);
        _setXrefEntryIfAbsent(
          entries,
          objId,
          XrefEntry(
            offset: fixed,
            gen: gen.value,
            type: XrefType.inUse,
          ),
        );
      } else if (flag == 0x66 /* f */) {
        final objId = startObj.value + j;
        _setXrefEntryIfAbsent(
          entries,
          objId,
          XrefEntry(
            offset: off.value,
            gen: gen.value,
            type: XrefType.free,
          ),
        );
      }

      // consumir fim de linha
      while (i < bytes.length && bytes[i] != 0x0A && bytes[i] != 0x0D) {
        i++;
      }
    }
  }

  return null;
}

TrailerInfo? _parseXrefStream(
  Uint8List bytes,
  int offset,
  Map<int, XrefEntry> entries,
) {
  final header = _tryReadIndirectObjectHeader(bytes, offset, bytes.length);
  if (header == null) return null;

  final dict = _parseXrefStreamDict(bytes, header.dictStart, bytes.length);
  if (dict.type != '/XRef') return null;

  final stream =
      extractStream(bytes, header.dictEnd, bytes.length, dict.length);
  if (stream == null)
    return TrailerInfo(
      size: dict.size,
      prev: dict.prev,
      rootObj: dict.rootObj,
      infoObj: dict.infoObj,
      id: dict.id,
    );

  Uint8List data = stream;
  if (dict.filter == '/FlateDecode') {
    if (stream.length > _maxStreamDecodeSize) {
      return TrailerInfo(
        size: dict.size,
        prev: dict.prev,
        rootObj: dict.rootObj,
        infoObj: dict.infoObj,
        id: dict.id,
      );
    }
    data = Uint8List.fromList(ZLibDecoder().decodeBytes(stream));
  }

  final w = dict.w;
  if (w == null || w.length < 3) {
    return TrailerInfo(
      size: dict.size,
      prev: dict.prev,
      rootObj: dict.rootObj,
      infoObj: dict.infoObj,
      id: dict.id,
    );
  }

  final index = dict.index ?? <int>[0, dict.size ?? 0];
  int pos = 0;
  for (int k = 0; k + 1 < index.length; k += 2) {
    final startObj = index[k];
    final count = index[k + 1];
    for (int j = 0; j < count; j++) {
      final type = _readField(data, pos, w[0]);
      pos += w[0];
      final f1 = _readField(data, pos, w[1]);
      pos += w[1];
      final f2 = _readField(data, pos, w[2]);
      pos += w[2];

      final objId = startObj + j;
      if (type == 0) {
        // free
        continue;
      } else if (type == 1) {
        final fixed = _fixOffset(bytes, objId, f2, f1);
        _setXrefEntryIfAbsent(
          entries,
          objId,
          XrefEntry(
            offset: fixed,
            gen: f2,
            type: XrefType.inUse,
          ),
        );
      } else if (type == 2) {
        _setXrefEntryIfAbsent(
          entries,
          objId,
          XrefEntry(
            offset: f1,
            gen: f2,
            type: XrefType.compressed,
          ),
        );
      }
    }
  }

  return TrailerInfo(
    size: dict.size,
    prev: dict.prev,
    rootObj: dict.rootObj,
    infoObj: dict.infoObj,
    id: dict.id,
  );
}

XrefStreamDict _parseXrefStreamDict(Uint8List bytes, int start, int end) {
  final parsed = readDict(bytes, start, end);
  final v = parsed.value;
  if (v is! PdfDictToken) {
    return XrefStreamDict();
  }

  final m = v.values;

  final String? type = asName(m[PdfKeys.type]);
  final int? size = asInt(m[PdfKeys.size]);
  final int? prev = asInt(m[PdfKeys.prev]);

  int? rootObj;
  int? infoObj;
  final rootRef = asRef(m[PdfKeys.root]);
  if (rootRef != null) rootObj = rootRef.obj;
  final infoRef = asRef(m[PdfKeys.info]);
  if (infoRef != null) infoObj = infoRef.obj;

  Uint8List? id;
  final idVal = m[PdfKeys.id];
  if (idVal is PdfArrayToken && idVal.values.isNotEmpty) {
    final first = idVal.values.first;
    if (first is PdfStringToken) {
      id = first.bytes;
    }
  }

  int? length;
  final lenVal = m[PdfKeys.length];
  if (lenVal is int) length = lenVal;
  if (lenVal is double) length = lenVal.toInt();

  String? filter;
  final filterVal = m[PdfKeys.filter];
  if (filterVal is PdfNameToken) {
    filter = filterVal.value;
  } else if (filterVal is PdfArrayToken && filterVal.values.isNotEmpty) {
    final f0 = filterVal.values.first;
    if (f0 is PdfNameToken) filter = f0.value;
  }

  List<int>? w;
  final wVal = m[PdfKeys.w];
  if (wVal is PdfArrayToken) {
    final tmp = <int>[];
    for (final e in wVal.values) {
      final vi = asInt(e);
      if (vi != null) tmp.add(vi);
    }
    if (tmp.isNotEmpty) w = tmp;
  }

  List<int>? index;
  final idxVal = m[PdfKeys.index];
  if (idxVal is PdfArrayToken) {
    final tmp = <int>[];
    for (final e in idxVal.values) {
      final vi = asInt(e);
      if (vi != null) tmp.add(vi);
    }
    if (tmp.isNotEmpty) index = tmp;
  }

  return XrefStreamDict(
    type: type,
    size: size,
    prev: prev,
    rootObj: rootObj,
    infoObj: infoObj,
    id: id,
    length: length,
    filter: filter,
    w: w,
    index: index,
  );
}

Uint8List? extractStream(Uint8List bytes, int dictEnd, int end, int? length) {
  int i = dictEnd;
  i = skipPdfWsAndComments(bytes, i, end);
  if (!matchToken(bytes, i, const <int>[0x73, 0x74, 0x72, 0x65, 0x61, 0x6D])) {
    return null;
  }
  i += 6;
  if (i < end && bytes[i] == 0x0D) i++;
  if (i < end && bytes[i] == 0x0A) i++;

  if (length != null && length > 0 && i + length <= end) {
    return bytes.sublist(i, i + length);
  }

  // fallback: até endstream
  final endPos = indexOfSequence(bytes, endStreamToken, i, end);
  if (endPos == -1) return null;
  return bytes.sublist(i, endPos);
}

int _readField(Uint8List data, int offset, int width) {
  if (width == 0) return 0;
  int value = 0;
  for (int i = 0; i < width; i++) {
    value = (value << 8) | data[offset + i];
  }
  return value;
}

int _fixOffset(Uint8List bytes, int objId, int gen, int offset) {
  if (offset < 0) {
    final corrected = offset + 0x100000000;
    if (_isValidObjAtOffset(bytes, objId, gen, corrected)) return corrected;
  }
  if (_isValidObjAtOffset(bytes, objId, gen, offset)) return offset;

  // Heurística: procurar o header do objeto num raio de 1KB
  const radius = 1024;
  final start = offset - radius < 0 ? 0 : offset - radius;
  final end = offset + radius > bytes.length ? bytes.length : offset + radius;
  final found = _findObjectHeader(bytes, objId, gen, start, end);
  return found ?? offset;
}

int _repairXrefByScan(
  Uint8List bytes,
  Map<int, XrefEntry> entries,
  void Function(int? rootObj) onRootFound,
) {
  final tailRoot = _findRootFromTail(bytes);
  if (tailRoot != null) {
    final found = _findObjectHeaderAnyGen(bytes, tailRoot.obj);
    if (found != null) {
      entries[tailRoot.obj] = XrefEntry(
        offset: found.offset,
        gen: found.gen,
        type: XrefType.inUse,
      );
      onRootFound(tailRoot.obj);
    }
  }

  int i = 0;
  int maxObjId = 0;
  int? lastInt;
  int? lastIntPos;
  int? prevInt;
  int? prevIntPos;
  int? rootObj;

  while (i < bytes.length) {
    i = skipPdfWsAndComments(bytes, i, bytes.length);
    if (i >= bytes.length) break;

    if (isDigit(bytes[i]) || bytes[i] == 0x2D || bytes[i] == 0x2B) {
      ({int value, int nextIndex}) num;
      try {
        num = readInt(bytes, i, bytes.length);
      } catch (_) {
        i++;
        continue;
      }
      prevInt = lastInt;
      prevIntPos = lastIntPos;
      lastInt = num.value;
      lastIntPos = i;
      i = num.nextIndex;

      final j = skipPdfWsAndComments(bytes, i, bytes.length);
      if (j < bytes.length &&
          matchToken(bytes, j, const <int>[0x6F, 0x62, 0x6A])) {
        // padrão: <prevInt> <lastInt> obj
        if (prevInt != null && prevIntPos != null) {
          final objId = prevInt;
          final gen = lastInt;

          if (objId > maxObjId) maxObjId = objId;
          final existing = entries[objId];
          if (existing == null || prevIntPos > existing.offset) {
            entries[objId] = XrefEntry(
              offset: prevIntPos,
              gen: gen,
              type: XrefType.inUse,
            );
          }

          final dictInfo = _scanObjectDictAndSkipStream(bytes, j + 3);
          if (dictInfo.nextIndex > i) {
            i = dictInfo.nextIndex;
          }

          if (rootObj == null && dictInfo.isCatalog) {
            rootObj = objId;
          }
        }

        prevInt = null;
        lastInt = null;
        prevIntPos = null;
        lastIntPos = null;
      }
      continue;
    }

    i++;
  }

  onRootFound(rootObj);
  return maxObjId;
}

int _repairXrefByScanFromReader(
  PdfRandomAccessReader reader,
  Map<int, XrefEntry> entries,
  void Function(int? rootObj) onRootFound,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return _repairXrefByScan(reader.readAll(), entries, onRootFound);
  }

  final tailRoot = _findRootFromTailFromReader(reader);
  if (tailRoot != null) {
    final found = _findObjectHeaderAnyGenReader(reader, tailRoot.obj);
    if (found != null) {
      entries[tailRoot.obj] = XrefEntry(
        offset: found.offset,
        gen: found.gen,
        type: XrefType.inUse,
      );
      onRootFound(tailRoot.obj);
    }
  }

  final len = reader.length;
  const chunkSize = 1024 * 1024;
  const overlap = 64;
  int offset = 0;

  int maxObjId = 0;
  int? lastInt;
  int? prevInt;
  int? lastIntPosAbs;
  int? prevIntPosAbs;
  int? rootObj;

  while (offset < len) {
    final windowSize = (offset + chunkSize > len) ? (len - offset) : chunkSize;
    final window = reader.readRange(offset, windowSize);
    final bytes = window;
    final end = bytes.length;
    int i = 0;
    bool jumped = false;

    while (i < end) {
      i = skipPdfWsAndComments(bytes, i, end);
      if (i >= end) break;

      final b = bytes[i];
      if (b >= 0x30 && b <= 0x39) {
        final res = readIntFast(bytes, i, end);
        if (res.value == -1) {
          i++;
          continue;
        }

        prevInt = lastInt;
        prevIntPosAbs = lastIntPosAbs;
        lastInt = res.value;
        lastIntPosAbs = offset + i;
        i = res.nextIndex;

        final j = skipPdfWsAndComments(bytes, i, end);
        if (j < end && matchToken(bytes, j, const <int>[0x6F, 0x62, 0x6A])) {
          if (prevInt != null && prevIntPosAbs != null) {
            final objId = prevInt;
            final gen = lastInt;

            if (objId > maxObjId) maxObjId = objId;
            final existing = entries[objId];
            if (existing == null || prevIntPosAbs > existing.offset) {
              entries[objId] = XrefEntry(
                offset: prevIntPosAbs,
                gen: gen,
                type: XrefType.inUse,
              );
            }

            final dictInfo = _scanObjectDictAndSkipStreamFromWindow(
              bytes,
              j + 3,
              offset,
              len,
            );

            if (dictInfo.isCatalog && rootObj == null) {
              rootObj = objId;
            }

            if (dictInfo.skipAbs != null && dictInfo.skipAbs! > offset) {
              offset = dictInfo.skipAbs!;
              prevInt = null;
              lastInt = null;
              prevIntPosAbs = null;
              lastIntPosAbs = null;
              jumped = true;
              break;
            }

            if (dictInfo.streamStartAbs != null) {
              final skipAbs = _skipUnknownLengthStreamReader(
                reader,
                dictInfo.streamStartAbs!,
                len,
              );

              if (skipAbs != null && skipAbs > offset && skipAbs <= len) {
                offset = skipAbs;
              } else {
                offset = (offset + end <= len) ? (offset + end) : len;
              }

              prevInt = null;
              lastInt = null;
              prevIntPosAbs = null;
              lastIntPosAbs = null;
              jumped = true;
              break;
            }

            if (dictInfo.nextIndex > i) {
              i = dictInfo.nextIndex;
            }
          }

          prevInt = null;
          lastInt = null;
          prevIntPosAbs = null;
          lastIntPosAbs = null;
        }
        continue;
      }

      i++;
    }

    if (jumped) {
      continue;
    }

    if (offset + chunkSize >= len) break;
    offset += chunkSize - overlap;
  }

  onRootFound(rootObj);
  return maxObjId;
}

ScanDictInfoReader _scanObjectDictAndSkipStreamFromWindow(
  Uint8List bytes,
  int start,
  int baseOffset,
  int fileLength,
) {
  int i = skipPdfWsAndComments(bytes, start, bytes.length);
  int? streamLength;
  bool isCatalog = false;
  if (i + 1 < bytes.length && bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
    final dict = readDictLight(bytes, i, bytes.length);
    streamLength = dict.length;
    isCatalog = dict.isCatalog;
    i = dict.nextIndex;
  }

  i = skipPdfWsAndComments(bytes, i, bytes.length);

  final streamStart = _findStreamStart(bytes, i);
  if (streamStart == null) {
    return ScanDictInfoReader(i, isCatalog, null, null);
  }

  if (streamLength != null && streamLength > 0) {
    final skipAbs = baseOffset + streamStart + streamLength;
    if (skipAbs > 0 && skipAbs <= fileLength) {
      final nextIndex = (skipAbs <= baseOffset + bytes.length)
          ? (skipAbs - baseOffset)
          : bytes.length;
      return ScanDictInfoReader(nextIndex, isCatalog, skipAbs, null);
    }
  }

  final endPos =
      indexOfSequenceBmh(bytes, endStreamToken, streamStart, bytes.length);
  if (endPos != -1) {
    final skipAbs = baseOffset + endPos + endStreamToken.length;
    return ScanDictInfoReader(
        endPos + endStreamToken.length, isCatalog, skipAbs, null);
  }

  return ScanDictInfoReader(
      bytes.length, isCatalog, null, baseOffset + streamStart);
}

int? _skipUnknownLengthStreamReader(
  PdfRandomAccessReader reader,
  int startAbs,
  int fileLength,
) {
  const chunkSize = 4 * 1024 * 1024;
  final overlap = endStreamToken.length + 32;

  int offset = startAbs;
  while (offset < fileLength) {
    final windowSize =
        (offset + chunkSize > fileLength) ? (fileLength - offset) : chunkSize;
    if (windowSize <= 0) return null;

    final window = reader.readRange(offset, windowSize);
    final pos = indexOfSequenceBmh(window, endStreamToken, 0, window.length);
    if (pos != -1) {
      return offset + pos + endStreamToken.length;
    }

    if (offset + chunkSize >= fileLength) break;
    offset += chunkSize - overlap;
  }

  return null;
}

PdfRefToken? _findRootFromTailFromReader(PdfRandomAccessReader reader) {
  final tailSize = reader.length > 1024 * 1024 ? 1024 * 1024 : reader.length;
  final start = reader.length - tailSize;
  final tail = reader.readRange(start, tailSize);
  int i = 0;
  while (i < tail.length) {
    if (tail[i] == 0x2F /* / */) {
      final name = readName(tail, i, tail.length);
      if (name.value == PdfKeys.root) {
        i = skipPdfWsAndComments(tail, name.nextIndex, tail.length);
        if (i < tail.length && isDigit(tail[i])) {
          final ref = _readRef(tail, i, tail.length);
          if (ref != null) return PdfRefToken(ref.obj, ref.gen);
        }
      }
    }
    i++;
  }
  return null;
}

PdfRefToken? _findInfoFromTailFromReader(PdfRandomAccessReader reader) {
  final tailSize = reader.length > 1024 * 1024 ? 1024 * 1024 : reader.length;
  final start = reader.length - tailSize;
  final tail = reader.readRange(start, tailSize);
  int i = 0;
  while (i < tail.length) {
    if (tail[i] == 0x2F /* / */) {
      final name = readName(tail, i, tail.length);
      if (name.value == PdfKeys.info) {
        i = skipPdfWsAndComments(tail, name.nextIndex, tail.length);
        if (i < tail.length && isDigit(tail[i])) {
          final ref = _readRef(tail, i, tail.length);
          if (ref != null) return PdfRefToken(ref.obj, ref.gen);
        }
      }
    }
    i++;
  }
  return null;
}

({int offset, int gen})? _findObjectHeaderAnyGenReader(
  PdfRandomAccessReader reader,
  int objId,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return _findObjectHeaderAnyGen(reader.readAll(), objId);
  }

  final len = reader.length;
  final headSize = len > 16 * 1024 * 1024 ? 16 * 1024 * 1024 : len;
  final tailSize = len > 16 * 1024 * 1024 ? 16 * 1024 * 1024 : len;

  final head = _findObjectHeaderAnyGenInRangeReader(reader, objId, 0, headSize);
  if (head != null) return head;

  final tailStart = len - tailSize;
  final tail =
      _findObjectHeaderAnyGenInRangeReader(reader, objId, tailStart, len);
  if (tail != null) return tail;

  return _findObjectHeaderAnyGenByScanReader(reader, objId);
}

({int offset, int gen})? _findObjectHeaderAnyGenByScanReader(
  PdfRandomAccessReader reader,
  int objId,
) {
  const chunkSize = 1024 * 1024;
  const overlap = 64;
  int offset = 0;

  while (offset < reader.length) {
    final windowSize = (offset + chunkSize > reader.length)
        ? (reader.length - offset)
        : chunkSize;
    final window = reader.readRange(offset, windowSize);
    final found =
        _findObjectHeaderAnyGenInRange(window, objId, 0, window.length);
    if (found != null) {
      return (offset: offset + found.offset, gen: found.gen);
    }

    if (offset + chunkSize >= reader.length) break;
    offset += chunkSize - overlap;
  }

  return null;
}

({int offset, int gen})? _findObjectHeaderAnyGenInRangeReader(
  PdfRandomAccessReader reader,
  int objId,
  int start,
  int end,
) {
  final window = reader.readRange(start, end - start);
  final found = _findObjectHeaderAnyGenInRange(window, objId, 0, window.length);
  if (found == null) return null;
  return (offset: start + found.offset, gen: found.gen);
}

ScanDictInfo _scanObjectDictAndSkipStream(Uint8List bytes, int start) {
  int i = skipPdfWsAndComments(bytes, start, bytes.length);
  int? streamLength;
  bool isCatalog = false;

  if (i + 1 < bytes.length && bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
    final dict = readDictLight(bytes, i, bytes.length);
    streamLength = dict.length;
    isCatalog = dict.isCatalog;
    i = dict.nextIndex;
  }

  i = skipPdfWsAndComments(bytes, i, bytes.length);
  if (matchToken(bytes, i, const <int>[0x73, 0x74, 0x72, 0x65, 0x61, 0x6D])) {
    i += 6;
    if (i < bytes.length && bytes[i] == 0x0D) i++;
    if (i < bytes.length && bytes[i] == 0x0A) i++;

    if (streamLength != null && streamLength > 0) {
      final skipTo = i + streamLength;
      if (skipTo > i && skipTo < bytes.length) {
        i = skipTo;
      }
    }

    // fallback: scan endstream
    final endPos = indexOfSequence(bytes, endStreamToken, i, bytes.length);
    if (endPos != -1) {
      i = endPos + endStreamToken.length;
    }
  }

  return ScanDictInfo(i, isCatalog);
}

DictLightResult readDictLight(Uint8List bytes, int start, int end) {
  int i = start;
  if (i + 1 >= end || bytes[i] != 0x3C || bytes[i + 1] != 0x3C) {
    return DictLightResult(i, null, false);
  }
  i += 2;

  int? length;
  bool isCatalog = false;
  final limitEnd = (start + 4096 < end) ? (start + 4096) : end;

  const keyLength = [0x2F, 0x4C, 0x65, 0x6E, 0x67, 0x74, 0x68];
  const keyType = [0x2F, 0x54, 0x79, 0x70, 0x65];
  const valCatalog = [0x2F, 0x43, 0x61, 0x74, 0x61, 0x6C, 0x6F, 0x67];

  while (i < limitEnd) {
    i = skipPdfWsAndComments(bytes, i, limitEnd);
    if (i >= limitEnd) break;

    if (bytes[i] == 0x3E && i + 1 < limitEnd && bytes[i + 1] == 0x3E) {
      return DictLightResult(i + 2, length, isCatalog);
    }

    if (bytes[i] == 0x2F) {
      final isKeyLength = matchBytes(bytes, i, keyLength);
      final isKeyType = !isKeyLength && matchBytes(bytes, i, keyType);

      i = skipTokenRaw(bytes, i, limitEnd);
      i = skipPdfWsAndComments(bytes, i, limitEnd);
      if (i >= limitEnd) break;

      if (isKeyLength) {
        if (isDigit(bytes[i])) {
          final res = readIntFast(bytes, i, limitEnd);
          if (res.value != -1) {
            final possibleLen = res.value;
            int nextI = res.nextIndex;

            int k = skipPdfWsAndComments(bytes, nextI, limitEnd);
            bool isRef = false;
            if (k < limitEnd) {
              if (isDigit(bytes[k])) {
                final resGen = readIntFast(bytes, k, limitEnd);
                int afterGen =
                    skipPdfWsAndComments(bytes, resGen.nextIndex, limitEnd);
                if (afterGen < limitEnd && bytes[afterGen] == 0x52) {
                  isRef = true;
                  nextI = afterGen + 1;
                }
              } else if (bytes[k] == 0x52) {
                isRef = true;
                nextI = k + 1;
              }
            }

            if (!isRef) {
              length = possibleLen;
            }
            i = nextI;
            continue;
          }
        }
      } else if (isKeyType) {
        if (matchBytes(bytes, i, valCatalog)) {
          isCatalog = true;
        }
      }

      i = skipTokenRaw(bytes, i, limitEnd);
      continue;
    }

    i++;
  }

  return DictLightResult(i, length, isCatalog);
}

PdfRefToken? _findRootFromTail(Uint8List bytes) {
  final tailSize = bytes.length > 1024 * 1024 ? 1024 * 1024 : bytes.length;
  final start = bytes.length - tailSize;
  int i = start;
  while (i < bytes.length) {
    if (bytes[i] == 0x2F /* / */) {
      final name = readName(bytes, i, bytes.length);
      if (name.value == PdfKeys.root) {
        i = skipPdfWsAndComments(bytes, name.nextIndex, bytes.length);
        if (i < bytes.length && isDigit(bytes[i])) {
          final ref = _readRef(bytes, i, bytes.length);
          if (ref != null) return PdfRefToken(ref.obj, ref.gen);
        }
      }
    }
    i++;
  }
  return null;
}

({int offset, int gen})? _findObjectHeaderAnyGen(
  Uint8List bytes,
  int objId,
) {
  final headSize =
      bytes.length > 16 * 1024 * 1024 ? 16 * 1024 * 1024 : bytes.length;
  final tailSize =
      bytes.length > 16 * 1024 * 1024 ? 16 * 1024 * 1024 : bytes.length;

  final head = _findObjectHeaderAnyGenInRange(bytes, objId, 0, headSize);
  if (head != null) return head;

  final tailStart = bytes.length - tailSize;
  final tail =
      _findObjectHeaderAnyGenInRange(bytes, objId, tailStart, bytes.length);
  if (tail != null) return tail;

  return _findObjectHeaderAnyGenInRange(bytes, objId, 0, bytes.length);
}

({int offset, int gen})? _findObjectHeaderAnyGenInRange(
  Uint8List bytes,
  int objId,
  int start,
  int end,
) {
  int i = start;
  while (i < end) {
    i = skipPdfWsAndComments(bytes, i, end);
    if (i >= end) break;
    if (!isDigit(bytes[i])) {
      i++;
      continue;
    }
    try {
      final obj = readInt(bytes, i, end);
      if (obj.value != objId) {
        i = obj.nextIndex;
        continue;
      }
      int j = skipPdfWsAndComments(bytes, obj.nextIndex, end);
      if (j >= end || !isDigit(bytes[j])) {
        i = obj.nextIndex;
        continue;
      }
      final gen = readInt(bytes, j, end);
      j = skipPdfWsAndComments(bytes, gen.nextIndex, end);
      if (matchToken(bytes, j, const <int>[0x6F, 0x62, 0x6A])) {
        return (offset: i, gen: gen.value);
      }
      i = gen.nextIndex;
    } catch (_) {
      i++;
    }
  }
  return null;
}

bool _isValidObjAtOffset(Uint8List bytes, int objId, int gen, int offset) {
  if (offset < 0 || offset >= bytes.length) return false;
  int i = skipPdfWsAndComments(bytes, offset, bytes.length);
  if (i >= bytes.length || !isDigit(bytes[i])) return false;
  final obj = readInt(bytes, i, bytes.length);
  if (obj.value != objId) return false;
  i = skipPdfWsAndComments(bytes, obj.nextIndex, bytes.length);
  if (i >= bytes.length || !isDigit(bytes[i])) return false;
  final genRead = readInt(bytes, i, bytes.length);
  if (genRead.value != gen) return false;
  i = skipPdfWsAndComments(bytes, genRead.nextIndex, bytes.length);
  return matchToken(bytes, i, const <int>[0x6F, 0x62, 0x6A]);
}

int? _findObjectHeader(
  Uint8List bytes,
  int objId,
  int gen,
  int start,
  int end,
) {
  for (int i = start; i < end; i++) {
    if (!isDigit(bytes[i])) continue;
    try {
      final obj = readInt(bytes, i, end);
      if (obj.value != objId) continue;
      int j = skipPdfWsAndComments(bytes, obj.nextIndex, end);
      if (j >= end || !isDigit(bytes[j])) continue;
      final genRead = readInt(bytes, j, end);
      if (genRead.value != gen) continue;
      j = skipPdfWsAndComments(bytes, genRead.nextIndex, end);
      if (matchToken(bytes, j, const <int>[0x6F, 0x62, 0x6A])) {
        return i;
      }
    } catch (_) {
      // ignora e continua
    }
  }
  return null;
}

int _findDictEnd(Uint8List bytes, int start, int end) {
  int depth = 0;
  for (int i = start; i + 1 < end; i++) {
    if (bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
      depth++;
      i++;
      continue;
    }
    if (bytes[i] == 0x3E && bytes[i + 1] == 0x3E) {
      depth--;
      i++;
      if (depth == 0) return i + 1;
    }
  }
  return -1;
}

({int obj, int gen})? _readRef(Uint8List bytes, int i, int end) {
  if (!isDigit(bytes[i])) return null;
  final obj = readInt(bytes, i, end);
  i = skipPdfWsAndComments(bytes, obj.nextIndex, end);
  if (i >= end || !isDigit(bytes[i])) return null;
  final gen = readInt(bytes, i, end);
  i = skipPdfWsAndComments(bytes, gen.nextIndex, end);
  if (i >= end || bytes[i] != 0x52 /* R */) return null;
  return (obj: obj.value, gen: gen.value);
}

class TrailerDictValues {
  TrailerDictValues({
    this.size,
    this.prev,
    this.rootObj,
    this.infoObj,
    this.id,
  });
  final int? size;
  final int? prev;
  final int? rootObj;
  final int? infoObj;
  final Uint8List? id;
}

TrailerDictValues _parseTrailerDict(Uint8List bytes, int start, int end) {
  int i = start;
  int depth = 0;
  String? currentKey;
  int? size;
  int? prev;
  int? rootObj;
  int? infoObj;
  Uint8List? id;

  while (i < end) {
    if (i + 1 < end && bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
      depth++;
      i += 2;
      continue;
    }
    if (i + 1 < end && bytes[i] == 0x3E && bytes[i + 1] == 0x3E) {
      depth--;
      i += 2;
      if (depth <= 0) break;
      continue;
    }

    i = skipPdfWsAndComments(bytes, i, end);
    if (i >= end) break;

    if (bytes[i] == 0x2F /* / */) {
      final name = readName(bytes, i, end);
      currentKey = name.value;
      i = name.nextIndex;
      continue;
    }

    if (currentKey != null) {
      if (isDigit(bytes[i]) || bytes[i] == 0x2D) {
        final num = readInt(bytes, i, end);
        if (currentKey == PdfKeys.size) size = num.value;
        if (currentKey == PdfKeys.prev) prev = num.value;

        if (currentKey == PdfKeys.root || currentKey == PdfKeys.info) {
          final ref = _readRef(bytes, i, end);
          if (ref != null) {
            if (currentKey == PdfKeys.root) rootObj = ref.obj;
            if (currentKey == PdfKeys.info) infoObj = ref.obj;
          }
        }

        i = num.nextIndex;
        currentKey = null;
        continue;
      }

      if (currentKey == PdfKeys.id && bytes[i] == 0x5B /* [ */) {
        final parsed = readIdArray(bytes, i, end);
        id = parsed.id;
        i = parsed.nextIndex;
        currentKey = null;
        continue;
      }
    }

    i++;
  }

  return TrailerDictValues(
    size: size,
    prev: prev,
    rootObj: rootObj,
    infoObj: infoObj,
    id: id,
  );
}

ParsedIndirectObject? readIndirectObjectAt(
  Uint8List bytes,
  int offset,
  int end,
  PdfDocumentParser parser,
) {
  int i = skipPdfWsAndComments(bytes, offset, end);
  if (i >= end || !isDigit(bytes[i])) return null;
  final obj = readInt(bytes, i, end);
  i = skipPdfWsAndComments(bytes, obj.nextIndex, end);
  if (i >= end || !isDigit(bytes[i])) return null;
  final gen = readInt(bytes, i, end);
  i = skipPdfWsAndComments(bytes, gen.nextIndex, end);
  if (!matchToken(bytes, i, const <int>[0x6F, 0x62, 0x6A])) return null;
  i += 3;
  i = skipPdfWsAndComments(bytes, i, end);

  final parsed = parseObject(bytes, i, end);
  if (parsed == null) return null;

  Uint8List? streamData;
  if (parsed.value is PdfDictToken && parsed.dictEnd != null) {
    final dict = parsed.value as PdfDictToken;
    final length = resolveLength(dict, parser);
    final data = extractStream(bytes, parsed.dictEnd!, end, length);
    if (data != null) {
      streamData = data;
    }
  }

  return ParsedIndirectObject(
    objId: obj.value,
    gen: gen.value,
    value: parsed.value,
    streamData: streamData,
  );
}

ParsedIndirectObject? readIndirectObjectAtFromReader(
  PdfRandomAccessReader reader,
  int offset,
  PdfDocumentParser parser,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return readIndirectObjectAt(
        reader.readAll(), offset, reader.length, parser);
  }

  final len = reader.length;
  const windowSizes = <int>[
    8 * 1024,
    32 * 1024,
    128 * 1024,
    512 * 1024,
    2 * 1024 * 1024,
  ];
  for (final size in windowSizes) {
    if (offset < 0 || offset >= len) return null;
    final windowSize = (offset + size > len) ? (len - offset) : size;
    final window = reader.readRange(offset, windowSize);

    int i = skipPdfWsAndComments(window, 0, window.length);
    if (i >= window.length || !isDigit(window[i])) continue;
    final obj = readInt(window, i, window.length);
    i = skipPdfWsAndComments(window, obj.nextIndex, window.length);
    if (i >= window.length || !isDigit(window[i])) continue;
    final gen = readInt(window, i, window.length);
    i = skipPdfWsAndComments(window, gen.nextIndex, window.length);
    if (!matchToken(window, i, const <int>[0x6F, 0x62, 0x6A])) continue;
    i += 3;
    i = skipPdfWsAndComments(window, i, window.length);

    final parsed = parseObject(window, i, window.length);
    if (parsed == null) continue;

    Uint8List? streamData;
    if (parsed.value is PdfDictToken && parsed.dictEnd != null) {
      final dict = parsed.value as PdfDictToken;
      final length = resolveLength(dict, parser);
      final streamStart = _findStreamStart(window, parsed.dictEnd!);

      if (streamStart != null && length != null) {
        final abs = offset + streamStart;
        if (abs + length <= len) {
          streamData = reader.readRange(abs, length);
        }
      } else {
        final data =
            extractStream(window, parsed.dictEnd!, window.length, length);
        if (data != null) {
          streamData = data;
        }
      }
    }

    return ParsedIndirectObject(
      objId: obj.value,
      gen: gen.value,
      value: parsed.value,
      streamData: streamData,
    );
  }

  return null;
}

ParsedIndirectObject? readIndirectObjectAtFromReaderNoStream(
  PdfRandomAccessReader reader,
  int offset,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return readIndirectObjectAt(
        reader.readAll(), offset, reader.length, DummyParser());
  }

  final len = reader.length;
  const windowSizes = <int>[
    8 * 1024,
    32 * 1024,
    128 * 1024,
    512 * 1024,
    2 * 1024 * 1024,
  ];
  for (final size in windowSizes) {
    if (offset < 0 || offset >= len) return null;
    final windowSize = (offset + size > len) ? (len - offset) : size;
    final window = reader.readRange(offset, windowSize);

    int i = skipPdfWsAndComments(window, 0, window.length);
    if (i >= window.length || !isDigit(window[i])) continue;
    final obj = readInt(window, i, window.length);
    i = skipPdfWsAndComments(window, obj.nextIndex, window.length);
    if (i >= window.length || !isDigit(window[i])) continue;
    final gen = readInt(window, i, window.length);
    i = skipPdfWsAndComments(window, gen.nextIndex, window.length);
    if (!matchToken(window, i, const <int>[0x6F, 0x62, 0x6A])) continue;
    i += 3;
    i = skipPdfWsAndComments(window, i, window.length);

    final parsed = parseObject(window, i, window.length);
    if (parsed == null) continue;

    return ParsedIndirectObject(
      objId: obj.value,
      gen: gen.value,
      value: parsed.value,
      streamData: null,
    );
  }

  return null;
}

class DummyParser extends PdfDocumentParser {
  DummyParser() : super(Uint8List(0));
}

ParsedIndirectObject? readCompressedObject(
  int objId,
  XrefEntry entry,
  PdfDocumentParser parser,
) {
  final objStmId = entry.offset;
  final objStm = parser._getObject(objStmId);
  if (objStm == null || objStm.value is! PdfDictToken) return null;
  if (objStm.streamData == null) return null;

  final dict = objStm.value as PdfDictToken;
  final type = asName(dict.values[PdfKeys.type]);
  if (type != '/ObjStm') return null;

  final n = asInt(dict.values[PdfKeys.n]);
  final first = asInt(dict.values['/First']);
  if (n == null || first == null) return null;

  Uint8List data = objStm.streamData!;
  final filter = asName(dict.values[PdfKeys.filter]);
  if (filter == '/FlateDecode') {
    if (data.length > _maxStreamDecodeSize) return null;
    data = Uint8List.fromList(ZLibDecoder().decodeBytes(data));
  }

  final header = readObjectStreamHeader(data, n);
  if (header == null) return null;

  final entryIndex = header.index[objId];
  if (entryIndex == null) return null;

  final objOffset = first + entryIndex;
  if (objOffset < 0 || objOffset >= data.length) return null;

  final parsed = parseObject(data, objOffset, data.length);
  if (parsed == null) return null;

  return ParsedIndirectObject(
    objId: objId,
    gen: entry.gen,
    value: parsed.value,
    streamData: null,
  );
}

ObjStmHeader? readObjectStreamHeader(Uint8List data, int n) {
  int i = 0;
  final index = <int, int>{};
  for (int k = 0; k < n; k++) {
    i = skipPdfWsAndComments(data, i, data.length);
    final obj = readNumber(data, i, data.length);
    if (obj == null || obj.value is! int) return null;
    i = obj.nextIndex;

    i = skipPdfWsAndComments(data, i, data.length);
    final offset = readNumber(data, i, data.length);
    if (offset == null || offset.value is! int) return null;
    i = offset.nextIndex;

    index[obj.value as int] = offset.value as int;
  }
  return ObjStmHeader(index);
}

int? resolveLength(PdfDictToken dict, PdfDocumentParser parser) {
  final lenValue = dict.values[PdfKeys.length];
  if (lenValue is int) return lenValue;
  if (lenValue is double) return lenValue.toInt();
  if (lenValue is PdfRefToken) {
    final lenObj = parser._getObject(lenValue.obj);
    if (lenObj != null && lenObj.value is int) {
      return lenObj.value as int;
    }
  }
  return null;
}

ParseResult? parseObject(Uint8List bytes, int start, int end, {int depth = 0}) {
  if (depth > 64) return null;
  int i = skipPdfWsAndComments(bytes, start, end);
  if (i >= end) return null;

  final b = bytes[i];
  if (b == 0x2F /* / */) {
    final name = readName(bytes, i, end);
    return ParseResult(PdfNameToken(name.value), name.nextIndex);
  }
  if (b == 0x28 /* ( */) {
    final str = readLiteralString(bytes, i, end);
    return ParseResult(
        PdfStringToken(str.bytes, PdfStringFormat.literal), str.nextIndex);
  }
  if (b == 0x3C /* < */) {
    if (i + 1 < end && bytes[i + 1] == 0x3C) {
      final dict = readDict(bytes, i, end, depth: depth + 1);
      return ParseResult(dict.value, dict.nextIndex, dictEnd: dict.dictEnd);
    }
    final hex = readHexString(bytes, i, end);
    return ParseResult(
        PdfStringToken(hex.bytes, PdfStringFormat.binary), hex.nextIndex);
  }
  if (b == 0x5B /* [ */) {
    final arr = readArray(bytes, i, end, depth: depth + 1);
    return ParseResult(arr.value, arr.nextIndex);
  }
  if (isDigit(b) || b == 0x2D || b == 0x2B || b == 0x2E) {
    final num = readNumber(bytes, i, end);
    if (num == null) return null;

    final maybeRef = tryReadRefAfterNumber(bytes, num, end);
    if (maybeRef != null) {
      return ParseResult(maybeRef.value, maybeRef.nextIndex);
    }
    return ParseResult(num.value, num.nextIndex);
  }

  if (matchToken(bytes, i, const <int>[0x74, 0x72, 0x75, 0x65])) {
    return ParseResult(true, i + 4);
  }
  if (matchToken(bytes, i, const <int>[0x66, 0x61, 0x6C, 0x73, 0x65])) {
    return ParseResult(false, i + 5);
  }
  if (matchToken(bytes, i, const <int>[0x6E, 0x75, 0x6C, 0x6C])) {
    return ParseResult(null, i + 4);
  }

  return null;
}

ParseResult readDict(Uint8List bytes, int start, int end, {int depth = 0}) {
  int i = start;
  if (bytes[i] != 0x3C || bytes[i + 1] != 0x3C) {
    return ParseResult(PdfDictToken(<String, dynamic>{}), i);
  }
  i += 2;
  final values = <String, dynamic>{};
  while (i < end) {
    i = skipPdfWsAndComments(bytes, i, end);
    if (i + 1 < end && bytes[i] == 0x3E && bytes[i + 1] == 0x3E) {
      i += 2;
      return ParseResult(PdfDictToken(values), i, dictEnd: i);
    }

    if (bytes[i] == 0x2F) {
      final key = readName(bytes, i, end);
      i = skipPdfWsAndComments(bytes, key.nextIndex, end);
      final value = parseObject(bytes, i, end, depth: depth + 1);
      if (value != null) {
        values[key.value] = value.value;
        i = value.nextIndex;
        continue;
      }
    }
    i++;
  }
  return ParseResult(PdfDictToken(values), i);
}

ParseResult readArray(Uint8List bytes, int start, int end, {int depth = 0}) {
  int i = start;
  if (bytes[i] != 0x5B) {
    return ParseResult(PdfArrayToken(<dynamic>[]), i);
  }
  i++;
  final values = <dynamic>[];
  while (i < end) {
    i = skipPdfWsAndComments(bytes, i, end);
    if (i < end && bytes[i] == 0x5D) {
      i++;
      break;
    }
    final value = parseObject(bytes, i, end, depth: depth + 1);
    if (value != null) {
      values.add(value.value);
      i = value.nextIndex;
      continue;
    }
    i++;
  }
  return ParseResult(PdfArrayToken(values), i);
}

({dynamic value, int nextIndex})? tryReadRefAfterNumber(
  Uint8List bytes,
  ({dynamic value, int nextIndex}) first,
  int end,
) {
  if (first.value is! int) return null;
  int i = skipPdfWsAndComments(bytes, first.nextIndex, end);
  if (i >= end || !isDigit(bytes[i])) return null;
  final gen = readInt(bytes, i, end);
  i = skipPdfWsAndComments(bytes, gen.nextIndex, end);
  if (i < end && bytes[i] == 0x52 /* R */) {
    return (
      value: PdfRefToken(first.value as int, gen.value),
      nextIndex: i + 1
    );
  }
  return null;
}

({dynamic value, int nextIndex})? readNumber(
  Uint8List bytes,
  int start,
  int end,
) {
  int i = start;
  final buffer = StringBuffer();
  if (i < end && (bytes[i] == 0x2B || bytes[i] == 0x2D)) {
    buffer.writeCharCode(bytes[i]);
    i++;
  }
  bool hasDot = false;
  while (i < end) {
    final b = bytes[i];
    if (isDigit(b)) {
      buffer.writeCharCode(b);
      i++;
      continue;
    }
    if (b == 0x2E /* . */ && !hasDot) {
      hasDot = true;
      buffer.writeCharCode(b);
      i++;
      continue;
    }
    break;
  }
  if (buffer.isEmpty) return null;
  final text = buffer.toString();
  if (hasDot) {
    return (value: double.tryParse(text) ?? 0.0, nextIndex: i);
  }
  return (value: int.tryParse(text) ?? 0, nextIndex: i);
}

({Uint8List bytes, int nextIndex}) readLiteralString(
  Uint8List bytes,
  int start,
  int end,
) {
  int i = start;
  if (bytes[i] != 0x28) {
    return (bytes: Uint8List(0), nextIndex: i);
  }
  i++;
  final out = <int>[];
  int depth = 1;
  while (i < end && depth > 0) {
    final b = bytes[i];
    if (b == 0x5C /* \\ */) {
      if (i + 1 >= end) break;
      final n = bytes[i + 1];
      if (n == 0x6E) {
        out.add(0x0A);
        i += 2;
        continue;
      }
      if (n == 0x72) {
        out.add(0x0D);
        i += 2;
        continue;
      }
      if (n == 0x74) {
        out.add(0x09);
        i += 2;
        continue;
      }
      if (n == 0x62) {
        out.add(0x08);
        i += 2;
        continue;
      }
      if (n == 0x66) {
        out.add(0x0C);
        i += 2;
        continue;
      }
      if (n == 0x28 || n == 0x29 || n == 0x5C) {
        out.add(n);
        i += 2;
        continue;
      }
      // octal sequence
      if (n >= 0x30 && n <= 0x37) {
        int val = n - 0x30;
        int count = 1;
        int j = i + 2;
        while (j < end && count < 3) {
          final o = bytes[j];
          if (o < 0x30 || o > 0x37) break;
          val = (val << 3) | (o - 0x30);
          j++;
          count++;
        }
        out.add(val & 0xFF);
        i = j;
        continue;
      }
      i += 2;
      continue;
    }
    if (b == 0x28) {
      depth++;
      out.add(b);
      i++;
      continue;
    }
    if (b == 0x29) {
      depth--;
      if (depth > 0) out.add(b);
      i++;
      continue;
    }
    out.add(b);
    i++;
  }
  return (bytes: Uint8List.fromList(out), nextIndex: i);
}

PdfDict<PdfDataType> toPdfDict(
  PdfDictToken dict, {
  Set<String> ignoreKeys = const {},
}) {
  final values = <String, PdfDataType>{};
  for (final entry in dict.values.entries) {
    if (ignoreKeys.contains(entry.key)) continue;
    final converted = toPdfDataType(entry.value);
    if (converted != null) values[entry.key] = converted;
  }
  return PdfDict.values(values);
}

PdfArray toPdfArray(PdfArrayToken array) {
  final values = <PdfDataType>[];
  for (final v in array.values) {
    final converted = toPdfDataType(v);
    if (converted != null) values.add(converted);
  }
  return PdfArray(values);
}

PdfDataType? toPdfDataType(dynamic value) {
  if (value == null) return const PdfNull();
  if (value is bool) return PdfBool(value);
  if (value is int || value is double) {
    return PdfNum(value is int ? value : (value as double));
  }
  if (value is PdfNameToken) return PdfName(value.value);
  if (value is PdfStringToken) {
    return PdfString(value.bytes, format: value.format, encrypted: false);
  }
  if (value is PdfRefToken) return PdfIndirect(value.obj, value.gen);
  if (value is PdfArrayToken) return toPdfArray(value);
  if (value is PdfDictToken) return toPdfDict(value);
  return null;
}

void mergeDictIntoPdfDict(
  PdfDict<PdfDataType> target,
  PdfDictToken source, {
  Set<String> ignoreKeys = const {},
}) {
  final converted = toPdfDict(source);
  for (final entry in converted.values.entries) {
    if (ignoreKeys.contains(entry.key)) continue;
    target[entry.key] = entry.value;
  }
}

PdfRefToken? asRef(dynamic value) {
  if (value is PdfRefToken) return value;
  return null;
}

String? asName(dynamic value) {
  if (value is PdfNameToken) return value.value;
  return null;
}

int? asInt(dynamic value) {
  if (value is int) return value;
  if (value is double) return value.toInt();
  return null;
}

List<double>? asNumArray(dynamic value) {
  if (value is PdfArrayToken && value.values.length >= 4) {
    final nums = <double>[];
    for (int i = 0; i < 4; i++) {
      final v = value.values[i];
      if (v is int) nums.add(v.toDouble());
      if (v is double) nums.add(v);
    }
    if (nums.length == 4) return nums;
  }
  return null;
}

PdfPageFormat? pageFormatFromBox(List<double>? box) {
  if (box == null || box.length < 4) return null;
  final width = box[2] - box[0];
  final height = box[3] - box[1];
  if (width <= 0 || height <= 0) return null;
  return PdfPageFormat(width, height);
}

PdfPageRotation pageRotationFromValue(dynamic value) {
  final rot = asInt(value) ?? 0;
  switch (rot % 360) {
    case 90:
      return PdfPageRotation.rotate90;
    case 180:
      return PdfPageRotation.rotate180;
    case 270:
      return PdfPageRotation.rotate270;
    default:
      return PdfPageRotation.none;
  }
}

({Uint8List? id, int nextIndex}) readIdArray(
  Uint8List bytes,
  int start,
  int end,
) {
  int i = start;
  if (bytes[i] != 0x5B) return (id: null, nextIndex: i);
  i++;
  i = skipPdfWsAndComments(bytes, i, end);
  if (i >= end || bytes[i] != 0x3C) return (id: null, nextIndex: i);
  final id1 = readHexString(bytes, i, end);
  i = id1.nextIndex;
  return (id: id1.bytes, nextIndex: i);
}

({Uint8List bytes, int nextIndex}) readHexString(
  Uint8List bytes,
  int start,
  int end,
) {
  int i = start;
  if (bytes[i] != 0x3C) {
    throw StateError('Hex string inválida');
  }
  i++;
  final hex = <int>[];
  while (i < end && bytes[i] != 0x3E) {
    final b = bytes[i];
    if (isWhitespace(b)) {
      i++;
      continue;
    }
    hex.add(b);
    i++;
  }
  if (i >= end) throw StateError('Hex string inválida');
  i++;
  return (bytes: hexToBytes(hex), nextIndex: i);
}

Uint8List hexToBytes(List<int> hexBytes) {
  final out = Uint8List((hexBytes.length + 1) ~/ 2);
  int oi = 0;
  for (int i = 0; i < hexBytes.length; i += 2) {
    final hi = hexBytes[i];
    final lo = (i + 1 < hexBytes.length) ? hexBytes[i + 1] : 0x30;
    out[oi++] = (hexValue(hi) << 4) | hexValue(lo);
  }
  return out;
}

int hexValue(int b) {
  if (b >= 0x30 && b <= 0x39) return b - 0x30;
  if (b >= 0x41 && b <= 0x46) return b - 0x41 + 10;
  if (b >= 0x61 && b <= 0x66) return b - 0x61 + 10;
  return 0;
}

class PdfQuickInfo {
  PdfQuickInfo._({
    required this.isPdf15OrAbove,
    required this.hasSignatures,
    required this.docMdpPermissionP,
  });

  final bool isPdf15OrAbove;
  final bool hasSignatures;
  final int? docMdpPermissionP;

  static PdfQuickInfo fromBytes(Uint8List bytes) {
    final version = readPdfVersion(bytes);
    final isPdf15OrAbove = version >= 1.5;
    final hasSignatures = findByteRangeToken(bytes) != -1;

    int? permissionP;
    try {
      final parser = PdfDocumentParser(bytes);
      permissionP = _extractDocMdpPermission(parser);
    } catch (_) {
      permissionP = null;
    }
    permissionP ??= extractDocMdpPermissionFromBytes(bytes);

    return PdfQuickInfo._(
      isPdf15OrAbove: isPdf15OrAbove,
      hasSignatures: hasSignatures,
      docMdpPermissionP: permissionP,
    );
  }
}

double readPdfVersion(Uint8List bytes) {
  const token = <int>[0x25, 0x50, 0x44, 0x46, 0x2D]; // %PDF-
  final limit = bytes.length > 1024 ? 1024 : bytes.length;
  final pos = indexOfSequence(bytes, token, 0, limit);
  if (pos == -1 || pos + 8 > limit) return 1.4;

  final major = bytes[pos + 5];
  final dot = bytes[pos + 6];
  final minor = bytes[pos + 7];
  if (dot != 0x2E /* . */) return 1.4;
  if (major < 0x30 || major > 0x39) return 1.4;
  if (minor < 0x30 || minor > 0x39) return 1.4;
  final majorVal = major - 0x30;
  final minorVal = minor - 0x30;
  return majorVal + (minorVal / 10.0);
}

int findByteRangeToken(Uint8List bytes) {
  const token = <int>[
    0x2F, // /
    0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65, // ByteRange
  ];
  return indexOfSequence(bytes, token, 0, bytes.length);
}

int? _extractDocMdpPermission(PdfDocumentParser parser) {
  parser._ensureXrefParsed();
  final trailer = parser._trailerInfo ??
      _readTrailerInfoFromReader(parser.reader, parser.xrefOffset);
  final rootObjId = trailer.rootObj;
  if (rootObjId == null) return null;

  final rootObj =
      parser._getObjectNoStream(rootObjId) ?? parser._getObject(rootObjId);
  if (rootObj == null || rootObj.value is! PdfDictToken) return null;
  final rootDict = rootObj.value as PdfDictToken;

  final permsDict =
      parser._resolveDictFromValueNoStream(rootDict.values['/Perms']);
  if (permsDict == null) return null;

  dynamic docMdpVal = permsDict.values['/DocMDP'];
  if (docMdpVal is PdfRefToken) {
    final docObj = parser._getObjectNoStream(docMdpVal.obj) ??
        parser._getObject(docMdpVal.obj);
    docMdpVal = docObj?.value;
  }
  if (docMdpVal is! PdfDictToken) return null;

  final refVal = docMdpVal.values['/Reference'];
  if (refVal is! PdfArrayToken) return null;

  for (final item in refVal.values) {
    dynamic refItem = item;
    if (refItem is PdfRefToken) {
      final refObj = parser._getObjectNoStream(refItem.obj) ??
          parser._getObject(refItem.obj);
      refItem = refObj?.value;
    }
    if (refItem is! PdfDictToken) continue;
    dynamic tp = refItem.values['/TransformParams'];
    if (tp is PdfRefToken) {
      final tpObj =
          parser._getObjectNoStream(tp.obj) ?? parser._getObject(tp.obj);
      tp = tpObj?.value;
    }
    if (tp is! PdfDictToken) continue;
    final p = asInt(tp.values[PdfKeys.p]);
    if (p != null) return p;
  }

  return null;
}

int? extractDocMdpPermissionFromBytes(Uint8List bytes) {
  const docMdpToken = <int>[
    0x2F, // /
    0x44, 0x6F, 0x63, 0x4D, 0x44, 0x50, // DocMDP
  ];
  const pToken = <int>[0x2F, 0x50]; // /P

  int offset = 0;
  while (offset < bytes.length) {
    final pos = indexOfSequence(bytes, docMdpToken, offset, bytes.length);
    if (pos == -1) break;
    final windowStart = pos;
    final windowEnd = (pos + 4096 < bytes.length) ? (pos + 4096) : bytes.length;
    final pPos = indexOfSequence(bytes, pToken, windowStart, windowEnd);
    if (pPos != -1) {
      try {
        int i = pPos + pToken.length;
        i = skipPdfWsAndComments(bytes, i, windowEnd);
        final parsed = readInt(bytes, i, windowEnd);
        if (parsed.value >= 1 && parsed.value <= 3) {
          return parsed.value;
        }
      } catch (_) {}
    }
    offset = pos + docMdpToken.length;
  }
  return null;
}

List<PdfSignatureFieldInfo> extractSignatureFieldsFromBytes(Uint8List bytes) {
  final ranges = findAllByteRangesFromBytes(bytes);
  if (ranges.isEmpty) return const <PdfSignatureFieldInfo>[];

  final out = <PdfSignatureFieldInfo>[];
  for (final range in ranges) {
    final gapStart = range[0] + range[1];
    final gapEnd = range[2];
    const windowSize = 524288;
    final windowStart = gapStart - windowSize >= 0 ? gapStart - windowSize : 0;
    final windowEnd = gapEnd + windowSize <= bytes.length
        ? gapEnd + windowSize
        : bytes.length;
    final window = bytes.sublist(windowStart, windowEnd);

    final fieldName = scanPdfStringValue(window, const <int>[
      0x2F, 0x54 // /T
    ]);
    final reason = scanPdfStringValue(window, const <int>[
      0x2F, 0x52, 0x65, 0x61, 0x73, 0x6F, 0x6E // /Reason
    ]);
    final location = scanPdfStringValue(window, const <int>[
      0x2F, 0x4C, 0x6F, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E // /Location
    ]);
    final name = scanPdfStringValue(window, const <int>[
      0x2F, 0x4E, 0x61, 0x6D, 0x65 // /Name
    ]);
    final signingTime = scanPdfStringValue(window, const <int>[
      0x2F, 0x4D // /M
    ]);
    final filter = scanPdfNameValue(window, const <int>[
      0x2F, 0x46, 0x69, 0x6C, 0x74, 0x65, 0x72 // /Filter
    ]);
    final subFilter = scanPdfNameValue(window, const <int>[
      0x2F, 0x53, 0x75, 0x62, 0x46, 0x69, 0x6C, 0x74, 0x65, 0x72 // /SubFilter
    ]);

    out.add(PdfSignatureFieldInfo(
      fieldName: fieldName,
      reason: reason,
      location: location,
      name: name,
      signingTimeRaw: signingTime,
      filter: filter,
      subFilter: subFilter,
      byteRange: range,
      signatureDictionaryPresent: true,
    ));
  }
  return out;
}

List<List<int>> findAllByteRangesFromBytes(Uint8List bytes) {
  const token = <int>[
    0x2F,
    0x42,
    0x79,
    0x74,
    0x65,
    0x52,
    0x61,
    0x6E,
    0x67,
    0x65
  ];
  final out = <List<int>>[];
  var offset = 0;
  while (offset < bytes.length) {
    final pos = indexOfSequence(bytes, token, offset, bytes.length);
    if (pos == -1) break;
    var i = skipPdfWsAndComments(bytes, pos + token.length, bytes.length);
    if (i >= bytes.length || bytes[i] != 0x5B) {
      offset = pos + token.length;
      continue;
    }
    i++;
    final nums = <int>[];
    while (i < bytes.length && nums.length < 4) {
      i = skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length) break;
      if (bytes[i] == 0x5D) {
        i++;
        break;
      }
      try {
        final parsed = readInt(bytes, i, bytes.length);
        nums.add(parsed.value);
        i = parsed.nextIndex;
      } catch (_) {
        i++;
      }
    }
    if (nums.length == 4) {
      out.add(nums);
    }
    offset = pos + token.length;
  }
  return out;
}

String? scanPdfStringValue(Uint8List bytes, List<int> key) {
  final pos = indexOfSequence(bytes, key, 0, bytes.length);
  if (pos == -1) return null;
  var i = skipPdfWsAndComments(bytes, pos + key.length, bytes.length);
  if (i >= bytes.length) return null;
  if (bytes[i] == 0x28) {
    final parsed = readLiteralString(bytes, i, bytes.length);
    return decodePdfString(parsed.bytes);
  }
  if (bytes[i] == 0x3C) {
    try {
      final hex = readHexString(bytes, i, bytes.length);
      return decodePdfString(hex.bytes);
    } catch (_) {
      return null;
    }
  }
  if (bytes[i] == 0x2F) {
    i++;
    final start = i;
    while (i < bytes.length &&
        !isWhitespace(bytes[i]) &&
        bytes[i] != 0x2F &&
        bytes[i] != 0x3E &&
        bytes[i] != 0x3C &&
        bytes[i] != 0x28 &&
        bytes[i] != 0x29 &&
        bytes[i] != 0x5B &&
        bytes[i] != 0x5D) {
      i++;
    }
    return String.fromCharCodes(bytes.sublist(start, i));
  }
  return null;
}

String? scanPdfNameValue(Uint8List bytes, List<int> key) {
  final pos = indexOfSequence(bytes, key, 0, bytes.length);
  if (pos == -1) return null;
  var i = skipPdfWsAndComments(bytes, pos + key.length, bytes.length);
  if (i >= bytes.length || bytes[i] != 0x2F) return null;
  i++;
  final start = i;
  while (i < bytes.length &&
      !isWhitespace(bytes[i]) &&
      bytes[i] != 0x2F &&
      bytes[i] != 0x3E &&
      bytes[i] != 0x3C &&
      bytes[i] != 0x28 &&
      bytes[i] != 0x29 &&
      bytes[i] != 0x5B &&
      bytes[i] != 0x5D) {
    i++;
  }
  if (i <= start) return null;
  return '/' + String.fromCharCodes(bytes.sublist(start, i));
}

int _maxObjectId(Uint8List bytes) {
  var maxId = 0;
  var i = 0;
  while (i < bytes.length) {
    i = skipPdfWsAndComments(bytes, i, bytes.length);
    if (i >= bytes.length) break;

    // Leitura do número do objeto.
    if (!isDigit(bytes[i])) {
      i++;
      continue;
    }
    final objNum = readInt(bytes, i, bytes.length);
    i = objNum.nextIndex;

    i = skipPdfWsAndComments(bytes, i, bytes.length);
    if (i >= bytes.length || !isDigit(bytes[i])) {
      continue;
    }
    final genNum = readInt(bytes, i, bytes.length);
    i = genNum.nextIndex;

    i = skipPdfWsAndComments(bytes, i, bytes.length);
    if (i + 2 < bytes.length &&
        bytes[i] == 0x6F &&
        bytes[i + 1] == 0x62 &&
        bytes[i + 2] == 0x6A &&
        isDelimiter(bytes, i + 3)) {
      if (objNum.value > maxId) {
        maxId = objNum.value;
      }
    }
  }
  return maxId;
}

int _maxObjectIdFromReader(PdfRandomAccessReader reader) {
  if (reader is PdfMemoryRandomAccessReader) {
    return _maxObjectId(reader.readAll());
  }

  const chunkSize = 1024 * 1024;
  const overlap = 64;
  int offset = 0;
  int maxId = 0;

  while (offset < reader.length) {
    final windowSize = (offset + chunkSize > reader.length)
        ? (reader.length - offset)
        : chunkSize;
    final window = reader.readRange(offset, windowSize);
    int i = 0;

    while (i < window.length) {
      i = skipPdfWsAndComments(window, i, window.length);
      if (i >= window.length) break;

      if (!isDigit(window[i])) {
        i++;
        continue;
      }
      try {
        final objNum = readInt(window, i, window.length);
        i = objNum.nextIndex;
        i = skipPdfWsAndComments(window, i, window.length);
        if (i >= window.length || !isDigit(window[i])) continue;
        final genNum = readInt(window, i, window.length);
        i = genNum.nextIndex;
        i = skipPdfWsAndComments(window, i, window.length);
        if (matchToken(window, i, const <int>[0x6F, 0x62, 0x6A])) {
          if (objNum.value > maxId) maxId = objNum.value;
        }
      } catch (_) {
        i++;
      }
    }

    if (offset + chunkSize >= reader.length) break;
    offset += chunkSize - overlap;
  }

  return maxId;
}

int lastIndexOfSequence(
  Uint8List bytes,
  List<int> pattern,
  int start,
  int end,
) {
  if (pattern.isEmpty) return -1;
  final int max = end - pattern.length;
  for (int i = max; i >= start; i--) {
    var ok = true;
    for (int j = 0; j < pattern.length; j++) {
      if (bytes[i + j] != pattern[j]) {
        ok = false;
        break;
      }
    }
    if (ok) return i;
  }
  return -1;
}

int indexOfSequence(
  Uint8List bytes,
  List<int> pattern,
  int start,
  int end,
) {
  return indexOfSequenceBmh(bytes, pattern, start, end);
}

int indexOfSequenceBmh(
  Uint8List bytes,
  List<int> pattern,
  int start,
  int end,
) {
  if (pattern.isEmpty) return -1;
  final m = pattern.length;
  final last = m - 1;
  final limit = end - m;
  if (limit < start) return -1;

  final skip = List<int>.filled(256, m);
  for (int i = 0; i < last; i++) {
    skip[pattern[i] & 0xFF] = last - i;
  }

  int i = start;
  while (i <= limit) {
    int j = last;
    while (j >= 0 && bytes[i + j] == pattern[j]) {
      j--;
    }
    if (j < 0) return i;
    i += skip[bytes[i + last] & 0xFF];
  }
  return -1;
}

int skipPdfWsAndComments(Uint8List bytes, int i, int end) {
  if (i < end) {
    final b = bytes[i];
    if (!isWhitespace(b) && b != 0x25) {
      return i;
    }
  }
  while (i < end) {
    final b = bytes[i];
    if (isWhitespace(b)) {
      i++;
      continue;
    }
    if (b == 0x25 /* % */) {
      i++;
      while (i < end) {
        final c = bytes[i];
        if (c == 0x0A || c == 0x0D) break;
        i++;
      }
      continue;
    }
    break;
  }
  return i;
}

({int value, int nextIndex}) readIntFast(Uint8List bytes, int start, int end) {
  int i = start;
  if (i < end && bytes[i] == 0x2B) i++;

  int value = 0;
  bool hasDigits = false;

  while (i < end) {
    final b = bytes[i];
    if (b >= 0x30 && b <= 0x39) {
      if (value > 900719925474099) {
        i++;
        continue;
      }
      value = (value * 10) + (b - 0x30);
      hasDigits = true;
      i++;
    } else {
      break;
    }
  }

  if (!hasDigits) return (value: -1, nextIndex: start);
  return (value: value, nextIndex: i);
}

bool matchBytes(Uint8List bytes, int offset, List<int> target) {
  if (offset + target.length > bytes.length) return false;
  for (int i = 0; i < target.length; i++) {
    if (bytes[offset + i] != target[i]) return false;
  }
  return true;
}

int skipTokenRaw(Uint8List bytes, int i, int end) {
  i = skipPdfWsAndComments(bytes, i, end);
  if (i >= end) return i;

  final b = bytes[i];

  if (b == 0x2F) {
    i++;
    while (i < end) {
      final c = bytes[i];
      if (isWhitespace(c) ||
          c == 0x2F ||
          c == 0x3C ||
          c == 0x3E ||
          c == 0x28 ||
          c == 0x29 ||
          c == 0x5B ||
          c == 0x5D ||
          c == 0x25) {
        break;
      }
      i++;
    }
    return i;
  }

  if (b == 0x28) {
    int depth = 1;
    i++;
    while (i < end && depth > 0) {
      final c = bytes[i];
      if (c == 0x5C) {
        i += 2;
        continue;
      }
      if (c == 0x28) depth++;
      if (c == 0x29) depth--;
      i++;
    }
    return i;
  }

  if (b == 0x3C && i + 1 < end && bytes[i + 1] == 0x3C) {
    int depth = 1;
    i += 2;
    while (i + 1 < end && depth > 0) {
      if (bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
        depth++;
        i += 2;
        continue;
      }
      if (bytes[i] == 0x3E && bytes[i + 1] == 0x3E) {
        depth--;
        i += 2;
        continue;
      }
      i++;
    }
    return i;
  }

  if (b == 0x3C) {
    i++;
    while (i < end && bytes[i] != 0x3E) i++;
    if (i < end) i++;
    return i;
  }

  if (b == 0x5B) {
    int depth = 1;
    i++;
    while (i < end && depth > 0) {
      if (bytes[i] == 0x5B) depth++;
      if (bytes[i] == 0x5D) depth--;
      i++;
    }
    return i;
  }

  while (i < end) {
    final c = bytes[i];
    if (isWhitespace(c) ||
        c == 0x2F ||
        c == 0x28 ||
        c == 0x3C ||
        c == 0x5B ||
        c == 0x25) break;
    i++;
  }
  return i;
}

({int value, int nextIndex}) readInt(Uint8List bytes, int i, int end) {
  if (i >= end) {
    throw StateError('Fim inesperado ao ler inteiro');
  }
  var neg = false;
  if (bytes[i] == 0x2B /* + */) {
    i++;
  } else if (bytes[i] == 0x2D /* - */) {
    neg = true;
    i++;
  }
  var value = 0;
  var digits = 0;
  while (i < end) {
    final b = bytes[i];
    if (!isDigit(b)) break;
    value = (value * 10) + (b - 0x30);
    i++;
    digits++;
  }
  if (digits == 0) {
    throw StateError('Inteiro inválido');
  }
  return (value: neg ? -value : value, nextIndex: i);
}

bool isDigit(int b) => b >= 0x30 && b <= 0x39;

bool isHexDigit(int b) =>
    (b >= 0x30 && b <= 0x39) ||
    (b >= 0x41 && b <= 0x46) ||
    (b >= 0x61 && b <= 0x66);

bool isWhitespace(int b) =>
    b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0C || b == 0x0D || b == 0x20;

bool isDelimiter(Uint8List bytes, int index) {
  if (index >= bytes.length) return true;
  final b = bytes[index];
  return isWhitespace(b) ||
      b == 0x3C ||
      b == 0x3E ||
      b == 0x2F ||
      b == 0x28 ||
      b == 0x29;
}
