//C:\MyDartProjects\pdf_plus\lib\src\pdf\parsing\pdf_document_parser.dart

import 'dart:convert';
import 'dart:typed_data';
import 'package:archive/archive.dart';

import '../document.dart';
import '../document_parser.dart';
import '../format/object_base.dart';
import '../io/pdf_random_access_reader.dart';
import '../obj/catalog.dart';
import '../obj/page.dart';
import '../obj/page_list.dart';
import '../page_format.dart';
import 'pdf_document_info.dart';

import 'pdf_parser_types.dart';
import 'parser_xref.dart';
import 'parser_fields.dart';
import 'parser_objects.dart';
import 'parser_pages.dart';
import 'parser_scan.dart';
import 'parser_tokens.dart';
import 'package:pdf_plus/src/pdf/pdf_names.dart';

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
    _cachedSize ??= PdfParserXref.computeSizeFromReader(reader, _trailerInfo);
    return _cachedSize!;
  }

  @override
  int get xrefOffset {
    _cachedXrefOffset ??= PdfParserXref.computeXrefOffsetFromReader(reader);
    return _cachedXrefOffset!;
  }

  @override
  PdfVersion get version => PdfVersion.pdf_1_4;

  PdfDocumentInfo extractInfo({int? maxPages}) {
    _ensureXrefParsed();

    final trailer = _trailerInfo ??
        PdfParserXref.readTrailerInfoFromReader(reader, xrefOffset);
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
    final pagesRef =
        PdfParserObjects.asRef(rootDict.values[PdfNameTokens.pages]);
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
            resDict != null ? resDict.values[PdfNameTokens.xObject] : null;
        final xObjectDict = _resolveDictFromValueNoStream(xObject);
        if (xObjectDict != null) {
          final usedXObjects = _extractXObjectNamesFromContent(pageDict);
          for (final entry in xObjectDict.values.entries) {
            if (usedXObjects.isNotEmpty && !usedXObjects.contains(entry.key)) {
              continue;
            }
            final ref = PdfParserObjects.asRef(entry.value);
            if (ref == null) continue;
            final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
            if (obj == null || obj.value is! PdfDictToken) continue;
            final dict = obj.value as PdfDictToken;
            final subtype =
                PdfParserObjects.asName(dict.values[PdfNameTokens.subtype]);
            if (subtype != PdfNameTokens.image) continue;

            final filter = _asFilterName(dict.values[PdfNameTokens.filter]);
            final colorSpace =
                _asColorSpaceName(dict.values[PdfNameTokens.colorSpace]);
            images.add(PdfImageInfo(
              pageIndex: i + 1,
              pageRef: PdfIndirectRef(pageRef.obj, pageRef.gen),
              imageRef: PdfIndirectRef(ref.obj, ref.gen),
              width: PdfParserObjects.asInt(dict.values[PdfNameTokens.width]),
              height: PdfParserObjects.asInt(dict.values[PdfNameTokens.height]),
              bitsPerComponent: PdfParserObjects.asInt(
                  dict.values[PdfNameTokens.bitsPerComponent]),
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

    final trailer = _trailerInfo ??
        PdfParserXref.readTrailerInfoFromReader(reader, xrefOffset);
    final rootObjId = trailer.rootObj;
    if (rootObjId == null) return const <PdfImageInfo>[];

    final rootObj = _getObjectNoStream(rootObjId) ?? _getObject(rootObjId);
    if (rootObj == null || rootObj.value is! PdfDictToken) {
      return const <PdfImageInfo>[];
    }

    final rootDict = rootObj.value as PdfDictToken;
    final pagesRef =
        PdfParserObjects.asRef(rootDict.values[PdfNameTokens.pages]);
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
      final xObject =
          resDict != null ? resDict.values[PdfNameTokens.xObject] : null;
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
        final ref = PdfParserObjects.asRef(entry.value);
        if (ref == null) continue;
        final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
        if (obj == null || obj.value is! PdfDictToken) continue;
        final dict = obj.value as PdfDictToken;
        final subtype =
            PdfParserObjects.asName(dict.values[PdfNameTokens.subtype]);
        if (subtype != PdfNameTokens.image) continue;

        final filter = _asFilterName(dict.values[PdfNameTokens.filter]);
        final colorSpace =
            _asColorSpaceName(dict.values[PdfNameTokens.colorSpace]);
        images.add(PdfImageInfo(
          pageIndex: pageIndex,
          pageRef: PdfIndirectRef(pageRef.obj, pageRef.gen),
          imageRef: PdfIndirectRef(ref.obj, ref.gen),
          width: PdfParserObjects.asInt(dict.values[PdfNameTokens.width]),
          height: PdfParserObjects.asInt(dict.values[PdfNameTokens.height]),
          bitsPerComponent: PdfParserObjects.asInt(
              dict.values[PdfNameTokens.bitsPerComponent]),
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
      final trailer = _trailerInfo ??
          PdfParserXref.readTrailerInfoFromReader(reader, xrefOffset);
      final rootObjId = trailer.rootObj;
      if (rootObjId == null) return const <PdfSignatureFieldInfo>[];

      final rootObj = _getObjectNoStream(rootObjId) ?? _getObject(rootObjId);
      if (rootObj == null || rootObj.value is! PdfDictToken) {
        return const <PdfSignatureFieldInfo>[];
      }
      final rootDict = rootObj.value as PdfDictToken;
      final acroForm = _resolveDictFromValueNoStream(
              rootDict.values[PdfNameTokens.acroForm]) ??
          _resolveDictFromValueFull(rootDict.values[PdfNameTokens.acroForm]);
      if (acroForm == null) return const <PdfSignatureFieldInfo>[];

      final fieldsVal = acroForm.values[PdfNameTokens.fields];
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
      return PdfParserFields.extractSignatureFieldsFromBytes(reader.readAll());
    }
  }

  /// Extrai informações completas para edição de campos de assinatura.
  ///
  /// Retorna referências e dicionários para permitir operações como renomear
  /// e remover campos usando update incremental.
  PdfSignatureFieldEditContext extractSignatureFieldEditContext() {
    try {
      _ensureXrefParsed();
      final trailer = _trailerInfo ??
          PdfParserXref.readTrailerInfoFromReader(reader, xrefOffset);
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

      final acroFormVal = rootDict.values[PdfNameTokens.acroForm];
      final acroFormRefToken = PdfParserObjects.asRef(acroFormVal);
      final acroFormToken = _resolveDictFromValueNoStream(acroFormVal) ??
          _resolveDictFromValueFull(acroFormVal);
      if (acroFormToken == null) {
        return const PdfSignatureFieldEditContext(
            fields: <PdfSignatureFieldObjectInfo>[]);
      }

      final acroFormDict = PdfParserObjects.toPdfDict(acroFormToken);
      final acroFormRef = acroFormRefToken != null
          ? PdfIndirectRef(acroFormRefToken.obj, acroFormRefToken.gen)
          : null;

      final fieldsVal = acroFormToken.values[PdfNameTokens.fields];
      final fieldsRefToken = PdfParserObjects.asRef(fieldsVal);
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

      final fieldsArray = PdfParserObjects.toPdfArray(fieldsToken);
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
      final type = PdfParserObjects.asName(dict.values[PdfNameTokens.type]);

      if (type == PdfNameTokens.page ||
          dict.values.containsKey(PdfNameTokens.contents)) {
        pages.add(ref);
        if (maxPages != null && pages.length >= maxPages) break;
        continue;
      }

      if (type == PdfNameTokens.pages ||
          dict.values.containsKey(PdfNameTokens.kids)) {
        final kids = dict.values[PdfNameTokens.kids];
        if (kids is PdfArrayToken) {
          for (final item in kids.values) {
            final kidRef = PdfParserObjects.asRef(item);
            if (kidRef != null) stack.add(kidRef);
          }
        }
      }
    }

    return pages;
  }

  PdfDictToken? _resolvePageResources(PdfDictToken pageDict) {
    final direct =
        _resolveDictFromValueNoStream(pageDict.values[PdfNameTokens.resources]);
    PdfDictToken? parentRes;
    var parentVal = pageDict.values[PdfNameTokens.parent];
    for (int depth = 0; depth < 32; depth++) {
      final parentRef = PdfParserObjects.asRef(parentVal);
      if (parentRef == null) break;
      final parentObj =
          _getObjectNoStream(parentRef.obj) ?? _getObject(parentRef.obj);
      if (parentObj == null || parentObj.value is! PdfDictToken) break;
      final parentDict = parentObj.value as PdfDictToken;
      parentRes = _resolveDictFromValueNoStream(
          parentDict.values[PdfNameTokens.resources]);
      if (parentRes != null) break;
      parentVal = parentDict.values[PdfNameTokens.parent];
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
        _resolveDictFromValueNoStream(parentRes.values[PdfNameTokens.xObject]);
    final childXObj =
        _resolveDictFromValueNoStream(childRes.values[PdfNameTokens.xObject]);
    if (parentXObj != null || childXObj != null) {
      final xValues = <String, dynamic>{};
      if (parentXObj != null) xValues.addAll(parentXObj.values);
      if (childXObj != null) xValues.addAll(childXObj.values);
      merged[PdfNameTokens.xObject] = PdfDictToken(xValues);
    }

    return PdfDictToken(merged);
  }

  List<double>? _resolvePageMediaBox(PdfDictToken pageDict) {
    final direct =
        PdfParserObjects.asNumArray(pageDict.values[PdfNameTokens.mediaBox]) ??
            PdfParserObjects.asNumArray(pageDict.values[PdfNameTokens.cropbox]);
    if (direct != null) return direct;
    var parentVal = pageDict.values[PdfNameTokens.parent];
    for (int depth = 0; depth < 32; depth++) {
      final parentRef = PdfParserObjects.asRef(parentVal);
      if (parentRef == null) break;
      final parentObj =
          _getObjectNoStream(parentRef.obj) ?? _getObject(parentRef.obj);
      if (parentObj == null || parentObj.value is! PdfDictToken) break;
      final parentDict = parentObj.value as PdfDictToken;
      final box = PdfParserObjects.asNumArray(
              parentDict.values[PdfNameTokens.mediaBox]) ??
          PdfParserObjects.asNumArray(parentDict.values[PdfNameTokens.cropbox]);
      if (box != null) return box;
      parentVal = parentDict.values[PdfNameTokens.parent];
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
      final type = PdfParserObjects.asName(dict.values[PdfNameTokens.type]);
      final looksLikePage = type == PdfNameTokens.page ||
          (dict.values.containsKey(PdfNameTokens.mediaBox) &&
              dict.values.containsKey(PdfNameTokens.contents));
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
      final subtype =
          PdfParserObjects.asName(dict.values[PdfNameTokens.subtype]);
      if (subtype != PdfNameTokens.image) continue;
      final filter = _asFilterName(dict.values[PdfNameTokens.filter]);
      final colorSpace =
          _asColorSpaceName(dict.values[PdfNameTokens.colorSpace]);
      entries.add((
        offset: entry.value.offset,
        info: ImageScanInfo(
          imageRef: PdfIndirectRef(obj.objId, obj.gen),
          width: PdfParserObjects.asInt(dict.values[PdfNameTokens.width]),
          height: PdfParserObjects.asInt(dict.values[PdfNameTokens.height]),
          bitsPerComponent: PdfParserObjects.asInt(
              dict.values[PdfNameTokens.bitsPerComponent]),
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
    final ref = PdfParserObjects.asRef(value);
    if (ref == null) return null;
    final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
    if (obj == null || obj.value is! PdfDictToken) return null;
    return obj.value as PdfDictToken;
  }

  PdfDictToken? _resolveDictFromValueFull(dynamic value) {
    if (value is PdfDictToken) return value;
    final ref = PdfParserObjects.asRef(value);
    if (ref == null) return null;
    final obj = _getObject(ref.obj) ?? _getObjectNoStream(ref.obj);
    if (obj == null || obj.value is! PdfDictToken) return null;
    return obj.value as PdfDictToken;
  }

  PdfArrayToken? _resolveArrayFromValue(dynamic value) {
    if (value is PdfArrayToken) return value;
    final ref = PdfParserObjects.asRef(value);
    if (ref == null) return null;
    final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
    if (obj == null || obj.value is! PdfArrayToken) return null;
    return obj.value as PdfArrayToken;
  }

  PdfArrayToken? _resolveArrayFromValueFull(dynamic value) {
    if (value is PdfArrayToken) return value;
    final ref = PdfParserObjects.asRef(value);
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

    final ownName = _asString(dict.values[PdfNameTokens.t]);
    final resolvedName = ownName ?? inheritedName;

    final kidsVal = dict.values[PdfNameTokens.kids];
    final kids = _resolveArrayFromValue(kidsVal);
    if (kids != null) {
      for (final kid in kids.values) {
        _collectSignatureFields(
          kid,
          out,
          visited,
          inheritedName: resolvedName,
          inheritedFieldType:
              PdfParserObjects.asName(dict.values[PdfNameTokens.ft]) ??
                  inheritedFieldType,
          pageIndexByObj: pageIndexByObj,
        );
      }
    }

    final fieldType = PdfParserObjects.asName(dict.values[PdfNameTokens.ft]) ??
        inheritedFieldType;
    final fieldName = resolvedName;

    dynamic sigVal = dict.values[PdfNameTokens.v];
    if (sigVal is PdfRefToken) {
      final sigObj = _getObjectNoStream(sigVal.obj) ?? _getObject(sigVal.obj);
      sigVal = sigObj?.value;
    }

    if (sigVal is! PdfDictToken) {
      if (fieldType != PdfNameTokens.sig) return;
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

    if (fieldType != PdfNameTokens.sig &&
        PdfParserObjects.asName(sigVal.values[PdfNameTokens.type]) !=
            PdfNameTokens.sig) {
      return;
    }

    final reason = _asString(sigVal.values[PdfNameTokens.reason]) ??
        _asString(dict.values[PdfNameTokens.reason]);
    final location = _asString(sigVal.values[PdfNameTokens.location]) ??
        _asString(dict.values[PdfNameTokens.location]);
    final name = _asString(sigVal.values[PdfNameTokens.name]) ??
        _asString(dict.values[PdfNameTokens.name]);
    final signingTime = _asString(sigVal.values[PdfNameTokens.m]) ??
        _asString(dict.values[PdfNameTokens.m]);
    final filter =
        PdfParserObjects.asName(sigVal.values[PdfNameTokens.filter]) ??
            PdfParserObjects.asName(dict.values[PdfNameTokens.filter]);
    final subFilter =
        PdfParserObjects.asName(sigVal.values[PdfNameTokens.subFilter]);
    final byteRange = asIntArray(sigVal.values[PdfNameTokens.byteRange]);
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

    final ownName = _asString(dict.values[PdfNameTokens.t]);
    final resolvedName = ownName ?? inheritedName;

    final kidsVal = dict.values[PdfNameTokens.kids];
    final kids = _resolveArrayFromValue(kidsVal);
    if (kids != null) {
      for (final kid in kids.values) {
        _collectSignatureFieldObjects(
          kid,
          out,
          visited,
          inheritedName: resolvedName,
          fieldIndex: fieldIndex,
          inheritedFieldType:
              PdfParserObjects.asName(dict.values[PdfNameTokens.ft]) ??
                  inheritedFieldType,
          pageIndexByObj: pageIndexByObj,
        );
      }
    }

    final fieldType = PdfParserObjects.asName(dict.values[PdfNameTokens.ft]) ??
        inheritedFieldType;
    final fieldName = resolvedName;

    dynamic sigVal = dict.values[PdfNameTokens.v];
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

    if (fieldType != PdfNameTokens.sig &&
        PdfParserObjects.asName(sigDictToken?.values[PdfNameTokens.type]) !=
            PdfNameTokens.sig) {
      return;
    }

    final reason = sigDictToken != null
        ? (_asString(sigDictToken.values[PdfNameTokens.reason]) ??
            _asString(dict.values[PdfNameTokens.reason]))
        : _asString(dict.values[PdfNameTokens.reason]);
    final location = sigDictToken != null
        ? (_asString(sigDictToken.values[PdfNameTokens.location]) ??
            _asString(dict.values[PdfNameTokens.location]))
        : _asString(dict.values[PdfNameTokens.location]);
    final name = sigDictToken != null
        ? (_asString(sigDictToken.values[PdfNameTokens.name]) ??
            _asString(dict.values[PdfNameTokens.name]))
        : _asString(dict.values[PdfNameTokens.name]);
    var signingTime = sigDictToken != null
        ? (_asString(sigDictToken.values[PdfNameTokens.m]) ??
            _asString(dict.values[PdfNameTokens.m]))
        : _asString(dict.values[PdfNameTokens.m]);
    if (signingTime == null && sigRef != null) {
      signingTime = _tryReadPdfDateFromObject(sigRef.obj, sigRef.gen);
    }
    var filter = sigDictToken != null
        ? (PdfParserObjects.asName(sigDictToken.values[PdfNameTokens.filter]) ??
            PdfParserObjects.asName(dict.values[PdfNameTokens.filter]))
        : PdfParserObjects.asName(dict.values[PdfNameTokens.filter]);
    var subFilter = sigDictToken != null
        ? PdfParserObjects.asName(sigDictToken.values[PdfNameTokens.subFilter])
        : null;
    if (subFilter == null && sigRef != null) {
      subFilter = _tryReadNameFromObject(sigRef.obj, sigRef.gen, 'SubFilter');
    }
    if (filter == null && sigRef != null) {
      filter = _tryReadNameFromObject(sigRef.obj, sigRef.gen, 'Filter');
    }
    var byteRange = sigDictToken != null
        ? asIntArray(sigDictToken.values[PdfNameTokens.byteRange])
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
      fieldDict: PdfParserObjects.toPdfDict(dict),
      fieldIndex: fieldRef == null ? fieldIndex : null,
      isDirect: fieldRef == null,
      signatureRef: sigRef,
      signatureDict: sigDictToken != null
          ? PdfParserObjects.toPdfDict(sigDictToken)
          : null,
    ));
  }

  Map<int, int> _buildPageIndexByObj(PdfDictToken rootDict) {
    final pagesRef =
        PdfParserObjects.asRef(rootDict.values[PdfNameTokens.pages]);
    if (pagesRef == null) return const <int, int>{};
    final pageRefs = _collectPageRefs(pagesRef);
    final out = <int, int>{};
    for (int i = 0; i < pageRefs.length; i++) {
      out[pageRefs[i].obj] = i + 1;
    }
    return out;
  }

  PdfRefToken? _findPageRefFromField(PdfDictToken dict) {
    final direct = PdfParserObjects.asRef(dict.values[PdfNameTokens.p]);
    if (direct != null) return direct;
    final kids = _resolveArrayFromValue(dict.values[PdfNameTokens.kids]);
    if (kids == null) return null;
    for (final kid in kids.values) {
      final kidDict = _resolveDictFromValueNoStream(kid);
      if (kidDict == null) continue;
      final p = PdfParserObjects.asRef(kidDict.values[PdfNameTokens.p]);
      if (p != null) return p;
    }
    return null;
  }

  List<double>? _findRectFromField(PdfDictToken dict) {
    final direct = PdfParserObjects.asNumArray(dict.values[PdfNameTokens.rect]);
    if (direct != null) return direct;
    final kids = _resolveArrayFromValue(dict.values[PdfNameTokens.kids]);
    if (kids == null) return null;
    for (final kid in kids.values) {
      final kidDict = _resolveDictFromValueNoStream(kid);
      if (kidDict == null) continue;
      final rect =
          PdfParserObjects.asNumArray(kidDict.values[PdfNameTokens.rect]);
      if (rect != null) return rect;
    }
    return null;
  }

  List<int>? _tryReadByteRangeFromObject(int objId, int gen) {
    try {
      final bytes = reader.readAll();
      final header = ascii.encode('$objId $gen obj');
      final start =
          PdfParserTokens.indexOfSequence(bytes, header, 0, bytes.length);
      if (start == -1) return null;

      final endObjToken = ascii.encode('endobj');
      final searchStart = start + header.length;
      final endObj = PdfParserTokens.indexOfSequence(
          bytes, endObjToken, searchStart, bytes.length);
      final end = endObj == -1 ? bytes.length : endObj;

      const byteRangeToken = <int>[
        0x2F, // /
        0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65, // ByteRange
      ];
      final pos = PdfParserTokens.indexOfSequence(
          bytes, byteRangeToken, searchStart, end);
      if (pos == -1) return null;

      int i = pos + byteRangeToken.length;
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
      while (i < end && bytes[i] != 0x5B /* [ */) {
        i++;
      }
      if (i >= end) return null;
      i++;

      final values = <int>[];
      for (int k = 0; k < 4; k++) {
        i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
        final parsed = PdfParserTokens.readInt(bytes, i, end);
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
      final start =
          PdfParserTokens.indexOfSequence(bytes, header, 0, bytes.length);
      if (start == -1) return null;

      final endObjToken = ascii.encode('endobj');
      final searchStart = start + header.length;
      final endObj = PdfParserTokens.indexOfSequence(
          bytes, endObjToken, searchStart, bytes.length);
      final end = endObj == -1 ? bytes.length : endObj;

      const token = <int>[0x2F, 0x4D]; // /M
      final pos =
          PdfParserTokens.indexOfSequence(bytes, token, searchStart, end);
      if (pos == -1) return null;

      int i = pos + token.length;
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
      if (i >= end) return null;

      if (bytes[i] == 0x28 /* ( */) {
        final parsed = PdfParserTokens.readLiteralString(bytes, i, end);
        if (parsed.bytes.isEmpty) return null;
        return ascii.decode(parsed.bytes);
      }
      if (bytes[i] == 0x3C /* < */) {
        final parsed = PdfParserTokens.readHexString(bytes, i, end);
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
      final start =
          PdfParserTokens.indexOfSequence(bytes, header, 0, bytes.length);
      if (start == -1) return null;

      final endObjToken = ascii.encode('endobj');
      final searchStart = start + header.length;
      final endObj = PdfParserTokens.indexOfSequence(
          bytes, endObjToken, searchStart, bytes.length);
      final end = endObj == -1 ? bytes.length : endObj;

      final token = ascii.encode('/$key');
      final pos =
          PdfParserTokens.indexOfSequence(bytes, token, searchStart, end);
      if (pos == -1) return null;

      int i = pos + token.length;
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
      if (i >= end) return null;
      if (bytes[i] != 0x2F /* / */) return null;
      i++;

      final startName = i;
      while (i < end) {
        final b = bytes[i];
        if (PdfParserTokens.isWhitespace(b) ||
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
      case PdfNameTokens.dctDecode:
        return 'DCT';
      case PdfNameTokens.jpxDecode:
        return 'JPX';
      case PdfNameTokens.jbig2Decode:
        return 'JBIG2';
      case PdfNameTokens.flateDecode:
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
    final contentVal = pageDict.values[PdfNameTokens.contents];
    if (contentVal == null) return out;

    final refs = <PdfRefToken>[];
    if (contentVal is PdfRefToken) {
      refs.add(contentVal);
    } else if (contentVal is PdfArrayToken) {
      for (final item in contentVal.values) {
        final ref = PdfParserObjects.asRef(item);
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

      final filters = _asFilterNames(dict.values[PdfNameTokens.filter]);
      if (filters.isNotEmpty) {
        for (final filter in filters.reversed) {
          if (filter == 'ASCII85') {
            dataBytes = _decodeAscii85(dataBytes);
          } else if (filter == 'Flate') {
            if (dataBytes.length > PdfParserXref.maxStreamDecodeSize) break;
            dataBytes =
                Uint8List.fromList(ZLibDecoder().decodeBytes(dataBytes));
          }
        }
      }

      int i = 0;
      while (i < dataBytes.length) {
        if (dataBytes[i] == 0x2F /* / */) {
          final name = PdfParserTokens.readName(dataBytes, i, dataBytes.length);
          i = name.nextIndex;
          final afterName = PdfParserTokens.skipPdfWsAndComments(
              dataBytes, i, dataBytes.length);
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
    final streamPos = PdfParserScan.findStreamStart(window, 0);
    if (streamPos == null) return null;
    var dataStart = streamPos;
    if (dataStart < window.length && window[dataStart] == 0x0D) {
      dataStart++;
    }
    if (dataStart < window.length && window[dataStart] == 0x0A) {
      dataStart++;
    }

    final endPos = PdfParserTokens.indexOfSequenceBmh(
      window,
      PdfParserTokens.endStreamToken,
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
    if (value is PdfStringToken)
      return PdfParserTokens.decodePdfString(value.bytes);
    if (value is int || value is double) return value.toString();
    if (value is bool) return value ? 'true' : 'false';
    if (value is PdfRefToken) return '${value.obj} ${value.gen} R';
    return value.toString();
  }

  String? _asString(dynamic value) {
    if (value is PdfStringToken)
      return PdfParserTokens.decodePdfString(value.bytes);
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

    final trailer = _trailerInfo ??
        PdfParserXref.readTrailerInfoFromReader(reader, xrefOffset);
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
    final pagesRef =
        PdfParserObjects.asRef(rootDict.values[PdfNameTokens.pages]);

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

    PdfParserObjects.mergeDictIntoPdfDict(
      pdfDocument.catalog.params,
      rootDict,
      ignoreKeys: const {PdfNameTokens.pages, PdfNameTokens.type},
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
        parsed = PdfParserObjects.readIndirectObjectAtFromReader(
          reader,
          entry.offset,
          _getObject,
        );
      } catch (_) {
        return null;
      }
    } else if (entry.type == XrefType.compressed) {
      try {
        parsed =
            PdfParserObjects.readCompressedObject(objId, entry, _getObject);
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
        parsed = PdfParserObjects.readIndirectObjectAtFromReaderNoStream(
            reader, entry.offset);
      } catch (_) {
        return null;
      }
    } else if (entry.type == XrefType.compressed) {
      try {
        parsed =
            PdfParserObjects.readCompressedObject(objId, entry, _getObject);
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
    final type = PdfParserObjects.asName(dict.values[PdfNameTokens.type]);

    if (type == PdfNameTokens.page ||
        dict.values.containsKey(PdfNameTokens.contents)) {
      final page = _buildPageFromDict(obj, dict, pdfDocument);
      if (page != null) pages.add(page);
      return;
    }

    final kids = dict.values[PdfNameTokens.kids];
    if (kids is PdfArrayToken) {
      for (final item in kids.values) {
        final kidRef = PdfParserObjects.asRef(item);
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
    final mediaBox =
        PdfParserObjects.asNumArray(dict.values[PdfNameTokens.mediaBox]) ??
            PdfParserObjects.asNumArray(dict.values[PdfNameTokens.cropbox]);
    final format = PdfParserPages.pageFormatFromBox(mediaBox);
    final rotate =
        PdfParserPages.pageRotationFromValue(dict.values[PdfNameTokens.rotate]);

    final page = PdfPage(
      pdfDocument,
      objser: pageObj.objId,
      objgen: pageObj.gen,
      pageFormat: format ?? PdfPageFormat.standard,
      rotate: rotate,
    );

    final filtered = PdfParserObjects.toPdfDict(
      dict,
      ignoreKeys: const {
        PdfNameTokens.parent,
        PdfNameTokens.type,
        PdfNameTokens.mediaBox,
        PdfNameTokens.rotate
      },
    );

    // Resolve /Annots se for referência indireta para permitir append
    final annotsValue = dict.values[PdfNameTokens.annots];
    if (annotsValue is PdfRefToken) {
      final annotsObj = _getObject(annotsValue.obj);
      if (annotsObj != null && annotsObj.value is PdfArrayToken) {
        filtered.values[PdfNameTokens.annots] =
            PdfParserObjects.toPdfArray(annotsObj.value as PdfArrayToken);
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

    final maxObjId = PdfParserXref.repairXrefByScanFromReader(
        reader, _xrefEntries, (rootObj) {
      if (rootObj != null) {
        _trailerInfo = PdfParserXref.mergeTrailerInfo(
            _trailerInfo, TrailerInfo(rootObj: rootObj));
      }
    });

    if ((_trailerInfo?.size == null || _trailerInfo!.size! <= 0) &&
        maxObjId > 0) {
      _trailerInfo = PdfParserXref.mergeTrailerInfo(
          _trailerInfo, TrailerInfo(size: maxObjId + 1));
    }

    _indexObjectStreams();
  }

  void _parseXrefChain() {
    final visited = <int>{};
    int offset = PdfParserXref.computeXrefOffsetFromReader(reader);

    while (offset > 0 && offset < reader.length && !visited.contains(offset)) {
      visited.add(offset);

      TrailerInfo? info;
      try {
        info = PdfParserXref.parseXrefAtOffsetFromReader(
            reader, offset, _xrefEntries);
      } catch (_) {
        break;
      }
      if (info != null) {
        _trailerInfo = PdfParserXref.mergeTrailerInfo(_trailerInfo, info);
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
      final tailRoot = PdfParserScan.findRootFromTailFromReader(reader);
      if (tailRoot != null) {
        _trailerInfo = PdfParserXref.mergeTrailerInfo(
            _trailerInfo, TrailerInfo(rootObj: tailRoot.obj));
      }
    }

    if (_allowRepair &&
        _trailerInfo?.infoObj == null &&
        _xrefEntries.isNotEmpty) {
      final tailInfo = PdfParserScan.findInfoFromTailFromReader(reader);
      if (tailInfo != null) {
        _trailerInfo = PdfParserXref.mergeTrailerInfo(
            _trailerInfo, TrailerInfo(infoObj: tailInfo.obj));
      }
    }

    if (_allowRepair &&
        (_xrefEntries.isEmpty || _trailerInfo?.rootObj == null) &&
        !_repairAttempted) {
      _repairAttempted = true;
      final maxObjId = PdfParserXref.repairXrefByScanFromReader(
          reader, _xrefEntries, (rootObj) {
        if (rootObj != null) {
          _trailerInfo = PdfParserXref.mergeTrailerInfo(
              _trailerInfo, TrailerInfo(rootObj: rootObj));
        }
      });
      if (maxObjId > 0) {
        _trailerInfo = PdfParserXref.mergeTrailerInfo(
            _trailerInfo, TrailerInfo(size: maxObjId + 1));
      }
      _fullScanIndexBuilt = true;
      _indexObjectStreams();
    }

    if (_allowRepair &&
        _trailerInfo?.infoObj == null &&
        _xrefEntries.isNotEmpty) {
      final tailInfo = PdfParserScan.findInfoFromTailFromReader(reader);
      if (tailInfo != null) {
        _trailerInfo = PdfParserXref.mergeTrailerInfo(
            _trailerInfo, TrailerInfo(infoObj: tailInfo.obj));
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
      final type = PdfParserObjects.asName(dict.values[PdfNameTokens.type]);
      if (type != PdfNameTokens.objStm) continue;
      if (obj.streamData == null) continue;

      final n = PdfParserObjects.asInt(dict.values[PdfNameTokens.n]);
      if (n == null || n <= 0) continue;

      Uint8List data = obj.streamData!;
      final filter = PdfParserObjects.asName(dict.values[PdfNameTokens.filter]);
      if (filter == PdfNameTokens.flateDecode) {
        if (data.length > PdfParserXref.maxStreamDecodeSize) continue;
        data = Uint8List.fromList(ZLibDecoder().decodeBytes(data));
      }

      final header = PdfParserObjects.readObjectStreamHeader(data, n);
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

