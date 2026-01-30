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
  }) : super.fromBytes(
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
  }) : super(
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
  final Map<int, _XrefEntry> _xrefEntries = <int, _XrefEntry>{};
  _TrailerInfo? _trailerInfo;
  final Map<int, _ParsedIndirectObject> _objectCache =
      <int, _ParsedIndirectObject>{};
  final Map<int, _ParsedIndirectObject> _objectCacheNoStream =
      <int, _ParsedIndirectObject>{};

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

    final trailer = _trailerInfo ?? _readTrailerInfoFromReader(reader, xrefOffset);
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
    if (rootObj == null || rootObj.value is! _PdfDictToken) {
      return const PdfDocumentInfo(
        version: '1.4',
        pageCount: 0,
        mediaBoxes: <PdfPageMediaBoxInfo>[],
        images: <PdfImageInfo>[],
      );
    }

    final rootDict = rootObj.value as _PdfDictToken;
    final pagesRef = _asRef(rootDict.values['/Pages']);
    final pageRefs = pagesRef != null
        ? _collectPageRefs(pagesRef, maxPages: maxPages)
        : <_PdfRef>[];

    final mediaBoxes = <PdfPageMediaBoxInfo>[];
    final images = <PdfImageInfo>[];

    for (int i = 0; i < pageRefs.length; i++) {
      final pageRef = pageRefs[i];
      final pageObj = _getObjectNoStream(pageRef.obj) ?? _getObject(pageRef.obj);
      if (pageObj == null || pageObj.value is! _PdfDictToken) continue;
      final pageDict = pageObj.value as _PdfDictToken;

      final mediaBox = _asNumArray(pageDict.values['/MediaBox']) ??
          _asNumArray(pageDict.values['/CropBox']);
      if (mediaBox != null) {
        mediaBoxes.add(PdfPageMediaBoxInfo(
          pageIndex: i + 1,
          pageRef: PdfIndirectRef(pageRef.obj, pageRef.gen),
          box: mediaBox,
        ));
      }

      final resDict = _resolvePageResources(pageDict);
      final xObject = resDict != null ? resDict.values['/XObject'] : null;
      final xObjectDict = _resolveDictFromValueNoStream(xObject);
      if (xObjectDict != null) {
        for (final entry in xObjectDict.values.entries) {
          final ref = _asRef(entry.value);
          if (ref == null) continue;
          final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
          if (obj == null || obj.value is! _PdfDictToken) continue;
          final dict = obj.value as _PdfDictToken;
          final subtype = _asName(dict.values['/Subtype']);
          if (subtype != '/Image') continue;

          final filter = _asFilterName(dict.values['/Filter']);
          final colorSpace = _asColorSpaceName(dict.values['/ColorSpace']);
          images.add(PdfImageInfo(
            pageIndex: i + 1,
            pageRef: PdfIndirectRef(pageRef.obj, pageRef.gen),
            imageRef: PdfIndirectRef(ref.obj, ref.gen),
            width: _asInt(dict.values['/Width']),
            height: _asInt(dict.values['/Height']),
            bitsPerComponent: _asInt(dict.values['/BitsPerComponent']),
            colorSpace: colorSpace,
            filter: filter,
          ));
        }
      }
    }

    final infoMap = trailer.infoObj != null
        ? _readInfoDict(trailer.infoObj!)
        : null;
    final infoEntry = trailer.infoObj != null
        ? _xrefEntries[trailer.infoObj!]
        : null;

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

  /// Extrai informações de campos de assinatura (/FT /Sig).
  List<PdfSignatureFieldInfo> extractSignatureFields() {
    try {
      _ensureXrefParsed();
      final trailer = _trailerInfo ?? _readTrailerInfoFromReader(reader, xrefOffset);
      final rootObjId = trailer.rootObj;
      if (rootObjId == null) return const <PdfSignatureFieldInfo>[];

      final rootObj = _getObjectNoStream(rootObjId) ?? _getObject(rootObjId);
      if (rootObj == null || rootObj.value is! _PdfDictToken) {
        return const <PdfSignatureFieldInfo>[];
      }
      final rootDict = rootObj.value as _PdfDictToken;
      final acroForm = _resolveDictFromValueNoStream(rootDict.values['/AcroForm']);
      if (acroForm == null) return const <PdfSignatureFieldInfo>[];

      final fieldsVal = acroForm.values['/Fields'];
      final fields = _resolveArrayFromValue(fieldsVal);
      if (fields == null) return const <PdfSignatureFieldInfo>[];

      final out = <PdfSignatureFieldInfo>[];
      final visited = <int>{};
      for (final item in fields.values) {
        _collectSignatureFields(item, out, visited);
      }
      return out;
    } catch (_) {
      return _extractSignatureFieldsFromBytes(reader.readAll());
    }
  }

  List<_PdfRef> _collectPageRefs(
    _PdfRef rootRef, {
    int? maxPages,
  }) {
    final pages = <_PdfRef>[];
    final stack = <_PdfRef>[rootRef];
    final visited = <int>{};

    while (stack.isNotEmpty) {
      final ref = stack.removeLast();
      if (visited.contains(ref.obj)) continue;
      visited.add(ref.obj);

      final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
      if (obj == null || obj.value is! _PdfDictToken) continue;
      final dict = obj.value as _PdfDictToken;
      final type = _asName(dict.values['/Type']);

      if (type == '/Page' || dict.values.containsKey('/Contents')) {
        pages.add(ref);
        if (maxPages != null && pages.length >= maxPages) break;
        continue;
      }

      if (type == '/Pages' || dict.values.containsKey('/Kids')) {
        final kids = dict.values['/Kids'];
        if (kids is _PdfArrayToken) {
          for (final item in kids.values) {
            final kidRef = _asRef(item);
            if (kidRef != null) stack.add(kidRef);
          }
        }
      }
    }

    return pages;
  }

  _PdfDictToken? _resolvePageResources(_PdfDictToken pageDict) {
    final direct = _resolveDictFromValueNoStream(pageDict.values['/Resources']);
    if (direct != null) return direct;
    var parentVal = pageDict.values['/Parent'];
    for (int depth = 0; depth < 32; depth++) {
      final parentRef = _asRef(parentVal);
      if (parentRef == null) break;
      final parentObj = _getObjectNoStream(parentRef.obj) ?? _getObject(parentRef.obj);
      if (parentObj == null || parentObj.value is! _PdfDictToken) break;
      final parentDict = parentObj.value as _PdfDictToken;
      final res = _resolveDictFromValueNoStream(parentDict.values['/Resources']);
      if (res != null) return res;
      parentVal = parentDict.values['/Parent'];
    }
    return null;
  }

  _PdfDictToken? _resolveDictFromValueNoStream(dynamic value) {
    if (value is _PdfDictToken) return value;
    final ref = _asRef(value);
    if (ref == null) return null;
    final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
    if (obj == null || obj.value is! _PdfDictToken) return null;
    return obj.value as _PdfDictToken;
  }

  _PdfArrayToken? _resolveArrayFromValue(dynamic value) {
    if (value is _PdfArrayToken) return value;
    final ref = _asRef(value);
    if (ref == null) return null;
    final obj = _getObjectNoStream(ref.obj) ?? _getObject(ref.obj);
    if (obj == null || obj.value is! _PdfArrayToken) return null;
    return obj.value as _PdfArrayToken;
  }

  void _collectSignatureFields(
    dynamic value,
    List<PdfSignatureFieldInfo> out,
    Set<int> visited, {
    String? inheritedName,
  }) {
    if (value is _PdfRef) {
      if (!visited.add(value.obj)) return;
      final obj = _getObjectNoStream(value.obj) ?? _getObject(value.obj);
      if (obj == null || obj.value is! _PdfDictToken) return;
      _collectSignatureFields(
        obj.value,
        out,
        visited,
        inheritedName: inheritedName,
      );
      return;
    }

    if (value is! _PdfDictToken) return;
    final dict = value;

    final ownName = _asString(dict.values['/T']);
    final resolvedName = ownName ?? inheritedName;

    final kidsVal = dict.values['/Kids'];
    final kids = _resolveArrayFromValue(kidsVal);
    if (kids != null) {
      for (final kid in kids.values) {
        _collectSignatureFields(
          kid,
          out,
          visited,
          inheritedName: resolvedName,
        );
      }
    }

    final fieldType = _asName(dict.values['/FT']);
    final fieldName = resolvedName;

    dynamic sigVal = dict.values['/V'];
    if (sigVal is _PdfRef) {
      final sigObj = _getObjectNoStream(sigVal.obj) ?? _getObject(sigVal.obj);
      sigVal = sigObj?.value;
    }

    if (sigVal is! _PdfDictToken) {
      if (fieldType != '/Sig') return;
      out.add(PdfSignatureFieldInfo(fieldName: fieldName));
      return;
    }

    if (fieldType != '/Sig' && _asName(sigVal.values['/Type']) != '/Sig') {
      return;
    }

    final reason = _asString(sigVal.values['/Reason']) ?? _asString(dict.values['/Reason']);
    final location = _asString(sigVal.values['/Location']) ?? _asString(dict.values['/Location']);
    final name = _asString(sigVal.values['/Name']) ?? _asString(dict.values['/Name']);
    final signingTime = _asString(sigVal.values['/M']) ?? _asString(dict.values['/M']);
    final subFilter = _asName(sigVal.values['/SubFilter']);
    final byteRange = _asIntArray(sigVal.values['/ByteRange']);

    out.add(PdfSignatureFieldInfo(
      fieldName: fieldName,
      reason: reason,
      location: location,
      name: name,
      signingTimeRaw: signingTime,
      subFilter: subFilter,
      byteRange: byteRange,
    ));
  }

  String? _asFilterName(dynamic value) {
    final resolved = _resolveValueNoStream(value);
    _PdfNameToken? name;
    if (resolved is _PdfNameToken) {
      name = resolved;
    } else if (resolved is _PdfArrayToken && resolved.values.isNotEmpty) {
      final first = resolved.values.first;
      if (first is _PdfNameToken) name = first;
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
        return name.value.startsWith('/') ? name.value.substring(1) : name.value;
    }
  }

  String? _asColorSpaceName(dynamic value) {
    final resolved = _resolveValueNoStream(value);
    if (resolved is _PdfNameToken) {
      return resolved.value.startsWith('/')
          ? resolved.value.substring(1)
          : resolved.value;
    }
    if (resolved is _PdfArrayToken && resolved.values.isNotEmpty) {
      final first = resolved.values.first;
      if (first is _PdfNameToken) {
        return first.value.startsWith('/')
            ? first.value.substring(1)
            : first.value;
      }
    }
    return null;
  }

  dynamic _resolveValueNoStream(dynamic value) {
    if (value is _PdfRef) {
      final obj = _getObjectNoStream(value.obj) ?? _getObject(value.obj);
      return obj?.value;
    }
    return value;
  }

  Map<String, String>? _readInfoDict(int infoObjId) {
    final obj = _getObjectNoStream(infoObjId) ?? _getObject(infoObjId);
    if (obj == null || obj.value is! _PdfDictToken) return null;
    final dict = obj.value as _PdfDictToken;
    final out = <String, String>{};
    for (final entry in dict.values.entries) {
      out[entry.key] = _valueToString(entry.value);
    }
    return out;
  }

  String _valueToString(dynamic value) {
    if (value is _PdfNameToken) return value.value;
    if (value is _PdfStringToken) return _decodePdfString(value.bytes);
    if (value is int || value is double) return value.toString();
    if (value is bool) return value ? 'true' : 'false';
    if (value is _PdfRef) return '${value.obj} ${value.gen} R';
    return value.toString();
  }

  String? _asString(dynamic value) {
    if (value is _PdfStringToken) return _decodePdfString(value.bytes);
    if (value is _PdfNameToken) return value.value;
    if (value is int || value is double || value is bool) {
      return value.toString();
    }
    if (value is _PdfRef) return '${value.obj} ${value.gen} R';
    return null;
  }

  List<int>? _asIntArray(dynamic value) {
    final resolved = _resolveValueNoStream(value);
    if (resolved is _PdfArrayToken) {
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

    final trailer = _trailerInfo ?? _readTrailerInfoFromReader(reader, xrefOffset);
    if (trailer.rootObj == null) {
      pdfDocument.catalog = PdfCatalog(pdfDocument, PdfPageList(pdfDocument));
      return;
    }

    final rootObj = _getObject(trailer.rootObj!);
    if (rootObj == null || rootObj.value is! _PdfDictToken) {
      pdfDocument.catalog = PdfCatalog(pdfDocument, PdfPageList(pdfDocument));
      return;
    }

    final rootDict = rootObj.value as _PdfDictToken;
    final pagesRef = _asRef(rootDict.values['/Pages']);

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

    _mergeDictIntoPdfDict(
      pdfDocument.catalog.params,
      rootDict,
      ignoreKeys: const {'/Pages', '/Type'},
    );

    if (pagesRef != null) {
      final pages = _loadPages(pagesRef, pdfDocument);
      pageList.pages.addAll(pages);
    }
  }

  _ParsedIndirectObject? _getObject(int objId) {
    final cached = _objectCache[objId];
    if (cached != null) return cached;

    _ensureXrefParsed();
    var entry = _xrefEntries[objId];
    if (entry == null) {
      _ensureFullScanIndexBuilt();
      entry = _xrefEntries[objId];
      if (entry == null) return null;
    }

    _ParsedIndirectObject? parsed;
    if (entry.type == _XrefType.inUse) {
      parsed = _readIndirectObjectAtFromReader(reader, entry.offset, this);
    } else if (entry.type == _XrefType.compressed) {
      parsed = _readCompressedObject(objId, entry, this);
    }

    if (parsed != null) {
      _objectCache[objId] = parsed;
    }
    return parsed;
  }

  _ParsedIndirectObject? _getObjectNoStream(int objId) {
    final cached = _objectCacheNoStream[objId];
    if (cached != null) return cached;

    _ensureXrefParsed();
    var entry = _xrefEntries[objId];
    if (entry == null) {
      _ensureFullScanIndexBuilt();
      entry = _xrefEntries[objId];
      if (entry == null) return null;
    }

    _ParsedIndirectObject? parsed;
    if (entry.type == _XrefType.inUse) {
      parsed = _readIndirectObjectAtFromReaderNoStream(reader, entry.offset);
    } else if (entry.type == _XrefType.compressed) {
      parsed = _readCompressedObject(objId, entry, this);
    }

    if (parsed != null) {
      _objectCacheNoStream[objId] = parsed;
    }
    return parsed;
  }

  List<PdfPage> _loadPages(_PdfRef pagesRef, PdfDocument pdfDocument) {
    final pages = <PdfPage>[];
    final visited = <int>{};
    _collectPages(pagesRef, pdfDocument, pages, visited);
    return pages;
  }

  void _collectPages(
    _PdfRef ref,
    PdfDocument pdfDocument,
    List<PdfPage> pages,
    Set<int> visited,
  ) {
    if (visited.contains(ref.obj)) return;
    visited.add(ref.obj);

    final obj = _getObject(ref.obj);
    if (obj == null || obj.value is! _PdfDictToken) return;
    final dict = obj.value as _PdfDictToken;
    final type = _asName(dict.values['/Type']);

    if (type == '/Page' || dict.values.containsKey('/Contents')) {
      final page = _buildPageFromDict(obj, dict, pdfDocument);
      if (page != null) pages.add(page);
      return;
    }

    final kids = dict.values['/Kids'];
    if (kids is _PdfArrayToken) {
      for (final item in kids.values) {
        final kidRef = _asRef(item);
        if (kidRef != null) {
          _collectPages(kidRef, pdfDocument, pages, visited);
        }
      }
    }
  }

  PdfPage? _buildPageFromDict(
    _ParsedIndirectObject pageObj,
    _PdfDictToken dict,
    PdfDocument pdfDocument,
  ) {
    final mediaBox = _asNumArray(dict.values['/MediaBox']) ??
        _asNumArray(dict.values['/CropBox']);
    final format = _pageFormatFromBox(mediaBox);
    final rotate = _pageRotationFromValue(dict.values['/Rotate']);

    final page = PdfPage(
      pdfDocument,
      objser: pageObj.objId,
      objgen: pageObj.gen,
      pageFormat: format ?? PdfPageFormat.standard,
      rotate: rotate,
    );

    final filtered = _toPdfDict(
      dict,
      ignoreKeys: const {'/Parent', '/Type', '/MediaBox', '/Rotate'},
    );

    // Resolve /Annots se for referência indireta para permitir append
    final annotsValue = dict.values['/Annots'];
    if (annotsValue is _PdfRef) {
      final annotsObj = _getObject(annotsValue.obj);
      if (annotsObj != null && annotsObj.value is _PdfArrayToken) {
        filtered.values['/Annots'] =
          _toPdfArray(annotsObj.value as _PdfArrayToken);
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

    final maxObjId = _repairXrefByScanFromReader(reader, _xrefEntries,
        (rootObj) {
      if (rootObj != null) {
        _trailerInfo = _mergeTrailerInfo(
            _trailerInfo, _TrailerInfo(rootObj: rootObj));
      }
    });

    if ((_trailerInfo?.size == null || _trailerInfo!.size! <= 0) &&
        maxObjId > 0) {
      _trailerInfo =
          _mergeTrailerInfo(_trailerInfo, _TrailerInfo(size: maxObjId + 1));
    }
  }

  void _parseXrefChain() {
    final visited = <int>{};
    int offset = _computeXrefOffsetFromReader(reader);

    while (offset > 0 && offset < reader.length && !visited.contains(offset)) {
      visited.add(offset);

      final info = _parseXrefAtOffsetFromReader(reader, offset, _xrefEntries);
      if (info != null) {
        _trailerInfo = _mergeTrailerInfo(_trailerInfo, info);
        if (info.prev != null && info.prev! > 0) {
          offset = info.prev!;
          continue;
        }
      }
      break;
    }

    if (_trailerInfo?.rootObj == null && _xrefEntries.isNotEmpty) {
      final tailRoot = _findRootFromTailFromReader(reader);
      if (tailRoot != null) {
        _trailerInfo = _mergeTrailerInfo(
            _trailerInfo, _TrailerInfo(rootObj: tailRoot.obj));
      }
    }

    if ((_xrefEntries.isEmpty || _trailerInfo?.rootObj == null) &&
        !_repairAttempted) {
      _repairAttempted = true;
      final maxObjId = _repairXrefByScanFromReader(reader, _xrefEntries,
          (rootObj) {
        if (rootObj != null) {
          _trailerInfo = _mergeTrailerInfo(
              _trailerInfo, _TrailerInfo(rootObj: rootObj));
        }
      });
      if (maxObjId > 0) {
        _trailerInfo = _mergeTrailerInfo(
            _trailerInfo, _TrailerInfo(size: maxObjId + 1));
      }
    }
  }
}

const int _maxStreamDecodeSize = 256 * 1024 * 1024;

const List<int> _endStreamToken = <int>[
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
  final int windowStart = bytes.length > 4 * 1024
      ? bytes.length - 4 * 1024
      : 0;
  final int pos = _lastIndexOfSequence(bytes, token, windowStart, bytes.length);
  if (pos == -1) return 0;

  int i = pos + token.length;
  i = _skipPdfWsAndComments(bytes, i, bytes.length);
  final parsed = _readInt(bytes, i, bytes.length);
  return parsed.value;
}

int _findStartXrefFromReader(PdfRandomAccessReader reader) {
  const token = <int>[0x73, 0x74, 0x61, 0x72, 0x74, 0x78, 0x72, 0x65, 0x66];
  final len = reader.length;
  final windowSize = len > 4 * 1024 ? 4 * 1024 : len;
  final windowStart = len - windowSize;
  final window = reader.readRange(windowStart, windowSize);
  final pos = _lastIndexOfSequence(window, token, 0, window.length);
  if (pos == -1) return 0;

  int i = pos + token.length;
  i = _skipPdfWsAndComments(window, i, window.length);
  final parsed = _readInt(window, i, window.length);
  return parsed.value;
}

int _computeXrefOffset(Uint8List bytes) {
  final startXref = _findStartXref(bytes);
  if (startXref > 0 && startXref < bytes.length) {
    return startXref;
  }

  // Fallback: procurar a última ocorrência de 'xref'
  const xrefToken = <int>[0x78, 0x72, 0x65, 0x66]; // xref
  final windowStart = bytes.length > 1024 * 1024 ? bytes.length - 1024 * 1024 : 0;
  final pos = _lastIndexOfSequence(bytes, xrefToken, windowStart, bytes.length);
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
  final pos = _lastIndexOfSequence(window, xrefToken, 0, window.length);
  if (pos != -1) {
    return windowStart + pos;
  }
  return 0;
}

int _computeSize(Uint8List bytes, _TrailerInfo? trailerInfo) {
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
  _TrailerInfo? trailerInfo,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return _computeSize(reader.readAll(), trailerInfo);
  }
  if (trailerInfo?.size != null && trailerInfo!.size! > 0) {
    return trailerInfo.size!;
  }

  final info = _readTrailerInfoFromReader(reader, _computeXrefOffsetFromReader(reader));
  if (info.size != null && info.size! > 0) {
    return info.size!;
  }

  return _maxObjectIdFromReader(reader) + 1;
}

String _decodePdfString(Uint8List bytes) {
  if (bytes.length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF) {
    final codeUnits = <int>[];
    for (int i = 2; i + 1 < bytes.length; i += 2) {
      codeUnits.add((bytes[i] << 8) | bytes[i + 1]);
    }
    return String.fromCharCodes(codeUnits);
  }
  return String.fromCharCodes(bytes);
}

class _TrailerInfo {
  _TrailerInfo({
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

_TrailerInfo _mergeTrailerInfo(_TrailerInfo? a, _TrailerInfo b) {
  if (a == null) return b;
  return _TrailerInfo(
    size: b.size ?? a.size,
    prev: b.prev ?? a.prev,
    rootObj: b.rootObj ?? a.rootObj,
    infoObj: b.infoObj ?? a.infoObj,
    id: b.id ?? a.id,
  );
}

_TrailerInfo _readTrailerInfo(Uint8List bytes, int startXref) {
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

  return _TrailerInfo();
}

_TrailerInfo _readTrailerInfoFromReader(
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

  return _TrailerInfo();
}

class _ParsedIndirectObject {
  _ParsedIndirectObject({
    required this.objId,
    required this.gen,
    required this.value,
    this.streamData,
  });

  final int objId;
  final int gen;
  final dynamic value;
  final Uint8List? streamData;
}

class _PdfRef {
  _PdfRef(this.obj, this.gen);
  final int obj;
  final int gen;
}

class _PdfNameToken {
  _PdfNameToken(this.value);
  final String value;
}

class _PdfStringToken {
  _PdfStringToken(this.bytes, this.format);
  final Uint8List bytes;
  final PdfStringFormat format;
}

class _PdfArrayToken {
  _PdfArrayToken(this.values);
  final List<dynamic> values;
}

class _PdfDictToken {
  _PdfDictToken(this.values);
  final Map<String, dynamic> values;
}

class _ParseResult {
  _ParseResult(this.value, this.nextIndex, {this.dictEnd});
  final dynamic value;
  final int nextIndex;
  final int? dictEnd;
}

_TrailerInfo _tryReadTrailerNearOffset(Uint8List bytes, int offset) {
  // Skip ws
  int i = _skipPdfWsAndComments(bytes, offset, bytes.length);

  // xref table?
  if (_matchToken(bytes, i, const <int>[0x78, 0x72, 0x65, 0x66])) {
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

  return _TrailerInfo();
}

_TrailerInfo _tryReadLastTrailer(Uint8List bytes) {
  const trailerToken = <int>[0x74, 0x72, 0x61, 0x69, 0x6C, 0x65, 0x72]; // trailer
  final windowStart = bytes.length > 1024 * 1024 ? bytes.length - 1024 * 1024 : 0;
  final pos = _lastIndexOfSequence(bytes, trailerToken, windowStart, bytes.length);
  if (pos == -1) {
    return _TrailerInfo();
  }
  return _scanForTrailerDict(bytes, pos + trailerToken.length, bytes.length);
}

_TrailerInfo _scanForTrailerDict(Uint8List bytes, int start, int end) {
  int i = _skipPdfWsAndComments(bytes, start, end);
  // buscar '<<'
  for (; i + 1 < end; i++) {
    if (bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
      break;
    }
  }
  if (i + 1 >= end) {
    return _TrailerInfo();
  }

  final dict = _parseTrailerDict(bytes, i, end);
  return _TrailerInfo(
    size: dict.size,
    prev: dict.prev,
    rootObj: dict.rootObj,
    infoObj: dict.infoObj,
    id: dict.id,
  );
}

_TrailerInfo _tryReadXrefStreamDict(Uint8List bytes, int offset) {
  // Verifica padrão: "<obj> <gen> obj" seguido de "<<" com /Type /XRef
  final header = _tryReadIndirectObjectHeader(bytes, offset, bytes.length);
  if (header == null) {
    return _TrailerInfo();
  }

  final dict = _parseXrefStreamDict(bytes, header.dictStart, bytes.length);
  if (dict.type == '/XRef') {
    return _TrailerInfo(
      size: dict.size,
      prev: dict.prev,
      rootObj: dict.rootObj,
      infoObj: dict.infoObj,
      id: dict.id,
    );
  }
  return _TrailerInfo();
}

class _IndirectHeader {
  _IndirectHeader(this.dictStart, this.dictEnd);
  final int dictStart;
  final int dictEnd;
}

_IndirectHeader? _tryReadIndirectObjectHeader(
  Uint8List bytes,
  int start,
  int end,
) {
  int i = _skipPdfWsAndComments(bytes, start, end);
  if (i >= end || !_isDigit(bytes[i])) return null;
  final obj = _readInt(bytes, i, end);
  i = obj.nextIndex;
  i = _skipPdfWsAndComments(bytes, i, end);
  if (i >= end || !_isDigit(bytes[i])) return null;
  final gen = _readInt(bytes, i, end);
  i = gen.nextIndex;
  i = _skipPdfWsAndComments(bytes, i, end);
  if (!_matchToken(bytes, i, const <int>[0x6F, 0x62, 0x6A])) return null; // obj
  i += 3;
  i = _skipPdfWsAndComments(bytes, i, end);
  if (i + 1 >= end || bytes[i] != 0x3C || bytes[i + 1] != 0x3C) return null;
  final dictEnd = _findDictEnd(bytes, i, end);
  if (dictEnd == -1) return null;
  return _IndirectHeader(i, dictEnd);
}

({String value, int nextIndex}) _readName(Uint8List bytes, int i, int end) {
  final buffer = StringBuffer();
  buffer.writeCharCode(bytes[i]);
  i++;
  while (i < end) {
    final b = bytes[i];
    if (_isWhitespace(b) ||
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
      if (_isHexDigit(h1) && _isHexDigit(h2)) {
        final v = (_hexValue(h1) << 4) | _hexValue(h2);
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

bool _matchToken(Uint8List bytes, int index, List<int> token) {
  if (index + token.length > bytes.length) return false;
  for (int i = 0; i < token.length; i++) {
    if (bytes[index + i] != token[i]) return false;
  }
  return true;
}

_TrailerInfo? _parseXrefAtOffset(
  Uint8List bytes,
  int offset,
  Map<int, _XrefEntry> entries,
) {
  int i = _skipPdfWsAndComments(bytes, offset, bytes.length);

  // xref table?
  if (_matchToken(bytes, i, const <int>[0x78, 0x72, 0x65, 0x66])) {
    return _parseXrefTable(bytes, i + 4, entries);
  }

  // xref stream?
  return _parseXrefStream(bytes, i, entries);
}

_TrailerInfo? _parseXrefAtOffsetFromReader(
  PdfRandomAccessReader reader,
  int offset,
  Map<int, _XrefEntry> entries,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return _parseXrefAtOffset(reader.readAll(), offset, entries);
  }

  final len = reader.length;
  const windowSizes = <int>[256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024];
  for (final size in windowSizes) {
    if (offset < 0 || offset >= len) return null;
    final windowSize = (offset + size > len) ? (len - offset) : size;
    final window = reader.readRange(offset, windowSize);
    int i = _skipPdfWsAndComments(window, 0, window.length);

    if (_matchToken(window, i, const <int>[0x78, 0x72, 0x65, 0x66])) {
      final info = _parseXrefTableFromWindow(window, entries, reader);
      if (info != null) return info;
    } else {
      final info = _parseXrefStreamFromWindow(window, offset, entries, reader);
      if (info != null) return info;
    }
  }

  return null;
}

_TrailerInfo? _parseXrefTableFromWindow(
  Uint8List bytes,
  Map<int, _XrefEntry> entries,
  PdfRandomAccessReader reader,
) {
  int i = 0;

  while (i < bytes.length) {
    i = _skipPdfWsAndComments(bytes, i, bytes.length);
    if (i >= bytes.length) break;

    if (_matchToken(bytes, i, const <int>[0x74, 0x72, 0x61, 0x69, 0x6C, 0x65, 0x72])) {
      return _scanForTrailerDict(bytes, i + 7, bytes.length);
    }

    if (!_isDigit(bytes[i])) {
      i++;
      continue;
    }

    final startObj = _readInt(bytes, i, bytes.length);
    i = startObj.nextIndex;
    i = _skipPdfWsAndComments(bytes, i, bytes.length);
    if (i >= bytes.length || !_isDigit(bytes[i])) {
      continue;
    }
    final count = _readInt(bytes, i, bytes.length);
    i = count.nextIndex;

    for (int j = 0; j < count.value; j++) {
      i = _skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length) break;

      final off = _readInt(bytes, i, bytes.length);
      i = off.nextIndex;
      i = _skipPdfWsAndComments(bytes, i, bytes.length);
      final gen = _readInt(bytes, i, bytes.length);
      i = gen.nextIndex;
      i = _skipPdfWsAndComments(bytes, i, bytes.length);

      final flag = bytes[i];
      i++;
      if (flag == 0x6E /* n */) {
        final objId = startObj.value + j;
        final fixed = _fixOffsetReader(reader, objId, gen.value, off.value);
        entries[objId] = _XrefEntry(
          offset: fixed,
          gen: gen.value,
          type: _XrefType.inUse,
        );
      } else if (flag == 0x66 /* f */) {
        final objId = startObj.value + j;
        entries[objId] = _XrefEntry(
          offset: off.value,
          gen: gen.value,
          type: _XrefType.free,
        );
      }

      while (i < bytes.length && bytes[i] != 0x0A && bytes[i] != 0x0D) {
        i++;
      }
    }
  }

  return null;
}

_TrailerInfo? _parseXrefStreamFromWindow(
  Uint8List bytes,
  int baseOffset,
  Map<int, _XrefEntry> entries,
  PdfRandomAccessReader reader,
) {
  final header = _tryReadIndirectObjectHeader(bytes, 0, bytes.length);
  if (header == null) return null;

  final dict = _parseXrefStreamDict(bytes, header.dictStart, bytes.length);
  if (dict.type != '/XRef') return null;

  Uint8List? stream = _extractStream(bytes, header.dictEnd, bytes.length, dict.length);
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
      final endAbs = _skipUnknownLengthStreamReader(reader, absStart, reader.length);
      if (endAbs != null) {
        final dataEnd = endAbs - _endStreamToken.length;
        final len = dataEnd - absStart;
        if (len > 0 && absStart + len <= reader.length) {
          stream = reader.readRange(absStart, len);
        }
      }
    }
  }

  if (stream == null) {
    return _TrailerInfo(
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
      return _TrailerInfo(
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
    return _TrailerInfo(
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
        entries[objId] = _XrefEntry(
          offset: fixed,
          gen: f2,
          type: _XrefType.inUse,
        );
      } else if (type == 2) {
        entries[objId] = _XrefEntry(
          offset: f1,
          gen: f2,
          type: _XrefType.compressed,
        );
      }
    }
  }

  return _TrailerInfo(
    size: dict.size,
    prev: dict.prev,
    rootObj: dict.rootObj,
    infoObj: dict.infoObj,
    id: dict.id,
  );
}

int? _findStreamStart(Uint8List bytes, int dictEnd) {
  int i = dictEnd;
  i = _skipPdfWsAndComments(bytes, i, bytes.length);
  if (!_matchToken(bytes, i, const <int>[0x73, 0x74, 0x72, 0x65, 0x61, 0x6D])) {
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
    if (_isValidObjAtOffsetReader(reader, objId, gen, corrected)) return corrected;
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
  int i = _skipPdfWsAndComments(win, 0, win.length);
  if (i >= win.length || !_isDigit(win[i])) return false;
  final obj = _readInt(win, i, win.length);
  if (obj.value != objId) return false;
  i = _skipPdfWsAndComments(win, obj.nextIndex, win.length);
  if (i >= win.length || !_isDigit(win[i])) return false;
  final genRead = _readInt(win, i, win.length);
  if (genRead.value != gen) return false;
  i = _skipPdfWsAndComments(win, genRead.nextIndex, win.length);
  return _matchToken(win, i, const <int>[0x6F, 0x62, 0x6A]);
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

_TrailerInfo? _parseXrefTable(
  Uint8List bytes,
  int start,
  Map<int, _XrefEntry> entries,
) {
  int i = start;

  while (i < bytes.length) {
    i = _skipPdfWsAndComments(bytes, i, bytes.length);
    if (i >= bytes.length) break;

    if (_matchToken(bytes, i, const <int>[0x74, 0x72, 0x61, 0x69, 0x6C, 0x65, 0x72])) {
      return _scanForTrailerDict(bytes, i + 7, bytes.length);
    }

    if (!_isDigit(bytes[i])) {
      i++;
      continue;
    }

    final startObj = _readInt(bytes, i, bytes.length);
    i = startObj.nextIndex;
    i = _skipPdfWsAndComments(bytes, i, bytes.length);
    if (!_isDigit(bytes[i])) {
      continue;
    }
    final count = _readInt(bytes, i, bytes.length);
    i = count.nextIndex;

    for (int j = 0; j < count.value; j++) {
      i = _skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length) break;

      final off = _readInt(bytes, i, bytes.length);
      i = off.nextIndex;
      i = _skipPdfWsAndComments(bytes, i, bytes.length);
      final gen = _readInt(bytes, i, bytes.length);
      i = gen.nextIndex;
      i = _skipPdfWsAndComments(bytes, i, bytes.length);

      final flag = bytes[i];
      i++;
      if (flag == 0x6E /* n */) {
        final objId = startObj.value + j;
        final fixed = _fixOffset(bytes, objId, gen.value, off.value);
        entries[objId] = _XrefEntry(
          offset: fixed,
          gen: gen.value,
          type: _XrefType.inUse,
        );
      } else if (flag == 0x66 /* f */) {
        final objId = startObj.value + j;
        entries[objId] = _XrefEntry(
          offset: off.value,
          gen: gen.value,
          type: _XrefType.free,
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

_TrailerInfo? _parseXrefStream(
  Uint8List bytes,
  int offset,
  Map<int, _XrefEntry> entries,
) {
  final header = _tryReadIndirectObjectHeader(bytes, offset, bytes.length);
  if (header == null) return null;

  final dict = _parseXrefStreamDict(bytes, header.dictStart, bytes.length);
  if (dict.type != '/XRef') return null;

  final stream = _extractStream(bytes, header.dictEnd, bytes.length, dict.length);
  if (stream == null) return _TrailerInfo(
    size: dict.size,
    prev: dict.prev,
    rootObj: dict.rootObj,
    infoObj: dict.infoObj,
    id: dict.id,
  );

  Uint8List data = stream;
  if (dict.filter == '/FlateDecode') {
    if (stream.length > _maxStreamDecodeSize) {
      return _TrailerInfo(
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
    return _TrailerInfo(
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
        entries[objId] = _XrefEntry(
          offset: fixed,
          gen: f2,
          type: _XrefType.inUse,
        );
      } else if (type == 2) {
        entries[objId] = _XrefEntry(
          offset: f1,
          gen: f2,
          type: _XrefType.compressed,
        );
      }
    }
  }

  return _TrailerInfo(
    size: dict.size,
    prev: dict.prev,
    rootObj: dict.rootObj,
    infoObj: dict.infoObj,
    id: dict.id,
  );
}

class _XrefEntry {
  _XrefEntry({required this.offset, required this.gen, required this.type});

  final int offset;
  final int gen;
  final _XrefType type;
}

enum _XrefType { free, inUse, compressed }

class _XrefStreamDict {
  _XrefStreamDict({
    this.type,
    this.size,
    this.prev,
    this.rootObj,
    this.infoObj,
    this.id,
    this.length,
    this.filter,
    this.w,
    this.index,
  });

  final String? type;
  final int? size;
  final int? prev;
  final int? rootObj;
  final int? infoObj;
  final Uint8List? id;
  final int? length;
  final String? filter;
  final List<int>? w;
  final List<int>? index;
}

_XrefStreamDict _parseXrefStreamDict(Uint8List bytes, int start, int end) {
  final parsed = _readDict(bytes, start, end);
  final v = parsed.value;
  if (v is! _PdfDictToken) {
    return _XrefStreamDict();
  }

  final m = v.values;

  final String? type = _asName(m['/Type']);
  final int? size = _asInt(m['/Size']);
  final int? prev = _asInt(m['/Prev']);

  int? rootObj;
  int? infoObj;
  final rootRef = _asRef(m['/Root']);
  if (rootRef != null) rootObj = rootRef.obj;
  final infoRef = _asRef(m['/Info']);
  if (infoRef != null) infoObj = infoRef.obj;

  Uint8List? id;
  final idVal = m['/ID'];
  if (idVal is _PdfArrayToken && idVal.values.isNotEmpty) {
    final first = idVal.values.first;
    if (first is _PdfStringToken) {
      id = first.bytes;
    }
  }

  int? length;
  final lenVal = m['/Length'];
  if (lenVal is int) length = lenVal;
  if (lenVal is double) length = lenVal.toInt();

  String? filter;
  final filterVal = m['/Filter'];
  if (filterVal is _PdfNameToken) {
    filter = filterVal.value;
  } else if (filterVal is _PdfArrayToken && filterVal.values.isNotEmpty) {
    final f0 = filterVal.values.first;
    if (f0 is _PdfNameToken) filter = f0.value;
  }

  List<int>? w;
  final wVal = m['/W'];
  if (wVal is _PdfArrayToken) {
    final tmp = <int>[];
    for (final e in wVal.values) {
      final vi = _asInt(e);
      if (vi != null) tmp.add(vi);
    }
    if (tmp.isNotEmpty) w = tmp;
  }

  List<int>? index;
  final idxVal = m['/Index'];
  if (idxVal is _PdfArrayToken) {
    final tmp = <int>[];
    for (final e in idxVal.values) {
      final vi = _asInt(e);
      if (vi != null) tmp.add(vi);
    }
    if (tmp.isNotEmpty) index = tmp;
  }

  return _XrefStreamDict(
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


Uint8List? _extractStream(Uint8List bytes, int dictEnd, int end, int? length) {
  int i = dictEnd;
  i = _skipPdfWsAndComments(bytes, i, end);
  if (!_matchToken(bytes, i, const <int>[0x73, 0x74, 0x72, 0x65, 0x61, 0x6D])) {
    return null;
  }
  i += 6;
  if (i < end && bytes[i] == 0x0D) i++;
  if (i < end && bytes[i] == 0x0A) i++;

  if (length != null && length > 0 && i + length <= end) {
    return bytes.sublist(i, i + length);
  }

  // fallback: até endstream
  final endPos = _indexOfSequence(bytes, _endStreamToken, i, end);
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
  Map<int, _XrefEntry> entries,
  void Function(int? rootObj) onRootFound,
) {
  final tailRoot = _findRootFromTail(bytes);
  if (tailRoot != null) {
    final found = _findObjectHeaderAnyGen(bytes, tailRoot.obj);
    if (found != null) {
      entries[tailRoot.obj] = _XrefEntry(
        offset: found.offset,
        gen: found.gen,
        type: _XrefType.inUse,
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
    i = _skipPdfWsAndComments(bytes, i, bytes.length);
    if (i >= bytes.length) break;

    if (_isDigit(bytes[i]) || bytes[i] == 0x2D || bytes[i] == 0x2B) {
      ({int value, int nextIndex}) num;
      try {
        num = _readInt(bytes, i, bytes.length);
      } catch (_) {
        i++;
        continue;
      }
      prevInt = lastInt;
      prevIntPos = lastIntPos;
      lastInt = num.value;
      lastIntPos = i;
      i = num.nextIndex;

      final j = _skipPdfWsAndComments(bytes, i, bytes.length);
      if (j < bytes.length && _matchToken(bytes, j, const <int>[0x6F, 0x62, 0x6A])) {
        // padrão: <prevInt> <lastInt> obj
        if (prevInt != null && prevIntPos != null) {
          final objId = prevInt;
          final gen = lastInt;

          if (objId > maxObjId) maxObjId = objId;
          final existing = entries[objId];
          if (existing == null || prevIntPos > existing.offset) {
            entries[objId] = _XrefEntry(
              offset: prevIntPos,
              gen: gen,
              type: _XrefType.inUse,
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
  Map<int, _XrefEntry> entries,
  void Function(int? rootObj) onRootFound,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return _repairXrefByScan(reader.readAll(), entries, onRootFound);
  }

  final tailRoot = _findRootFromTailFromReader(reader);
  if (tailRoot != null) {
    final found = _findObjectHeaderAnyGenReader(reader, tailRoot.obj);
    if (found != null) {
      entries[tailRoot.obj] = _XrefEntry(
        offset: found.offset,
        gen: found.gen,
        type: _XrefType.inUse,
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
      i = _skipPdfWsAndComments(bytes, i, end);
      if (i >= end) break;

      final b = bytes[i];
      if (b >= 0x30 && b <= 0x39) {
        final res = _readIntFast(bytes, i, end);
        if (res.value == -1) {
          i++;
          continue;
        }

        prevInt = lastInt;
        prevIntPosAbs = lastIntPosAbs;
        lastInt = res.value;
        lastIntPosAbs = offset + i;
        i = res.nextIndex;

        final j = _skipPdfWsAndComments(bytes, i, end);
        if (j < end &&
          _matchToken(bytes, j, const <int>[0x6F, 0x62, 0x6A])) {
          if (prevInt != null && prevIntPosAbs != null) {
            final objId = prevInt;
            final gen = lastInt;

            if (objId > maxObjId) maxObjId = objId;
            final existing = entries[objId];
            if (existing == null || prevIntPosAbs > existing.offset) {
              entries[objId] = _XrefEntry(
                offset: prevIntPosAbs,
                gen: gen,
                type: _XrefType.inUse,
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
                offset = (offset + end <= len)
                  ? (offset + end)
                    : len;
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

class _ScanDictInfoReader {
  _ScanDictInfoReader(
      this.nextIndex, this.isCatalog, this.skipAbs, this.streamStartAbs);
  final int nextIndex;
  final bool isCatalog;
  final int? skipAbs;
  final int? streamStartAbs;
}


_ScanDictInfoReader _scanObjectDictAndSkipStreamFromWindow(
  Uint8List bytes,
  int start,
  int baseOffset,
  int fileLength,
) {
  int i = _skipPdfWsAndComments(bytes, start, bytes.length);
  int? streamLength;
  bool isCatalog = false;
  if (i + 1 < bytes.length && bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
    final dict = _readDictLight(bytes, i, bytes.length);
    streamLength = dict.length;
    isCatalog = dict.isCatalog;
    i = dict.nextIndex;
  }

  i = _skipPdfWsAndComments(bytes, i, bytes.length);

  final streamStart = _findStreamStart(bytes, i);
  if (streamStart == null) {
    return _ScanDictInfoReader(i, isCatalog, null, null);
  }

  if (streamLength != null && streamLength > 0) {
    final skipAbs = baseOffset + streamStart + streamLength;
    if (skipAbs > 0 && skipAbs <= fileLength) {
      final nextIndex = (skipAbs <= baseOffset + bytes.length)
          ? (skipAbs - baseOffset)
          : bytes.length;
      return _ScanDictInfoReader(nextIndex, isCatalog, skipAbs, null);
    }
  }

  final endPos =
      _indexOfSequenceBmh(bytes, _endStreamToken, streamStart, bytes.length);
  if (endPos != -1) {
    final skipAbs = baseOffset + endPos + _endStreamToken.length;
    return _ScanDictInfoReader(
        endPos + _endStreamToken.length, isCatalog, skipAbs, null);
  }

  return _ScanDictInfoReader(
      bytes.length, isCatalog, null, baseOffset + streamStart);
}

int? _skipUnknownLengthStreamReader(
  PdfRandomAccessReader reader,
  int startAbs,
  int fileLength,
) {
  const chunkSize = 4 * 1024 * 1024;
  final overlap = _endStreamToken.length + 32;

  int offset = startAbs;
  while (offset < fileLength) {
    final windowSize = (offset + chunkSize > fileLength)
        ? (fileLength - offset)
        : chunkSize;
    if (windowSize <= 0) return null;

    final window = reader.readRange(offset, windowSize);
    final pos = _indexOfSequenceBmh(window, _endStreamToken, 0, window.length);
    if (pos != -1) {
      return offset + pos + _endStreamToken.length;
    }

    if (offset + chunkSize >= fileLength) break;
    offset += chunkSize - overlap;
  }

  return null;
}

_PdfRef? _findRootFromTailFromReader(PdfRandomAccessReader reader) {
  final tailSize = reader.length > 1024 * 1024 ? 1024 * 1024 : reader.length;
  final start = reader.length - tailSize;
  final tail = reader.readRange(start, tailSize);
  int i = 0;
  while (i < tail.length) {
    if (tail[i] == 0x2F /* / */) {
      final name = _readName(tail, i, tail.length);
      if (name.value == '/Root') {
        i = _skipPdfWsAndComments(tail, name.nextIndex, tail.length);
        if (i < tail.length && _isDigit(tail[i])) {
          final ref = _readRef(tail, i, tail.length);
          if (ref != null) return _PdfRef(ref.obj, ref.gen);
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
  final tail = _findObjectHeaderAnyGenInRangeReader(reader, objId, tailStart, len);
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
    final found = _findObjectHeaderAnyGenInRange(window, objId, 0, window.length);
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

class _ScanDictInfo {
  _ScanDictInfo(this.nextIndex, this.isCatalog);
  final int nextIndex;
  final bool isCatalog;
}

_ScanDictInfo _scanObjectDictAndSkipStream(Uint8List bytes, int start) {
  int i = _skipPdfWsAndComments(bytes, start, bytes.length);
  int? streamLength;
  bool isCatalog = false;

  if (i + 1 < bytes.length && bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
    final dict = _readDictLight(bytes, i, bytes.length);
    streamLength = dict.length;
    isCatalog = dict.isCatalog;
    i = dict.nextIndex;
  }

  i = _skipPdfWsAndComments(bytes, i, bytes.length);
  if (_matchToken(bytes, i, const <int>[0x73, 0x74, 0x72, 0x65, 0x61, 0x6D])) {
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
    final endPos = _indexOfSequence(bytes, _endStreamToken, i, bytes.length);
    if (endPos != -1) {
      i = endPos + _endStreamToken.length;
    }
  }

  return _ScanDictInfo(i, isCatalog);
}

class _DictLightResult {
  _DictLightResult(this.nextIndex, this.length, this.isCatalog);
  final int nextIndex;
  final int? length;
  final bool isCatalog;
}

_DictLightResult _readDictLight(Uint8List bytes, int start, int end) {
  int i = start;
  if (i + 1 >= end || bytes[i] != 0x3C || bytes[i + 1] != 0x3C) {
    return _DictLightResult(i, null, false);
  }
  i += 2;

  int? length;
  bool isCatalog = false;
  final limitEnd = (start + 4096 < end) ? (start + 4096) : end;

  const keyLength = [0x2F, 0x4C, 0x65, 0x6E, 0x67, 0x74, 0x68];
  const keyType = [0x2F, 0x54, 0x79, 0x70, 0x65];
  const valCatalog = [0x2F, 0x43, 0x61, 0x74, 0x61, 0x6C, 0x6F, 0x67];

  while (i < limitEnd) {
    i = _skipPdfWsAndComments(bytes, i, limitEnd);
    if (i >= limitEnd) break;

    if (bytes[i] == 0x3E && i + 1 < limitEnd && bytes[i + 1] == 0x3E) {
      return _DictLightResult(i + 2, length, isCatalog);
    }

    if (bytes[i] == 0x2F) {
      final isKeyLength = _matchBytes(bytes, i, keyLength);
      final isKeyType = !isKeyLength && _matchBytes(bytes, i, keyType);

      i = _skipTokenRaw(bytes, i, limitEnd);
      i = _skipPdfWsAndComments(bytes, i, limitEnd);
      if (i >= limitEnd) break;

      if (isKeyLength) {
        if (_isDigit(bytes[i])) {
          final res = _readIntFast(bytes, i, limitEnd);
          if (res.value != -1) {
            final possibleLen = res.value;
            int nextI = res.nextIndex;

            int k = _skipPdfWsAndComments(bytes, nextI, limitEnd);
            bool isRef = false;
            if (k < limitEnd) {
              if (_isDigit(bytes[k])) {
                final resGen = _readIntFast(bytes, k, limitEnd);
                int afterGen =
                    _skipPdfWsAndComments(bytes, resGen.nextIndex, limitEnd);
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
        if (_matchBytes(bytes, i, valCatalog)) {
          isCatalog = true;
        }
      }

      i = _skipTokenRaw(bytes, i, limitEnd);
      continue;
    }

    i++;
  }

  return _DictLightResult(i, length, isCatalog);
}

_PdfRef? _findRootFromTail(Uint8List bytes) {
  final tailSize = bytes.length > 1024 * 1024 ? 1024 * 1024 : bytes.length;
  final start = bytes.length - tailSize;
  int i = start;
  while (i < bytes.length) {
    if (bytes[i] == 0x2F /* / */) {
      final name = _readName(bytes, i, bytes.length);
      if (name.value == '/Root') {
        i = _skipPdfWsAndComments(bytes, name.nextIndex, bytes.length);
        if (i < bytes.length && _isDigit(bytes[i])) {
          final ref = _readRef(bytes, i, bytes.length);
          if (ref != null) return _PdfRef(ref.obj, ref.gen);
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
  final headSize = bytes.length > 16 * 1024 * 1024
      ? 16 * 1024 * 1024
      : bytes.length;
  final tailSize = bytes.length > 16 * 1024 * 1024
      ? 16 * 1024 * 1024
      : bytes.length;

  final head = _findObjectHeaderAnyGenInRange(bytes, objId, 0, headSize);
  if (head != null) return head;

  final tailStart = bytes.length - tailSize;
  final tail = _findObjectHeaderAnyGenInRange(bytes, objId, tailStart, bytes.length);
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
    i = _skipPdfWsAndComments(bytes, i, end);
    if (i >= end) break;
    if (!_isDigit(bytes[i])) {
      i++;
      continue;
    }
    try {
      final obj = _readInt(bytes, i, end);
      if (obj.value != objId) {
        i = obj.nextIndex;
        continue;
      }
      int j = _skipPdfWsAndComments(bytes, obj.nextIndex, end);
      if (j >= end || !_isDigit(bytes[j])) {
        i = obj.nextIndex;
        continue;
      }
      final gen = _readInt(bytes, j, end);
      j = _skipPdfWsAndComments(bytes, gen.nextIndex, end);
      if (_matchToken(bytes, j, const <int>[0x6F, 0x62, 0x6A])) {
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
  int i = _skipPdfWsAndComments(bytes, offset, bytes.length);
  if (i >= bytes.length || !_isDigit(bytes[i])) return false;
  final obj = _readInt(bytes, i, bytes.length);
  if (obj.value != objId) return false;
  i = _skipPdfWsAndComments(bytes, obj.nextIndex, bytes.length);
  if (i >= bytes.length || !_isDigit(bytes[i])) return false;
  final genRead = _readInt(bytes, i, bytes.length);
  if (genRead.value != gen) return false;
  i = _skipPdfWsAndComments(bytes, genRead.nextIndex, bytes.length);
  return _matchToken(bytes, i, const <int>[0x6F, 0x62, 0x6A]);
}

int? _findObjectHeader(
  Uint8List bytes,
  int objId,
  int gen,
  int start,
  int end,
) {
  for (int i = start; i < end; i++) {
    if (!_isDigit(bytes[i])) continue;
    try {
      final obj = _readInt(bytes, i, end);
      if (obj.value != objId) continue;
      int j = _skipPdfWsAndComments(bytes, obj.nextIndex, end);
      if (j >= end || !_isDigit(bytes[j])) continue;
      final genRead = _readInt(bytes, j, end);
      if (genRead.value != gen) continue;
      j = _skipPdfWsAndComments(bytes, genRead.nextIndex, end);
      if (_matchToken(bytes, j, const <int>[0x6F, 0x62, 0x6A])) {
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
  if (!_isDigit(bytes[i])) return null;
  final obj = _readInt(bytes, i, end);
  i = _skipPdfWsAndComments(bytes, obj.nextIndex, end);
  if (i >= end || !_isDigit(bytes[i])) return null;
  final gen = _readInt(bytes, i, end);
  i = _skipPdfWsAndComments(bytes, gen.nextIndex, end);
  if (i >= end || bytes[i] != 0x52 /* R */) return null;
  return (obj: obj.value, gen: gen.value);
}

class _TrailerDictValues {
  _TrailerDictValues({this.size, this.prev, this.rootObj, this.infoObj, this.id});
  final int? size;
  final int? prev;
  final int? rootObj;
  final int? infoObj;
  final Uint8List? id;
}

_TrailerDictValues _parseTrailerDict(Uint8List bytes, int start, int end) {
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

    i = _skipPdfWsAndComments(bytes, i, end);
    if (i >= end) break;

    if (bytes[i] == 0x2F /* / */) {
      final name = _readName(bytes, i, end);
      currentKey = name.value;
      i = name.nextIndex;
      continue;
    }

    if (currentKey != null) {
      if (_isDigit(bytes[i]) || bytes[i] == 0x2D) {
        final num = _readInt(bytes, i, end);
        if (currentKey == '/Size') size = num.value;
        if (currentKey == '/Prev') prev = num.value;

        if (currentKey == '/Root' || currentKey == '/Info') {
          final ref = _readRef(bytes, i, end);
          if (ref != null) {
            if (currentKey == '/Root') rootObj = ref.obj;
            if (currentKey == '/Info') infoObj = ref.obj;
          }
        }

        i = num.nextIndex;
        currentKey = null;
        continue;
      }

      if (currentKey == '/ID' && bytes[i] == 0x5B /* [ */) {
        final parsed = _readIdArray(bytes, i, end);
        id = parsed.id;
        i = parsed.nextIndex;
        currentKey = null;
        continue;
      }
    }

    i++;
  }

  return _TrailerDictValues(
    size: size,
    prev: prev,
    rootObj: rootObj,
    infoObj: infoObj,
    id: id,
  );
}

_ParsedIndirectObject? _readIndirectObjectAt(
  Uint8List bytes,
  int offset,
  int end,
  PdfDocumentParser parser,
) {
  int i = _skipPdfWsAndComments(bytes, offset, end);
  if (i >= end || !_isDigit(bytes[i])) return null;
  final obj = _readInt(bytes, i, end);
  i = _skipPdfWsAndComments(bytes, obj.nextIndex, end);
  if (i >= end || !_isDigit(bytes[i])) return null;
  final gen = _readInt(bytes, i, end);
  i = _skipPdfWsAndComments(bytes, gen.nextIndex, end);
  if (!_matchToken(bytes, i, const <int>[0x6F, 0x62, 0x6A])) return null;
  i += 3;
  i = _skipPdfWsAndComments(bytes, i, end);

  final parsed = _parseObject(bytes, i, end);
  if (parsed == null) return null;

  Uint8List? streamData;
  if (parsed.value is _PdfDictToken && parsed.dictEnd != null) {
    final dict = parsed.value as _PdfDictToken;
    final length = _resolveLength(dict, parser);
    final data = _extractStream(bytes, parsed.dictEnd!, end, length);
    if (data != null) {
      streamData = data;
    }
  }

  return _ParsedIndirectObject(
    objId: obj.value,
    gen: gen.value,
    value: parsed.value,
    streamData: streamData,
  );
}

_ParsedIndirectObject? _readIndirectObjectAtFromReader(
  PdfRandomAccessReader reader,
  int offset,
  PdfDocumentParser parser,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return _readIndirectObjectAt(reader.readAll(), offset, reader.length, parser);
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

    int i = _skipPdfWsAndComments(window, 0, window.length);
    if (i >= window.length || !_isDigit(window[i])) continue;
    final obj = _readInt(window, i, window.length);
    i = _skipPdfWsAndComments(window, obj.nextIndex, window.length);
    if (i >= window.length || !_isDigit(window[i])) continue;
    final gen = _readInt(window, i, window.length);
    i = _skipPdfWsAndComments(window, gen.nextIndex, window.length);
    if (!_matchToken(window, i, const <int>[0x6F, 0x62, 0x6A])) continue;
    i += 3;
    i = _skipPdfWsAndComments(window, i, window.length);

    final parsed = _parseObject(window, i, window.length);
    if (parsed == null) continue;

    Uint8List? streamData;
    if (parsed.value is _PdfDictToken && parsed.dictEnd != null) {
      final dict = parsed.value as _PdfDictToken;
      final length = _resolveLength(dict, parser);
      final streamStart = _findStreamStart(window, parsed.dictEnd!);

      if (streamStart != null && length != null) {
        final abs = offset + streamStart;
        if (abs + length <= len) {
          streamData = reader.readRange(abs, length);
        }
      } else {
        final data = _extractStream(window, parsed.dictEnd!, window.length, length);
        if (data != null) {
          streamData = data;
        }
      }
    }

    return _ParsedIndirectObject(
      objId: obj.value,
      gen: gen.value,
      value: parsed.value,
      streamData: streamData,
    );
  }

  return null;
}

_ParsedIndirectObject? _readIndirectObjectAtFromReaderNoStream(
  PdfRandomAccessReader reader,
  int offset,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return _readIndirectObjectAt(reader.readAll(), offset, reader.length, _DummyParser());
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

    int i = _skipPdfWsAndComments(window, 0, window.length);
    if (i >= window.length || !_isDigit(window[i])) continue;
    final obj = _readInt(window, i, window.length);
    i = _skipPdfWsAndComments(window, obj.nextIndex, window.length);
    if (i >= window.length || !_isDigit(window[i])) continue;
    final gen = _readInt(window, i, window.length);
    i = _skipPdfWsAndComments(window, gen.nextIndex, window.length);
    if (!_matchToken(window, i, const <int>[0x6F, 0x62, 0x6A])) continue;
    i += 3;
    i = _skipPdfWsAndComments(window, i, window.length);

    final parsed = _parseObject(window, i, window.length);
    if (parsed == null) continue;

    return _ParsedIndirectObject(
      objId: obj.value,
      gen: gen.value,
      value: parsed.value,
      streamData: null,
    );
  }

  return null;
}

class _DummyParser extends PdfDocumentParser {
  _DummyParser() : super(Uint8List(0));
}

_ParsedIndirectObject? _readCompressedObject(
  int objId,
  _XrefEntry entry,
  PdfDocumentParser parser,
) {
  final objStmId = entry.offset;
  final objStm = parser._getObject(objStmId);
  if (objStm == null || objStm.value is! _PdfDictToken) return null;
  if (objStm.streamData == null) return null;

  final dict = objStm.value as _PdfDictToken;
  final type = _asName(dict.values['/Type']);
  if (type != '/ObjStm') return null;

  final n = _asInt(dict.values['/N']);
  final first = _asInt(dict.values['/First']);
  if (n == null || first == null) return null;

  Uint8List data = objStm.streamData!;
  final filter = _asName(dict.values['/Filter']);
  if (filter == '/FlateDecode') {
    if (data.length > _maxStreamDecodeSize) return null;
    data = Uint8List.fromList(ZLibDecoder().decodeBytes(data));
  }

  final header = _readObjectStreamHeader(data, n);
  if (header == null) return null;

  final entryIndex = header.index[objId];
  if (entryIndex == null) return null;

  final objOffset = first + entryIndex;
  if (objOffset < 0 || objOffset >= data.length) return null;

  final parsed = _parseObject(data, objOffset, data.length);
  if (parsed == null) return null;

  return _ParsedIndirectObject(
    objId: objId,
    gen: entry.gen,
    value: parsed.value,
    streamData: null,
  );
}

class _ObjStmHeader {
  _ObjStmHeader(this.index);
  final Map<int, int> index;
}

_ObjStmHeader? _readObjectStreamHeader(Uint8List data, int n) {
  int i = 0;
  final index = <int, int>{};
  for (int k = 0; k < n; k++) {
    i = _skipPdfWsAndComments(data, i, data.length);
    final obj = _readNumber(data, i, data.length);
    if (obj == null || obj.value is! int) return null;
    i = obj.nextIndex;

    i = _skipPdfWsAndComments(data, i, data.length);
    final offset = _readNumber(data, i, data.length);
    if (offset == null || offset.value is! int) return null;
    i = offset.nextIndex;

    index[obj.value as int] = offset.value as int;
  }
  return _ObjStmHeader(index);
}

int? _resolveLength(_PdfDictToken dict, PdfDocumentParser parser) {
  final lenValue = dict.values['/Length'];
  if (lenValue is int) return lenValue;
  if (lenValue is double) return lenValue.toInt();
  if (lenValue is _PdfRef) {
    final lenObj = parser._getObject(lenValue.obj);
    if (lenObj != null && lenObj.value is int) {
      return lenObj.value as int;
    }
  }
  return null;
}

_ParseResult? _parseObject(Uint8List bytes, int start, int end,
    {int depth = 0}) {
  if (depth > 64) return null;
  int i = _skipPdfWsAndComments(bytes, start, end);
  if (i >= end) return null;

  final b = bytes[i];
  if (b == 0x2F /* / */) {
    final name = _readName(bytes, i, end);
    return _ParseResult(_PdfNameToken(name.value), name.nextIndex);
  }
  if (b == 0x28 /* ( */) {
    final str = _readLiteralString(bytes, i, end);
    return _ParseResult(_PdfStringToken(str.bytes, PdfStringFormat.literal),
        str.nextIndex);
  }
  if (b == 0x3C /* < */) {
    if (i + 1 < end && bytes[i + 1] == 0x3C) {
      final dict = _readDict(bytes, i, end, depth: depth + 1);
      return _ParseResult(dict.value, dict.nextIndex, dictEnd: dict.dictEnd);
    }
    final hex = _readHexString(bytes, i, end);
    return _ParseResult(_PdfStringToken(hex.bytes, PdfStringFormat.binary),
        hex.nextIndex);
  }
  if (b == 0x5B /* [ */) {
    final arr = _readArray(bytes, i, end, depth: depth + 1);
    return _ParseResult(arr.value, arr.nextIndex);
  }
  if (_isDigit(b) || b == 0x2D || b == 0x2B || b == 0x2E) {
    final num = _readNumber(bytes, i, end);
    if (num == null) return null;

    final maybeRef = _tryReadRefAfterNumber(bytes, num, end);
    if (maybeRef != null) {
      return _ParseResult(maybeRef.value, maybeRef.nextIndex);
    }
    return _ParseResult(num.value, num.nextIndex);
  }

  if (_matchToken(bytes, i, const <int>[0x74, 0x72, 0x75, 0x65])) {
    return _ParseResult(true, i + 4);
  }
  if (_matchToken(bytes, i, const <int>[0x66, 0x61, 0x6C, 0x73, 0x65])) {
    return _ParseResult(false, i + 5);
  }
  if (_matchToken(bytes, i, const <int>[0x6E, 0x75, 0x6C, 0x6C])) {
    return _ParseResult(null, i + 4);
  }

  return null;
}

_ParseResult _readDict(Uint8List bytes, int start, int end,
    {int depth = 0}) {
  int i = start;
  if (bytes[i] != 0x3C || bytes[i + 1] != 0x3C) {
    return _ParseResult(_PdfDictToken(<String, dynamic>{}), i);
  }
  i += 2;
  final values = <String, dynamic>{};
  while (i < end) {
    i = _skipPdfWsAndComments(bytes, i, end);
    if (i + 1 < end && bytes[i] == 0x3E && bytes[i + 1] == 0x3E) {
      i += 2;
      return _ParseResult(_PdfDictToken(values), i, dictEnd: i);
    }

    if (bytes[i] == 0x2F) {
      final key = _readName(bytes, i, end);
      i = _skipPdfWsAndComments(bytes, key.nextIndex, end);
      final value = _parseObject(bytes, i, end, depth: depth + 1);
      if (value != null) {
        values[key.value] = value.value;
        i = value.nextIndex;
        continue;
      }
    }
    i++;
  }
  return _ParseResult(_PdfDictToken(values), i);
}

_ParseResult _readArray(Uint8List bytes, int start, int end,
    {int depth = 0}) {
  int i = start;
  if (bytes[i] != 0x5B) {
    return _ParseResult(_PdfArrayToken(<dynamic>[]), i);
  }
  i++;
  final values = <dynamic>[];
  while (i < end) {
    i = _skipPdfWsAndComments(bytes, i, end);
    if (i < end && bytes[i] == 0x5D) {
      i++;
      break;
    }
    final value = _parseObject(bytes, i, end, depth: depth + 1);
    if (value != null) {
      values.add(value.value);
      i = value.nextIndex;
      continue;
    }
    i++;
  }
  return _ParseResult(_PdfArrayToken(values), i);
}

({dynamic value, int nextIndex})? _tryReadRefAfterNumber(
  Uint8List bytes,
  ({dynamic value, int nextIndex}) first,
  int end,
) {
  if (first.value is! int) return null;
  int i = _skipPdfWsAndComments(bytes, first.nextIndex, end);
  if (i >= end || !_isDigit(bytes[i])) return null;
  final gen = _readInt(bytes, i, end);
  i = _skipPdfWsAndComments(bytes, gen.nextIndex, end);
  if (i < end && bytes[i] == 0x52 /* R */) {
    return (value: _PdfRef(first.value as int, gen.value), nextIndex: i + 1);
  }
  return null;
}

({dynamic value, int nextIndex})? _readNumber(
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
    if (_isDigit(b)) {
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

({Uint8List bytes, int nextIndex}) _readLiteralString(
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

PdfDict<PdfDataType> _toPdfDict(
  _PdfDictToken dict, {
  Set<String> ignoreKeys = const {},
}) {
  final values = <String, PdfDataType>{};
  for (final entry in dict.values.entries) {
    if (ignoreKeys.contains(entry.key)) continue;
    final converted = _toPdfDataType(entry.value);
    if (converted != null) values[entry.key] = converted;
  }
  return PdfDict.values(values);
}

PdfArray _toPdfArray(_PdfArrayToken array) {
  final values = <PdfDataType>[];
  for (final v in array.values) {
    final converted = _toPdfDataType(v);
    if (converted != null) values.add(converted);
  }
  return PdfArray(values);
}

PdfDataType? _toPdfDataType(dynamic value) {
  if (value == null) return const PdfNull();
  if (value is bool) return PdfBool(value);
  if (value is int || value is double) {
    return PdfNum(value is int ? value : (value as double));
  }
  if (value is _PdfNameToken) return PdfName(value.value);
  if (value is _PdfStringToken) {
    return PdfString(value.bytes, format: value.format, encrypted: false);
  }
  if (value is _PdfRef) return PdfIndirect(value.obj, value.gen);
  if (value is _PdfArrayToken) return _toPdfArray(value);
  if (value is _PdfDictToken) return _toPdfDict(value);
  return null;
}

void _mergeDictIntoPdfDict(
  PdfDict<PdfDataType> target,
  _PdfDictToken source, {
  Set<String> ignoreKeys = const {},
}) {
  final converted = _toPdfDict(source);
  for (final entry in converted.values.entries) {
    if (ignoreKeys.contains(entry.key)) continue;
    target[entry.key] = entry.value;
  }
}

_PdfRef? _asRef(dynamic value) {
  if (value is _PdfRef) return value;
  return null;
}

String? _asName(dynamic value) {
  if (value is _PdfNameToken) return value.value;
  return null;
}

int? _asInt(dynamic value) {
  if (value is int) return value;
  if (value is double) return value.toInt();
  return null;
}

List<double>? _asNumArray(dynamic value) {
  if (value is _PdfArrayToken && value.values.length >= 4) {
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

PdfPageFormat? _pageFormatFromBox(List<double>? box) {
  if (box == null || box.length < 4) return null;
  final width = box[2] - box[0];
  final height = box[3] - box[1];
  if (width <= 0 || height <= 0) return null;
  return PdfPageFormat(width, height);
}

PdfPageRotation _pageRotationFromValue(dynamic value) {
  final rot = _asInt(value) ?? 0;
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

({Uint8List? id, int nextIndex}) _readIdArray(
  Uint8List bytes,
  int start,
  int end,
) {
  int i = start;
  if (bytes[i] != 0x5B) return (id: null, nextIndex: i);
  i++;
  i = _skipPdfWsAndComments(bytes, i, end);
  if (i >= end || bytes[i] != 0x3C) return (id: null, nextIndex: i);
  final id1 = _readHexString(bytes, i, end);
  i = id1.nextIndex;
  return (id: id1.bytes, nextIndex: i);
}

({Uint8List bytes, int nextIndex}) _readHexString(
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
    if (_isWhitespace(b)) {
      i++;
      continue;
    }
    hex.add(b);
    i++;
  }
  if (i >= end) throw StateError('Hex string inválida');
  i++;
  return (bytes: _hexToBytes(hex), nextIndex: i);
}

Uint8List _hexToBytes(List<int> hexBytes) {
  final out = Uint8List((hexBytes.length + 1) ~/ 2);
  int oi = 0;
  for (int i = 0; i < hexBytes.length; i += 2) {
    final hi = hexBytes[i];
    final lo = (i + 1 < hexBytes.length) ? hexBytes[i + 1] : 0x30;
    out[oi++] = (_hexValue(hi) << 4) | _hexValue(lo);
  }
  return out;
}

int _hexValue(int b) {
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
    final version = _readPdfVersion(bytes);
    final isPdf15OrAbove = version >= 1.5;
    final hasSignatures = _findByteRangeToken(bytes) != -1;

    int? permissionP;
    try {
      final parser = PdfDocumentParser(bytes);
      permissionP = _extractDocMdpPermission(parser);
    } catch (_) {
      permissionP = null;
    }
    permissionP ??= _extractDocMdpPermissionFromBytes(bytes);

    return PdfQuickInfo._(
      isPdf15OrAbove: isPdf15OrAbove,
      hasSignatures: hasSignatures,
      docMdpPermissionP: permissionP,
    );
  }
}

double _readPdfVersion(Uint8List bytes) {
  const token = <int>[0x25, 0x50, 0x44, 0x46, 0x2D]; // %PDF-
  final limit = bytes.length > 1024 ? 1024 : bytes.length;
  final pos = _indexOfSequence(bytes, token, 0, limit);
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

int _findByteRangeToken(Uint8List bytes) {
  const token = <int>[
    0x2F, // /
    0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65, // ByteRange
  ];
  return _indexOfSequence(bytes, token, 0, bytes.length);
}

int? _extractDocMdpPermission(PdfDocumentParser parser) {
  parser._ensureXrefParsed();
  final trailer =
      parser._trailerInfo ?? _readTrailerInfoFromReader(parser.reader, parser.xrefOffset);
  final rootObjId = trailer.rootObj;
  if (rootObjId == null) return null;

  final rootObj = parser._getObjectNoStream(rootObjId) ?? parser._getObject(rootObjId);
  if (rootObj == null || rootObj.value is! _PdfDictToken) return null;
  final rootDict = rootObj.value as _PdfDictToken;

  final permsDict = parser._resolveDictFromValueNoStream(rootDict.values['/Perms']);
  if (permsDict == null) return null;

  dynamic docMdpVal = permsDict.values['/DocMDP'];
  if (docMdpVal is _PdfRef) {
    final docObj = parser._getObjectNoStream(docMdpVal.obj) ?? parser._getObject(docMdpVal.obj);
    docMdpVal = docObj?.value;
  }
  if (docMdpVal is! _PdfDictToken) return null;

  final refVal = docMdpVal.values['/Reference'];
  if (refVal is! _PdfArrayToken) return null;

  for (final item in refVal.values) {
    dynamic refItem = item;
    if (refItem is _PdfRef) {
      final refObj = parser._getObjectNoStream(refItem.obj) ?? parser._getObject(refItem.obj);
      refItem = refObj?.value;
    }
    if (refItem is! _PdfDictToken) continue;
    dynamic tp = refItem.values['/TransformParams'];
    if (tp is _PdfRef) {
      final tpObj = parser._getObjectNoStream(tp.obj) ?? parser._getObject(tp.obj);
      tp = tpObj?.value;
    }
    if (tp is! _PdfDictToken) continue;
    final p = _asInt(tp.values['/P']);
    if (p != null) return p;
  }

  return null;
}

int? _extractDocMdpPermissionFromBytes(Uint8List bytes) {
  const docMdpToken = <int>[
    0x2F, // /
    0x44, 0x6F, 0x63, 0x4D, 0x44, 0x50, // DocMDP
  ];
  const pToken = <int>[0x2F, 0x50]; // /P

  int offset = 0;
  while (offset < bytes.length) {
    final pos = _indexOfSequence(bytes, docMdpToken, offset, bytes.length);
    if (pos == -1) break;
    final windowStart = pos;
    final windowEnd = (pos + 4096 < bytes.length) ? (pos + 4096) : bytes.length;
    final pPos = _indexOfSequence(bytes, pToken, windowStart, windowEnd);
    if (pPos != -1) {
      try {
        int i = pPos + pToken.length;
        i = _skipPdfWsAndComments(bytes, i, windowEnd);
        final parsed = _readInt(bytes, i, windowEnd);
        if (parsed.value >= 1 && parsed.value <= 3) {
          return parsed.value;
        }
      } catch (_) {}
    }
    offset = pos + docMdpToken.length;
  }
  return null;
}

List<PdfSignatureFieldInfo> _extractSignatureFieldsFromBytes(Uint8List bytes) {
  final ranges = _findAllByteRangesFromBytes(bytes);
  if (ranges.isEmpty) return const <PdfSignatureFieldInfo>[];

  final out = <PdfSignatureFieldInfo>[];
  for (final range in ranges) {
    final gapStart = range[0] + range[1];
    final gapEnd = range[2];
    const windowSize = 524288;
    final windowStart = gapStart - windowSize >= 0 ? gapStart - windowSize : 0;
    final windowEnd = gapEnd + windowSize <= bytes.length ? gapEnd + windowSize : bytes.length;
    final window = bytes.sublist(windowStart, windowEnd);

    final fieldName = _scanPdfStringValue(window, const <int>[
      0x2F, 0x54 // /T
    ]);
    final reason = _scanPdfStringValue(window, const <int>[
      0x2F, 0x52, 0x65, 0x61, 0x73, 0x6F, 0x6E // /Reason
    ]);
    final location = _scanPdfStringValue(window, const <int>[
      0x2F, 0x4C, 0x6F, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E // /Location
    ]);
    final name = _scanPdfStringValue(window, const <int>[
      0x2F, 0x4E, 0x61, 0x6D, 0x65 // /Name
    ]);
    final signingTime = _scanPdfStringValue(window, const <int>[
      0x2F, 0x4D // /M
    ]);
    final subFilter = _scanPdfNameValue(window, const <int>[
      0x2F, 0x53, 0x75, 0x62, 0x46, 0x69, 0x6C, 0x74, 0x65, 0x72 // /SubFilter
    ]);

    out.add(PdfSignatureFieldInfo(
      fieldName: fieldName,
      reason: reason,
      location: location,
      name: name,
      signingTimeRaw: signingTime,
      subFilter: subFilter,
      byteRange: range,
    ));
  }
  return out;
}

List<List<int>> _findAllByteRangesFromBytes(Uint8List bytes) {
  const token = <int>[
    0x2F, 0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65
  ];
  final out = <List<int>>[];
  var offset = 0;
  while (offset < bytes.length) {
    final pos = _indexOfSequence(bytes, token, offset, bytes.length);
    if (pos == -1) break;
    var i = _skipPdfWsAndComments(bytes, pos + token.length, bytes.length);
    if (i >= bytes.length || bytes[i] != 0x5B) {
      offset = pos + token.length;
      continue;
    }
    i++;
    final nums = <int>[];
    while (i < bytes.length && nums.length < 4) {
      i = _skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length) break;
      if (bytes[i] == 0x5D) {
        i++;
        break;
      }
      try {
        final parsed = _readInt(bytes, i, bytes.length);
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

String? _scanPdfStringValue(Uint8List bytes, List<int> key) {
  final pos = _indexOfSequence(bytes, key, 0, bytes.length);
  if (pos == -1) return null;
  var i = _skipPdfWsAndComments(bytes, pos + key.length, bytes.length);
  if (i >= bytes.length) return null;
  if (bytes[i] == 0x28) {
    final parsed = _readLiteralString(bytes, i, bytes.length);
    return _decodePdfString(parsed.bytes);
  }
  if (bytes[i] == 0x3C) {
    try {
      final hex = _readHexString(bytes, i, bytes.length);
      return _decodePdfString(hex.bytes);
    } catch (_) {
      return null;
    }
  }
  if (bytes[i] == 0x2F) {
    i++;
    final start = i;
    while (i < bytes.length &&
        !_isWhitespace(bytes[i]) &&
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

String? _scanPdfNameValue(Uint8List bytes, List<int> key) {
  final pos = _indexOfSequence(bytes, key, 0, bytes.length);
  if (pos == -1) return null;
  var i = _skipPdfWsAndComments(bytes, pos + key.length, bytes.length);
  if (i >= bytes.length || bytes[i] != 0x2F) return null;
  i++;
  final start = i;
  while (i < bytes.length &&
      !_isWhitespace(bytes[i]) &&
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
    i = _skipPdfWsAndComments(bytes, i, bytes.length);
    if (i >= bytes.length) break;

    // Leitura do número do objeto.
    if (!_isDigit(bytes[i])) {
      i++;
      continue;
    }
    final objNum = _readInt(bytes, i, bytes.length);
    i = objNum.nextIndex;

    i = _skipPdfWsAndComments(bytes, i, bytes.length);
    if (i >= bytes.length || !_isDigit(bytes[i])) {
      continue;
    }
    final genNum = _readInt(bytes, i, bytes.length);
    i = genNum.nextIndex;

    i = _skipPdfWsAndComments(bytes, i, bytes.length);
    if (i + 2 < bytes.length &&
        bytes[i] == 0x6F &&
        bytes[i + 1] == 0x62 &&
        bytes[i + 2] == 0x6A &&
        _isDelimiter(bytes, i + 3)) {
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
      i = _skipPdfWsAndComments(window, i, window.length);
      if (i >= window.length) break;

      if (!_isDigit(window[i])) {
        i++;
        continue;
      }
      try {
        final objNum = _readInt(window, i, window.length);
        i = objNum.nextIndex;
        i = _skipPdfWsAndComments(window, i, window.length);
        if (i >= window.length || !_isDigit(window[i])) continue;
        final genNum = _readInt(window, i, window.length);
        i = genNum.nextIndex;
        i = _skipPdfWsAndComments(window, i, window.length);
        if (_matchToken(window, i, const <int>[0x6F, 0x62, 0x6A])) {
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

int _lastIndexOfSequence(
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

int _indexOfSequence(
  Uint8List bytes,
  List<int> pattern,
  int start,
  int end,
) {
  return _indexOfSequenceBmh(bytes, pattern, start, end);
}

int _indexOfSequenceBmh(
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

int _skipPdfWsAndComments(Uint8List bytes, int i, int end) {
  if (i < end) {
    final b = bytes[i];
    if (!_isWhitespace(b) && b != 0x25) {
      return i;
    }
  }
  while (i < end) {
    final b = bytes[i];
    if (_isWhitespace(b)) {
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

({int value, int nextIndex}) _readIntFast(Uint8List bytes, int start, int end) {
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

bool _matchBytes(Uint8List bytes, int offset, List<int> target) {
  if (offset + target.length > bytes.length) return false;
  for (int i = 0; i < target.length; i++) {
    if (bytes[offset + i] != target[i]) return false;
  }
  return true;
}

int _skipTokenRaw(Uint8List bytes, int i, int end) {
  i = _skipPdfWsAndComments(bytes, i, end);
  if (i >= end) return i;

  final b = bytes[i];

  if (b == 0x2F) {
    i++;
    while (i < end) {
      final c = bytes[i];
      if (_isWhitespace(c) ||
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
    if (_isWhitespace(c) ||
        c == 0x2F ||
        c == 0x28 ||
        c == 0x3C ||
        c == 0x5B ||
        c == 0x25) break;
    i++;
  }
  return i;
}

({int value, int nextIndex}) _readInt(Uint8List bytes, int i, int end) {
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
    if (!_isDigit(b)) break;
    value = (value * 10) + (b - 0x30);
    i++;
    digits++;
  }
  if (digits == 0) {
    throw StateError('Inteiro inválido');
  }
  return (value: neg ? -value : value, nextIndex: i);
}

bool _isDigit(int b) => b >= 0x30 && b <= 0x39;

bool _isHexDigit(int b) =>
  (b >= 0x30 && b <= 0x39) ||
  (b >= 0x41 && b <= 0x46) ||
  (b >= 0x61 && b <= 0x66);

bool _isWhitespace(int b) =>
    b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0C || b == 0x0D || b == 0x20;

bool _isDelimiter(Uint8List bytes, int index) {
  if (index >= bytes.length) return true;
  final b = bytes[index];
  return _isWhitespace(b) || b == 0x3C || b == 0x3E || b == 0x2F || b == 0x28 || b == 0x29;
}
