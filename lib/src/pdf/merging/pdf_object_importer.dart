import 'dart:convert';
import 'dart:typed_data';

import '../crypto/pdf_crypto.dart';
import '../editing/object_graph/pdf_object_converter.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/dict_stream.dart';
import '../format/indirect.dart';
import '../format/null_value.dart';
import '../obj/object.dart';
import '../parsing/parser_objects.dart';
import '../parsing/pdf_parser_types.dart';
import '../pdf_names.dart';
import 'pdf_import_context.dart';

/// Materializes objects read from a source document as indirect objects of the
/// destination document, renumbering every reference.
///
/// A document loaded by this library does not materialize its graph — it lives
/// in the bytes of the original file (see `PdfDocument.load`). Merging demands
/// the opposite: every reachable object must exist in the destination with a
/// new number. That is what this class does.
///
/// Two guarantees hold the algorithm together:
///
/// 1. **The destination object is allocated before the content is converted.**
///    That way a cycle (`A → B → A`) finds the object again in the memo
///    instead of recursing forever.
/// 2. **Page references are not followed.** Importing `/Parent`, or the
///    destination of a link, would drag in the whole page tree of the source.
///    They are resolved through the map of pages already imported.
class PdfObjectImporter {
  PdfObjectImporter(this.context);

  final PdfImportContext context;

  /// Keys never copied from an imported object.
  static const _alwaysDropped = <String>{
    PdfNameTokens.length, // recomputed on serialization
  };

  /// Imports the indirect object [ref] and returns its reference in the
  /// destination.
  ///
  /// Returns `null` when the object does not exist in the source or when it is
  /// a page that was not imported.
  PdfIndirect? importRef(PdfRefToken ref) {
    final existing = context.imported[ref.obj];
    if (existing != null) return existing.ref();

    // Pages are never followed: they are resolved through the page map.
    if (context.isSourcePage(ref.obj)) {
      return context.pageMap[ref.obj]?.ref();
    }

    final parsed = context.source.getObject(ref.obj);
    if (parsed == null) {
      context.warn('objeto ${ref.obj} ${ref.gen} R não pôde ser lido');
      return null;
    }

    if (parsed.value is PdfDictToken) {
      final type = PdfParserObjects.asName(
          (parsed.value as PdfDictToken).values[PdfNameTokens.type]);
      if (type == PdfNameTokens.page || type == PdfNameTokens.pages) {
        // A page the tree scan did not reach.
        return context.pageMap[ref.obj]?.ref();
      }
      if (type == PdfNameTokens.xRef || type == PdfNameTokens.objStm) {
        // Structural objects of the source file make no sense in the
        // destination.
        return null;
      }
    }

    return _materialize(ref.obj, parsed).ref();
  }

  /// Creates the object in the destination and fills in its content.
  PdfObject _materialize(int srcObjId, ParsedIndirectObject parsed) {
    final rawStream = parsed.streamData;

    if (rawStream != null && parsed.value is PdfDictToken) {
      final srcDict = parsed.value as PdfDictToken;
      final reusable = _reusableStream(srcDict, rawStream);
      if (reusable != null) {
        context.imported[srcObjId] = reusable;
        return reusable;
      }

      final object = PdfObject<PdfDictStream>(
        context.destination,
        params: PdfDictStream(
          values: <String, PdfDataType>{},
          data: rawStream,
          // Streams with their own /Filter are copied verbatim; unfiltered
          // ones may be compressed by the destination.
          compress: !srcDict.values.containsKey(PdfNameTokens.filter),
        ),
      );
      context.imported[srcObjId] = object;
      _fillDict(object.params, srcDict);
      _rememberStream(srcDict, rawStream, object);
      return object;
    }

    final value = parsed.value;

    if (value is PdfDictToken) {
      final object = PdfObject<PdfDict>(
        context.destination,
        params: PdfDict(),
      );
      context.imported[srcObjId] = object;
      _fillDict(object.params, value);
      return object;
    }

    if (value is PdfArrayToken) {
      // Indirect arrays show up in `/Annots`, `/Kids` and destinations.
      final object = PdfObject<PdfArray>(
        context.destination,
        params: PdfArray(),
      );
      context.imported[srcObjId] = object;
      for (final item in value.values) {
        object.params.add(convert(item) ?? const PdfNull());
      }
      return object;
    }

    // Scalars cannot hold references, so there is no cycle to close.
    final object = PdfObject<PdfDataType>(
      context.destination,
      params: convert(value) ?? const PdfNull(),
    );
    context.imported[srcObjId] = object;
    return object;
  }

  void _fillDict(PdfDict target, PdfDictToken source,
      {Set<String> ignoreKeys = const <String>{}}) {
    source.values.forEach((key, value) {
      if (_alwaysDropped.contains(key) || ignoreKeys.contains(key)) return;
      final converted = convert(value);
      if (converted != null) {
        target[key] = converted;
      }
    });
  }

  /// Shared converter, carrying this session's reference policy: every
  /// indirect reference goes through [importRef].
  ///
  /// The conversion itself is the same one the parser uses to read a document —
  /// all that changes between the two cases is where the references point.
  late final PdfObjectConverter _converter = PdfObjectConverter(
    referencePolicy: importRef,
    // An item that vanished becomes a PDF `null` so the others are not
    // shifted: in a destination `[pageRef /XYZ x y z]`, the position of every
    // value carries meaning.
    arrayGapPolicy: PdfArrayGapPolicy.keepNull,
  );

  /// Converts a value read by the parser into the writing model, remapping
  /// indirect references.
  ///
  /// Returns `null` when the value must disappear (broken reference or page not
  /// imported); in dictionaries that means removing the key, which the
  /// specification treats as equivalent to `null`.
  PdfDataType? convert(dynamic value) => _converter.convert(value);

  /// Converts a direct (non-indirect) dictionary.
  PdfDict convertDict(PdfDictToken dict,
          {Set<String> ignoreKeys = const <String>{}}) =>
      _converter.convertDict(dict, ignoreKeys: ignoreKeys);

  /// Converts a direct array. Values that disappear become a PDF `null` so
  /// the positions of the others are not shifted.
  PdfArray convertArray(PdfArrayToken array) =>
      _converter.convertArray(array);

  /// Converts an array dropping the items that vanished, instead of replacing
  /// them with `null` — used where the position does not matter (`/Annots`,
  /// `/Kids`).
  PdfArray convertArrayCompact(PdfArrayToken array) =>
      _converter.convertArray(array, gapPolicy: PdfArrayGapPolicy.drop);

  // --------------------------------------------------------------------------
  // Stream deduplication
  // --------------------------------------------------------------------------

  String? _streamDigest(PdfDictToken dict, Uint8List data) {
    if (!context.options.deduplicateResources) return null;
    // Only worth it for content large enough to pay for the hash.
    if (data.length < 512) return null;
    // A dictionary with indirect references would only equal another one if
    // the objects they point at were equal too — which this cheap check has no
    // way to know.
    if (_hasIndirectValue(dict)) return null;

    final signature = StringBuffer();
    final keys = dict.values.keys.toList()..sort();
    for (final key in keys) {
      if (key == PdfNameTokens.length) continue;
      signature
        ..write(key)
        ..write('=')
        ..write(_signatureOf(dict.values[key]))
        ..write(';');
    }
    final hash = PdfCrypto.sha256(data);
    return '${data.length}:${base64.encode(hash)}:$signature';
  }

  PdfObject? _reusableStream(PdfDictToken dict, Uint8List data) {
    final digest = _streamDigest(dict, data);
    if (digest == null) return null;
    return context.streamsByDigest[digest];
  }

  void _rememberStream(PdfDictToken dict, Uint8List data, PdfObject object) {
    final digest = _streamDigest(dict, data);
    if (digest == null) return;
    context.streamsByDigest[digest] = object;
  }

  bool _hasIndirectValue(dynamic value, {int depth = 0}) {
    if (depth > 8) return true;
    if (value is PdfRefToken) return true;
    if (value is PdfArrayToken) {
      for (final item in value.values) {
        if (_hasIndirectValue(item, depth: depth + 1)) return true;
      }
      return false;
    }
    if (value is PdfDictToken) {
      for (final item in value.values.values) {
        if (_hasIndirectValue(item, depth: depth + 1)) return true;
      }
      return false;
    }
    return false;
  }

  String _signatureOf(dynamic value) {
    if (value is PdfNameToken) return '/${value.value}';
    if (value is PdfStringToken) return '(${base64.encode(value.bytes)})';
    if (value is PdfArrayToken) {
      return '[${value.values.map(_signatureOf).join(' ')}]';
    }
    if (value is PdfDictToken) {
      final keys = value.values.keys.toList()..sort();
      return '<<${keys.map((k) => '$k ${_signatureOf(value.values[k])}').join(' ')}>>';
    }
    return '$value';
  }
}
