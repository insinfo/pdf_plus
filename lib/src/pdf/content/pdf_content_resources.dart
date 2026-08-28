/*
 * Copyright (C) 2026, Isaque Neves <insinfo2008@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'dart:typed_data';

import 'package:archive/archive.dart';

import '../parsing/parser_objects.dart';
import '../parsing/parser_predictor.dart';
import '../parsing/parser_xref.dart';
import '../parsing/pdf_document_parser.dart';
import '../parsing/pdf_parser_types.dart';
import 'pdf_content_font.dart';

/// Access to the resources a content stream references by name.
///
/// Text extraction only needs fonts and form XObjects; the rest
/// (`/ExtGState`, `/Shading`, `/Pattern`) does not influence the text and for
/// that reason is not part of the interface.
abstract class PdfContentResources {
  /// Font named [name] (with the slash, `/F1`), or `null`.
  PdfContentFont? findFont(String name);

  /// Form XObject named [name] (with the slash), or `null`.
  PdfContentFormXObject? findFormXObject(String name);

  /// Empty resources, for when there is no dictionary available.
  static const PdfContentResources empty = _EmptyContentResources();
}

class _EmptyContentResources implements PdfContentResources {
  const _EmptyContentResources();

  @override
  PdfContentFont? findFont(String name) => null;

  @override
  PdfContentFormXObject? findFormXObject(String name) => null;
}

/// A form XObject ready to be walked by the extractor.
class PdfContentFormXObject {
  /// Creates the descriptor of a form XObject.
  const PdfContentFormXObject({
    required this.content,
    required this.resources,
    this.matrix,
    this.objectId,
  });

  /// Content stream, already decompressed.
  final Uint8List content;

  /// The form's own resources, falling back to the parent's resources.
  final PdfContentResources resources;

  /// `/Matrix`, when declared.
  final List<double>? matrix;

  /// Object number, used to detect recursion.
  final int? objectId;
}

/// Resources built from in-memory maps.
///
/// Useful in tests and for callers that already resolved the fonts some other
/// way.
class PdfMapContentResources implements PdfContentResources {
  /// Creates resources from maps.
  PdfMapContentResources({
    Map<String, PdfContentFont>? fonts,
    Map<String, PdfContentFormXObject>? forms,
  })  : fonts = fonts ?? const <String, PdfContentFont>{},
        forms = forms ?? const <String, PdfContentFormXObject>{};

  /// Fonts by resource name.
  final Map<String, PdfContentFont> fonts;

  /// Form XObjects by resource name.
  final Map<String, PdfContentFormXObject> forms;

  @override
  PdfContentFont? findFont(String name) => fonts[name];

  @override
  PdfContentFormXObject? findFormXObject(String name) => forms[name];
}

/// Resources read from a document opened by [PdfDocumentParser].
///
/// Resolves `/Font` and `/XObject` on demand and memoizes the result: a
/// document with many pages usually reuses the same fonts.
class PdfParserContentResources implements PdfContentResources {
  /// Creates the resources of a page or of a form XObject.
  PdfParserContentResources(this.parser, this.dict, {this.parent});

  /// Effective resources of page [pageIndex], with inheritance already
  /// applied.
  static PdfParserContentResources? forPage(
      PdfDocumentParser parser, int pageIndex) {
    final page = parser.pageDictAt(pageIndex);
    if (page == null) return null;
    return PdfParserContentResources(
        parser, parser.resolvePageResources(page));
  }

  /// Source document.
  final PdfDocumentParser parser;

  /// `/Resources` dictionary; may be null when the page declares none.
  final PdfDictToken? dict;

  /// Inherited resources, consulted when the name is not in [dict].
  final PdfContentResources? parent;

  final Map<String, PdfContentFont?> _fontCache = <String, PdfContentFont?>{};

  @override
  PdfContentFont? findFont(String name) {
    if (_fontCache.containsKey(name)) return _fontCache[name];

    PdfContentFont? font;
    final fonts = _subDictionary('/Font');
    final entry = fonts?.values[name];
    if (entry != null) {
      final fontDict = parser.resolve(entry);
      if (fontDict is PdfDictToken) {
        font = buildFont(parser, fontDict, resourceName: name);
      }
    }
    font ??= parent?.findFont(name);
    _fontCache[name] = font;
    return font;
  }

  @override
  PdfContentFormXObject? findFormXObject(String name) {
    final xObjects = _subDictionary('/XObject');
    final entry = xObjects?.values[name];
    if (entry == null) return parent?.findFormXObject(name);

    final ref = PdfParserObjects.asRef(entry);
    final object = ref == null ? null : parser.getObject(ref.obj);
    final dictValue = object?.value ?? parser.resolve(entry);
    if (dictValue is! PdfDictToken) return parent?.findFormXObject(name);
    if (PdfParserObjects.asName(dictValue.values['/Subtype']) != '/Form') {
      return null;
    }

    final raw = object?.streamData;
    if (raw == null) return null;
    final content = decodeStreamData(parser, dictValue, raw);
    if (content == null) return null;

    final own = parser.resolve(dictValue.values['/Resources']);
    return PdfContentFormXObject(
      content: content,
      resources: PdfParserContentResources(
          parser, own is PdfDictToken ? own : null,
          parent: this),
      matrix: _numberArray(parser, dictValue.values['/Matrix']),
      objectId: ref?.obj,
    );
  }

  PdfDictToken? _subDictionary(String key) {
    final resources = dict;
    if (resources == null) return null;
    final value = parser.resolve(resources.values[key]);
    return value is PdfDictToken ? value : null;
  }

  // ---------------------------------------------------------------------------
  // Font construction
  // ---------------------------------------------------------------------------

  /// Builds a [PdfContentFont] from the font dictionary [fontDict].
  static PdfContentFont buildFont(
    PdfDocumentParser parser,
    PdfDictToken fontDict, {
    String? resourceName,
  }) {
    final subtype = PdfParserObjects.asName(fontDict.values['/Subtype']);
    final baseFont = PdfParserObjects.asName(fontDict.values['/BaseFont']);
    final composite = subtype == '/Type0';

    final toUnicode = _readToUnicode(parser, fontDict);
    var codeByteLength = composite ? 2 : 1;
    if (composite) {
      final encoding = PdfParserObjects.asName(fontDict.values['/Encoding']);
      if (encoding != null &&
          (encoding == '/Identity-H' || encoding == '/Identity-V')) {
        codeByteLength = 2;
      } else if (toUnicode != null && toUnicode.codeByteLength > 0) {
        codeByteLength = toUnicode.codeByteLength;
      }
    } else if (toUnicode != null && toUnicode.codeByteLength == 2) {
      // A simple font with a two-byte CMap is anomalous, but it exists.
      codeByteLength = 2;
    }

    if (composite) {
      final descendant = _descendantFont(parser, fontDict);
      final descriptor = descendant == null
          ? null
          : parser.resolve(descendant.values['/FontDescriptor']);
      return PdfContentFont(
        resourceName: resourceName,
        baseFont: baseFont,
        subtype: subtype,
        composite: true,
        codeByteLength: codeByteLength,
        toUnicode: toUnicode?.map,
        defaultWidth: descendant == null
            ? 1000
            : _numberOf(parser.resolve(descendant.values['/DW'])) ?? 1000,
        cidWidths: descendant == null
            ? null
            : _readCidWidths(parser, descendant.values['/W']),
        missingWidth: descriptor is PdfDictToken
            ? _numberOf(parser.resolve(descriptor.values['/MissingWidth']))
            : null,
      );
    }

    final widths = <double>[];
    final widthsValue = parser.resolve(fontDict.values['/Widths']);
    if (widthsValue is PdfArrayToken) {
      for (final item in widthsValue.values) {
        widths.add(_numberOf(parser.resolve(item)) ?? 0);
      }
    }

    final descriptor = parser.resolve(fontDict.values['/FontDescriptor']);
    final encodingInfo = _readEncoding(parser, fontDict.values['/Encoding']);

    return PdfContentFont(
      resourceName: resourceName,
      baseFont: baseFont,
      subtype: subtype,
      codeByteLength: codeByteLength,
      toUnicode: toUnicode?.map,
      differences: encodingInfo.differences,
      winAnsi: encodingInfo.winAnsi,
      firstChar: PdfParserObjects.asInt(
              parser.resolve(fontDict.values['/FirstChar'])) ??
          0,
      widths: widths,
      missingWidth: descriptor is PdfDictToken
          ? _numberOf(parser.resolve(descriptor.values['/MissingWidth']))
          : null,
    );
  }

  static PdfDictToken? _descendantFont(
      PdfDocumentParser parser, PdfDictToken fontDict) {
    final descendants = parser.resolve(fontDict.values['/DescendantFonts']);
    if (descendants is PdfArrayToken && descendants.values.isNotEmpty) {
      final first = parser.resolve(descendants.values.first);
      if (first is PdfDictToken) return first;
    }
    if (descendants is PdfDictToken) return descendants;
    return null;
  }

  static PdfToUnicodeCMap? _readToUnicode(
      PdfDocumentParser parser, PdfDictToken fontDict) {
    final ref = PdfParserObjects.asRef(fontDict.values['/ToUnicode']);
    if (ref == null) return null;
    final object = parser.getObject(ref.obj);
    final raw = object?.streamData;
    if (object == null || raw == null) return null;
    final dict = object.value;
    if (dict is! PdfDictToken) return null;
    final data = decodeStreamData(parser, dict, raw);
    if (data == null || data.isEmpty) return null;
    try {
      return PdfContentFont.parseToUnicode(data);
    } catch (_) {
      return null;
    }
  }

  /// Reads `/W` of a CID font: `[ c [w1 … wn] cFirst cLast w … ]`.
  static Map<int, double> _readCidWidths(
      PdfDocumentParser parser, dynamic value) {
    final result = <int, double>{};
    final array = parser.resolve(value);
    if (array is! PdfArrayToken) return result;

    var i = 0;
    final items = array.values;
    while (i < items.length) {
      final first = _numberOf(parser.resolve(items[i]));
      if (first == null) {
        i++;
        continue;
      }
      if (i + 1 >= items.length) break;

      final second = parser.resolve(items[i + 1]);
      if (second is PdfArrayToken) {
        final start = first.toInt();
        for (var k = 0; k < second.values.length; k++) {
          final width = _numberOf(parser.resolve(second.values[k]));
          if (width != null) result[start + k] = width;
        }
        i += 2;
        continue;
      }

      if (i + 2 >= items.length) break;
      final last = _numberOf(second);
      final width = _numberOf(parser.resolve(items[i + 2]));
      if (last != null && width != null) {
        final start = first.toInt();
        final end = last.toInt();
        // Absurd ranges come from corrupted files; ignore them.
        if (end >= start && end - start <= 0xFFFF) {
          for (var code = start; code <= end; code++) {
            result[code] = width;
          }
        }
      }
      i += 3;
    }
    return result;
  }

  static _EncodingInfo _readEncoding(PdfDocumentParser parser, dynamic value) {
    final resolved = parser.resolve(value);
    if (resolved is PdfNameToken) {
      return _EncodingInfo(
        winAnsi: resolved.value != '/MacRomanEncoding',
        differences: const <int, String>{},
      );
    }
    if (resolved is! PdfDictToken) {
      return const _EncodingInfo(
          winAnsi: true, differences: <int, String>{});
    }

    final base = PdfParserObjects.asName(resolved.values['/BaseEncoding']);
    final differences = <int, String>{};
    final list = parser.resolve(resolved.values['/Differences']);
    if (list is PdfArrayToken) {
      var code = 0;
      for (final item in list.values) {
        final resolvedItem = parser.resolve(item);
        final number = _numberOf(resolvedItem);
        if (number != null) {
          code = number.toInt();
          continue;
        }
        if (resolvedItem is PdfNameToken) {
          final text = PdfContentFont.glyphNameToText(resolvedItem.value);
          if (text != null) differences[code] = text;
          code++;
        }
      }
    }
    return _EncodingInfo(
      winAnsi: base != '/MacRomanEncoding',
      differences: differences,
    );
  }

  static double? _numberOf(dynamic value) {
    if (value is num) return value.toDouble();
    return null;
  }

  /// Numeric array of any length (`/Matrix` has six elements, and
  /// `PdfParserObjects.asNumArray` only returns four).
  static List<double>? _numberArray(PdfDocumentParser parser, dynamic value) {
    final array = parser.resolve(value);
    if (array is! PdfArrayToken) return null;
    final result = <double>[];
    for (final item in array.values) {
      final number = _numberOf(parser.resolve(item));
      if (number == null) return null;
      result.add(number);
    }
    return result;
  }
}

class _EncodingInfo {
  const _EncodingInfo({required this.winAnsi, required this.differences});

  final bool winAnsi;
  final Map<int, String> differences;
}

/// Content stream of a page, with every part of `/Contents` concatenated and
/// decompressed.
///
/// Returns `null` when the page does not exist; returns empty bytes when the
/// page exists but has no content.
Uint8List? decodePageContent(PdfDocumentParser parser, int pageIndex) {
  final page = parser.pageDictAt(pageIndex);
  if (page == null) return null;

  final parts = BytesBuilder(copy: false);
  void addStream(dynamic value) {
    final ref = PdfParserObjects.asRef(value);
    if (ref == null) return;
    final object = parser.getObject(ref.obj);
    final raw = object?.streamData;
    if (object == null || raw == null) return;
    final dict = object.value;
    if (dict is! PdfDictToken) return;
    final data = decodeStreamData(parser, dict, raw);
    if (data == null) return;
    if (parts.length > 0) parts.addByte(0x0A);
    parts.add(data);
  }

  final contents = parser.resolve(page.values['/Contents']);
  if (contents is PdfArrayToken) {
    for (final item in contents.values) {
      addStream(item);
    }
  } else {
    addStream(page.values['/Contents']);
  }

  return parts.toBytes();
}

/// Applies the filters of [dict] over [raw].
///
/// Handles `/FlateDecode` (with and without a zlib header) and
/// `/ASCIIHexDecode`, including the `/DecodeParms` predictor that follows a
/// Flate stream. Returns `null` when the filter is not supported — LZW, DCT,
/// JPX and RunLength do not show up in content streams or in `/ToUnicode` in
/// practice.
Uint8List? decodeStreamData(
    PdfDocumentParser parser, PdfDictToken dict, Uint8List raw) {
  var data = raw;
  final predictor =
      PdfParserXref.readPredictorParams(parser.resolve(dict.values['/DecodeParms']));

  for (final filter in _filterNames(parser, dict.values['/Filter'])) {
    switch (filter) {
      case '/FlateDecode':
      case '/Fl':
        final inflated = _inflate(data);
        if (inflated == null) return null;
        // A predictor left in place would decode to garbage, silently.
        data = PdfParserPredictor.apply(inflated, predictor);
        break;
      case '/ASCIIHexDecode':
      case '/AHx':
        data = _asciiHexDecode(data);
        break;
      default:
        return null;
    }
  }
  return data;
}

Uint8List? _inflate(Uint8List data) {
  try {
    return Uint8List.fromList(ZLibDecoder().decodeBytes(data));
  } catch (_) {
    // Some producers write raw deflate, without the zlib header.
    try {
      return Uint8List.fromList(Inflate(data).getBytes());
    } catch (_) {
      return null;
    }
  }
}

Uint8List _asciiHexDecode(Uint8List data) {
  final out = <int>[];
  int? pending;
  for (final byte in data) {
    if (byte == 0x3E) break; // >
    int value;
    if (byte >= 0x30 && byte <= 0x39) {
      value = byte - 0x30;
    } else if (byte >= 0x41 && byte <= 0x46) {
      value = byte - 0x37;
    } else if (byte >= 0x61 && byte <= 0x66) {
      value = byte - 0x57;
    } else {
      continue;
    }
    if (pending == null) {
      pending = value;
    } else {
      out.add(pending * 16 + value);
      pending = null;
    }
  }
  if (pending != null) out.add(pending * 16);
  return Uint8List.fromList(out);
}

List<String> _filterNames(PdfDocumentParser parser, dynamic value) {
  final resolved = parser.resolve(value);
  if (resolved is PdfNameToken) return <String>[resolved.value];
  if (resolved is PdfArrayToken) {
    return resolved.values
        .map(parser.resolve)
        .whereType<PdfNameToken>()
        .map((e) => e.value)
        .toList();
  }
  return const <String>[];
}
