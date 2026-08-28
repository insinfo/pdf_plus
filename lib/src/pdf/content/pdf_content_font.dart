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

import 'pdf_content_lexer.dart';

/// A character code already resolved to text and width.
class PdfContentGlyph {
  /// Creates a decoded glyph.
  const PdfContentGlyph({
    required this.code,
    required this.text,
    required this.width,
    required this.byteLength,
    required this.mapped,
  });

  /// Code as it appears in the content stream string.
  final int code;

  /// Matching text; `�` when it could not be mapped.
  final String text;

  /// Width in text units (thousandths of an em).
  final double width;

  /// How many bytes the code took up.
  final int byteLength;

  /// `false` when the text is a guess (or a `�`) and did not come from
  /// a reliable mapping.
  final bool mapped;
}

/// Font information sufficient to turn `Tj`/`TJ` bytes into text and widths.
///
/// ## Honesty about the reach
///
/// - with `/ToUnicode` present, the text comes out right, subsetted Type0
///   included;
/// - without `/ToUnicode`, simple fonts fall back to WinAnsi/latin-1, which
///   gets ordinary Western documents right and any exotic encoding wrong;
/// - without `/ToUnicode`, a **subsetted Type0** font is undecipherable: the
///   codes are arbitrary glyph indices. In that case the characters come out
///   as `�` and [PdfContentGlyph.mapped] is `false`. There is no way
///   around this without reading the `cmap` table of the embedded font file,
///   which is out of scope here;
/// - `/Encoding` with `/Differences` is only honored for `uniXXXX` names,
///   `uXXXX` names with four or more hex digits, and the names of the standard
///   Latin set;
/// - Type3 is not handled: the font's own matrix is ignored and the widths
///   come out wrong.
class PdfContentFont {
  /// Creates the description of a font.
  PdfContentFont({
    this.resourceName,
    this.baseFont,
    this.subtype,
    this.composite = false,
    int codeByteLength = 1,
    Map<int, String>? toUnicode,
    Map<int, String>? differences,
    this.winAnsi = true,
    this.firstChar = 0,
    List<double>? widths,
    Map<int, double>? cidWidths,
    double? defaultWidth,
    this.missingWidth,
  })  : codeByteLength = codeByteLength.clamp(1, 2),
        toUnicode = toUnicode ?? const <int, String>{},
        differences = differences ?? const <int, String>{},
        widths = widths ?? const <double>[],
        cidWidths = cidWidths ?? const <int, double>{},
        defaultWidth = defaultWidth ?? (composite ? 1000 : 500);

  /// Resource name on the page (`/F1`), when known.
  final String? resourceName;

  /// `/BaseFont`.
  final String? baseFont;

  /// `/Subtype` (`/Type1`, `/TrueType`, `/Type0`, `/Type3`).
  final String? subtype;

  /// `true` for Type0 (multi-byte codes).
  final bool composite;

  /// How many bytes each code takes up (1 or 2).
  final int codeByteLength;

  /// `/ToUnicode` map, code → text.
  final Map<int, String> toUnicode;

  /// Map coming from `/Encoding /Differences`, code → text.
  final Map<int, String> differences;

  /// `true` when `/Encoding` is WinAnsi (or absent, which is the common
  /// case).
  final bool winAnsi;

  /// `/FirstChar` of a simple font.
  final int firstChar;

  /// `/Widths` of a simple font, in thousandths of an em.
  final List<double> widths;

  /// Per-CID widths of a composite font (`/W`).
  final Map<int, double> cidWidths;

  /// `/DW` of a composite font, or the guess used when there is no
  /// `/Widths`.
  final double defaultWidth;

  /// `/MissingWidth` of the descriptor, when declared.
  final double? missingWidth;

  /// `true` when the text mapping is reliable for any code.
  bool get hasReliableTextMapping => toUnicode.isNotEmpty || !composite;

  /// Generic font used when the resource could not be resolved.
  static PdfContentFont unknown([String? resourceName]) =>
      PdfContentFont(resourceName: resourceName);

  /// Decodes the bytes of a text string into glyphs.
  List<PdfContentGlyph> decode(Uint8List bytes) {
    final glyphs = <PdfContentGlyph>[];
    final step = codeByteLength;
    for (var i = 0; i < bytes.length; i += step) {
      var code = bytes[i];
      var length = 1;
      if (step == 2) {
        code = (bytes[i] << 8) | (i + 1 < bytes.length ? bytes[i + 1] : 0);
        length = i + 1 < bytes.length ? 2 : 1;
      }
      final mappedText = _textOf(code);
      glyphs.add(PdfContentGlyph(
        code: code,
        text: mappedText ?? '�',
        width: widthOf(code),
        byteLength: length,
        mapped: mappedText != null,
      ));
    }
    return glyphs;
  }

  /// Text matching a content string.
  String decodeText(Uint8List bytes) {
    final buffer = StringBuffer();
    for (final glyph in decode(bytes)) {
      buffer.write(glyph.text);
    }
    return buffer.toString();
  }

  /// Width of code [code] in thousandths of an em.
  double widthOf(int code) {
    if (composite) {
      return cidWidths[code] ?? defaultWidth;
    }
    final index = code - firstChar;
    if (index >= 0 && index < widths.length) {
      final value = widths[index];
      // A zero in `/Widths` is usually a hole in the subset, not a glyph
      // with no advance; in that case the fallback is the better guess.
      if (value != 0) return value;
    }
    if (widths.isEmpty) return missingWidth ?? defaultWidth;
    return missingWidth ?? 0;
  }

  String? _textOf(int code) {
    final unicode = toUnicode[code];
    if (unicode != null && unicode.isNotEmpty) return unicode;

    final difference = differences[code];
    if (difference != null && difference.isNotEmpty) return difference;

    if (composite) return null;

    if (winAnsi) {
      final special = _winAnsiHigh[code];
      if (special != null) return special;
      if (code == 0xAD) return '-'; // soft hyphen
    }
    if (code == 0) return '';
    return String.fromCharCode(code);
  }

  // ---------------------------------------------------------------------------
  // `/ToUnicode`
  // ---------------------------------------------------------------------------

  /// Reads an already decompressed `/ToUnicode` CMap.
  ///
  /// Handles `begincodespacerange`, `beginbfchar` and `beginbfrange` — the
  /// form with an array of destinations included. `begincidrange` is ignored:
  /// a CID CMap says nothing about Unicode.
  static PdfToUnicodeCMap parseToUnicode(Uint8List bytes) {
    final map = <int, String>{};
    var codeLength = 0;

    final lexer = PdfContentLexer(bytes);
    while (true) {
      final token = lexer.next();
      if (token.kind == PdfContentTokenKind.endOfData) break;
      if (token.kind != PdfContentTokenKind.keyword) continue;

      switch (token.text) {
        case 'begincodespacerange':
          final length = _readCodespace(lexer);
          if (length > codeLength) codeLength = length;
          break;
        case 'beginbfchar':
          _readBfChar(lexer, map);
          break;
        case 'beginbfrange':
          _readBfRange(lexer, map);
          break;
      }
    }

    return PdfToUnicodeCMap(map, codeLength);
  }

  static int _readCodespace(PdfContentLexer lexer) {
    var length = 0;
    var guard = 0;
    while (guard++ < 4096) {
      final token = lexer.next();
      if (token.kind == PdfContentTokenKind.endOfData) break;
      if (token.kind == PdfContentTokenKind.keyword) {
        if (token.text == 'endcodespacerange') break;
        continue;
      }
      if (token.kind == PdfContentTokenKind.hexString) {
        final size = token.bytes?.length ?? 0;
        if (size > length) length = size;
      }
    }
    return length;
  }

  static void _readBfChar(PdfContentLexer lexer, Map<int, String> map) {
    int? source;
    var guard = 0;
    while (guard++ < 200000) {
      final token = lexer.next();
      if (token.kind == PdfContentTokenKind.endOfData) break;
      if (token.kind == PdfContentTokenKind.keyword) {
        if (token.text == 'endbfchar') break;
        continue;
      }
      if (token.kind != PdfContentTokenKind.hexString) continue;

      if (source == null) {
        source = _codeOf(token.bytes);
      } else {
        map[source] = decodeUtf16Be(token.bytes ?? Uint8List(0));
        source = null;
      }
    }
  }

  static void _readBfRange(PdfContentLexer lexer, Map<int, String> map) {
    int? low;
    int? high;
    var guard = 0;
    while (guard++ < 200000) {
      final token = lexer.next();
      if (token.kind == PdfContentTokenKind.endOfData) break;
      if (token.kind == PdfContentTokenKind.keyword) {
        if (token.text == 'endbfrange') break;
        continue;
      }

      if (token.kind == PdfContentTokenKind.hexString) {
        if (low == null) {
          low = _codeOf(token.bytes);
          continue;
        }
        if (high == null) {
          high = _codeOf(token.bytes);
          continue;
        }
        _fillRange(map, low, high, token.bytes ?? Uint8List(0));
        low = null;
        high = null;
        continue;
      }

      if (token.kind == PdfContentTokenKind.arrayStart) {
        final destinations = <Uint8List>[];
        var inner = 0;
        while (inner++ < 200000) {
          final item = lexer.next();
          if (item.kind == PdfContentTokenKind.arrayEnd ||
              item.kind == PdfContentTokenKind.endOfData) {
            break;
          }
          if (item.kind == PdfContentTokenKind.hexString) {
            destinations.add(item.bytes ?? Uint8List(0));
          }
        }
        if (low != null) {
          for (var i = 0; i < destinations.length; i++) {
            map[low + i] = decodeUtf16Be(destinations[i]);
          }
        }
        low = null;
        high = null;
      }
    }
  }

  static void _fillRange(
      Map<int, String> map, int low, int high, Uint8List destination) {
    if (high < low) return;
    // A huge range is nearly always garbage; cap it so a corrupted CMap
    // cannot blow up memory.
    final last = high - low > 0xFFFF ? low + 0xFFFF : high;
    final base = decodeUtf16Be(destination);
    if (base.isEmpty) return;

    for (var code = low; code <= last; code++) {
      if (code == low) {
        map[code] = base;
        continue;
      }
      // The increment applies to the last code unit of the destination.
      final units = base.codeUnits.toList();
      units[units.length - 1] = (units.last + (code - low)) & 0xFFFF;
      map[code] = String.fromCharCodes(units);
    }
  }

  static int _codeOf(Uint8List? bytes) {
    if (bytes == null || bytes.isEmpty) return 0;
    var value = 0;
    for (final byte in bytes) {
      value = (value << 8) | byte;
    }
    return value;
  }

  /// Converts UTF-16BE bytes (the format of `/ToUnicode` destinations) into
  /// text, respecting surrogate pairs.
  static String decodeUtf16Be(Uint8List bytes) {
    if (bytes.isEmpty) return '';
    if (bytes.length == 1) return String.fromCharCode(bytes[0]);
    final units = <int>[];
    for (var i = 0; i + 1 < bytes.length; i += 2) {
      units.add((bytes[i] << 8) | bytes[i + 1]);
    }
    try {
      return String.fromCharCodes(units);
    } catch (_) {
      return '';
    }
  }

  // ---------------------------------------------------------------------------
  // `/Differences`
  // ---------------------------------------------------------------------------

  /// Translates a glyph name into text.
  ///
  /// Covers `uniXXXX`, `uXXXX` with four or more hex digits, and the names of
  /// the standard Latin set.
  /// Names outside that return `null`, and the caller falls back to the base
  /// encoding.
  static String? glyphNameToText(String name) {
    final clean = name.startsWith('/') ? name.substring(1) : name;
    if (clean.isEmpty) return null;

    final standard = _standardGlyphNames[clean];
    if (standard != null) return standard;

    if (clean.length >= 7 && clean.startsWith('uni')) {
      final value = int.tryParse(clean.substring(3, 7), radix: 16);
      if (value != null) return String.fromCharCode(value);
    }
    if (clean.length >= 5 && clean.startsWith('u')) {
      final value = int.tryParse(clean.substring(1), radix: 16);
      if (value != null && value >= 0 && value <= 0x10FFFF) {
        return String.fromCharCode(value);
      }
    }
    // `gNN` / `cidNN` / `indexNN` are glyph indices: undecipherable here.
    return null;
  }

  static const Map<int, String> _winAnsiHigh = <int, String>{
    0x80: '€',
    0x82: '‚',
    0x83: 'ƒ',
    0x84: '„',
    0x85: '…',
    0x86: '†',
    0x87: '‡',
    0x88: 'ˆ',
    0x89: '‰',
    0x8A: 'Š',
    0x8B: '‹',
    0x8C: 'Œ',
    0x8E: 'Ž',
    0x91: '‘',
    0x92: '’',
    0x93: '“',
    0x94: '”',
    0x95: '•',
    0x96: '–',
    0x97: '—',
    0x98: '˜',
    0x99: '™',
    0x9A: 'š',
    0x9B: '›',
    0x9C: 'œ',
    0x9E: 'ž',
    0x9F: 'Ÿ',
  };

  static const Map<String, String> _standardGlyphNames = <String, String>{
    'space': ' ',
    'exclam': '!',
    'quotedbl': '"',
    'numbersign': '#',
    'dollar': r'$',
    'percent': '%',
    'ampersand': '&',
    'quotesingle': "'",
    'quoteright': '’',
    'quoteleft': '‘',
    'parenleft': '(',
    'parenright': ')',
    'asterisk': '*',
    'plus': '+',
    'comma': ',',
    'hyphen': '-',
    'period': '.',
    'slash': '/',
    'zero': '0',
    'one': '1',
    'two': '2',
    'three': '3',
    'four': '4',
    'five': '5',
    'six': '6',
    'seven': '7',
    'eight': '8',
    'nine': '9',
    'colon': ':',
    'semicolon': ';',
    'less': '<',
    'equal': '=',
    'greater': '>',
    'question': '?',
    'at': '@',
    'bracketleft': '[',
    'backslash': r'\',
    'bracketright': ']',
    'asciicircum': '^',
    'underscore': '_',
    'grave': '`',
    'braceleft': '{',
    'bar': '|',
    'braceright': '}',
    'asciitilde': '~',
    'quotedblleft': '“',
    'quotedblright': '”',
    'quotedblbase': '„',
    'quotesinglbase': '‚',
    'endash': '–',
    'emdash': '—',
    'bullet': '•',
    'ellipsis': '…',
    'dagger': '†',
    'daggerdbl': '‡',
    'perthousand': '‰',
    'guilsinglleft': '‹',
    'guilsinglright': '›',
    'trademark': '™',
    'fi': 'ﬁ',
    'fl': 'ﬂ',
    'exclamdown': '¡',
    'cent': '¢',
    'sterling': '£',
    'currency': '¤',
    'yen': '¥',
    'brokenbar': '¦',
    'section': '§',
    'dieresis': '¨',
    'copyright': '©',
    'ordfeminine': 'ª',
    'guillemotleft': '«',
    'logicalnot': '¬',
    'registered': '®',
    'macron': '¯',
    'degree': '°',
    'plusminus': '±',
    'acute': '´',
    'mu': 'µ',
    'paragraph': '¶',
    'periodcentered': '·',
    'cedilla': '¸',
    'ordmasculine': 'º',
    'guillemotright': '»',
    'onequarter': '¼',
    'onehalf': '½',
    'threequarters': '¾',
    'questiondown': '¿',
    'Agrave': 'À',
    'Aacute': 'Á',
    'Acircumflex': 'Â',
    'Atilde': 'Ã',
    'Adieresis': 'Ä',
    'Aring': 'Å',
    'AE': 'Æ',
    'Ccedilla': 'Ç',
    'Egrave': 'È',
    'Eacute': 'É',
    'Ecircumflex': 'Ê',
    'Edieresis': 'Ë',
    'Igrave': 'Ì',
    'Iacute': 'Í',
    'Icircumflex': 'Î',
    'Idieresis': 'Ï',
    'Ntilde': 'Ñ',
    'Ograve': 'Ò',
    'Oacute': 'Ó',
    'Ocircumflex': 'Ô',
    'Otilde': 'Õ',
    'Odieresis': 'Ö',
    'Oslash': 'Ø',
    'Ugrave': 'Ù',
    'Uacute': 'Ú',
    'Ucircumflex': 'Û',
    'Udieresis': 'Ü',
    'Yacute': 'Ý',
    'germandbls': 'ß',
    'agrave': 'à',
    'aacute': 'á',
    'acircumflex': 'â',
    'atilde': 'ã',
    'adieresis': 'ä',
    'aring': 'å',
    'ae': 'æ',
    'ccedilla': 'ç',
    'egrave': 'è',
    'eacute': 'é',
    'ecircumflex': 'ê',
    'edieresis': 'ë',
    'igrave': 'ì',
    'iacute': 'í',
    'icircumflex': 'î',
    'idieresis': 'ï',
    'ntilde': 'ñ',
    'ograve': 'ò',
    'oacute': 'ó',
    'ocircumflex': 'ô',
    'otilde': 'õ',
    'odieresis': 'ö',
    'divide': '÷',
    'oslash': 'ø',
    'ugrave': 'ù',
    'uacute': 'ú',
    'ucircumflex': 'û',
    'udieresis': 'ü',
    'yacute': 'ý',
    'ydieresis': 'ÿ',
  };
}

/// Result of reading a `/ToUnicode` CMap.
class PdfToUnicodeCMap {
  /// Creates the result.
  const PdfToUnicodeCMap(this.map, this.codeByteLength);

  /// Code → text.
  final Map<int, String> map;

  /// Code size in bytes declared by `begincodespacerange`; zero when the CMap
  /// declared none.
  final int codeByteLength;

  /// `true` when there is no useful mapping at all.
  bool get isEmpty => map.isEmpty;
}
