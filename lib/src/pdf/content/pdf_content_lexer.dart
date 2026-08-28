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

/// Token categories of a content stream.
enum PdfContentTokenKind {
  /// Integer or real number.
  number,

  /// Name (`/Name`).
  name,

  /// Literal string `( … )`.
  literalString,

  /// Hexadecimal string `< … >`.
  hexString,

  /// Array opening `[`.
  arrayStart,

  /// Array closing `]`.
  arrayEnd,

  /// Dictionary opening `<<`.
  dictStart,

  /// Dictionary closing `>>`.
  dictEnd,

  /// Word without a slash: operator, `true`, `false`, `null`, `{`, `}`.
  keyword,

  /// Comment `% …`.
  comment,

  /// End of data.
  endOfData,
}

/// A token with the exact position it occupied in the source bytes.
class PdfContentToken {
  /// Creates a token.
  const PdfContentToken(
    this.kind,
    this.start,
    this.end, {
    this.text = '',
    this.bytes,
  });

  /// Category.
  final PdfContentTokenKind kind;

  /// Index of the first byte of the token.
  final int start;

  /// Index just past the last byte of the token.
  final int end;

  /// Token text: the lexeme of a number, the already decoded name (with the
  /// slash), the keyword, or the body of a comment (without the `%`).
  final String text;

  /// Decoded bytes, for strings only.
  final Uint8List? bytes;

  @override
  String toString() => '$kind($text) @$start..$end';
}

/// Content stream tokenizer.
///
/// Recognizes numbers, names, literal and hexadecimal strings with escapes,
/// arrays, dictionaries, comments and keywords. It does not interpret
/// `BI … ID … EI`: the binary data of an inline image is the parser's
/// responsibility, and the parser uses [position] to consume the raw bytes
/// directly.
///
/// The lexer is tolerant: unexpected bytes never throw, they become
/// single-character keywords. A real content stream nearly always has some
/// garbage in it, and aborting the whole read because of that would be worse
/// than ignoring it.
class PdfContentLexer {
  /// Creates a lexer over [data], optionally limited to [start] .. [end].
  PdfContentLexer(this.data, {int start = 0, int? end})
      : position = start,
        end = end ?? data.length;

  /// Source bytes.
  final Uint8List data;

  /// Index just past the last byte considered.
  final int end;

  /// Current read position.
  int position;

  /// True for the six PDF whitespace bytes.
  static bool isWhitespace(int byte) =>
      byte == 0x20 ||
      byte == 0x0A ||
      byte == 0x0D ||
      byte == 0x09 ||
      byte == 0x0C ||
      byte == 0x00;

  /// True for the PDF delimiters.
  static bool isDelimiter(int byte) =>
      byte == 0x28 || // (
      byte == 0x29 || // )
      byte == 0x3C || // <
      byte == 0x3E || // >
      byte == 0x5B || // [
      byte == 0x5D || // ]
      byte == 0x7B || // {
      byte == 0x7D || // }
      byte == 0x2F || // /
      byte == 0x25; // %

  /// True when the byte ends a regular token.
  static bool isTokenBoundary(int byte) =>
      isWhitespace(byte) || isDelimiter(byte);

  /// Skips over whitespace.
  void skipWhitespace() {
    while (position < end && isWhitespace(data[position])) {
      position++;
    }
  }

  /// Reads the next token.
  ///
  /// At the end of the data it returns a [PdfContentTokenKind.endOfData] token;
  /// calling again keeps returning the same one.
  PdfContentToken next() {
    skipWhitespace();
    if (position >= end) {
      return PdfContentToken(PdfContentTokenKind.endOfData, position, position);
    }

    final start = position;
    final byte = data[position];

    switch (byte) {
      case 0x25: // %
        return _readComment(start);
      case 0x2F: // /
        return _readName(start);
      case 0x28: // (
        return _readLiteralString(start);
      case 0x3C: // <
        if (position + 1 < end && data[position + 1] == 0x3C) {
          position += 2;
          return PdfContentToken(
              PdfContentTokenKind.dictStart, start, position,
              text: '<<');
        }
        return _readHexString(start);
      case 0x3E: // >
        if (position + 1 < end && data[position + 1] == 0x3E) {
          position += 2;
          return PdfContentToken(PdfContentTokenKind.dictEnd, start, position,
              text: '>>');
        }
        // Stray `>`: garbage, consumed as a one-byte keyword.
        position++;
        return PdfContentToken(PdfContentTokenKind.keyword, start, position,
            text: '>');
      case 0x5B: // [
        position++;
        return PdfContentToken(PdfContentTokenKind.arrayStart, start, position,
            text: '[');
      case 0x5D: // ]
        position++;
        return PdfContentToken(PdfContentTokenKind.arrayEnd, start, position,
            text: ']');
      case 0x7B: // {
      case 0x7D: // }
        position++;
        return PdfContentToken(PdfContentTokenKind.keyword, start, position,
            text: String.fromCharCode(byte));
      case 0x29: // stray )
        position++;
        return PdfContentToken(PdfContentTokenKind.keyword, start, position,
            text: ')');
    }

    if (_startsNumber(byte)) {
      return _readNumber(start);
    }
    return _readKeyword(start);
  }

  static bool _startsNumber(int byte) =>
      (byte >= 0x30 && byte <= 0x39) || // 0-9
      byte == 0x2B || // +
      byte == 0x2D || // -
      byte == 0x2E; // .

  PdfContentToken _readComment(int start) {
    position++; // %
    final textStart = position;
    while (position < end && data[position] != 0x0A && data[position] != 0x0D) {
      position++;
    }
    final text = String.fromCharCodes(data, textStart, position);
    return PdfContentToken(PdfContentTokenKind.comment, start, position,
        text: text);
  }

  PdfContentToken _readName(int start) {
    position++; // /
    final buffer = StringBuffer('/');
    while (position < end && !isTokenBoundary(data[position])) {
      final byte = data[position];
      if (byte == 0x23 && position + 2 < end) {
        // #xx
        final high = _hexValue(data[position + 1]);
        final low = _hexValue(data[position + 2]);
        if (high >= 0 && low >= 0) {
          buffer.writeCharCode(high * 16 + low);
          position += 3;
          continue;
        }
      }
      buffer.writeCharCode(byte);
      position++;
    }
    return PdfContentToken(PdfContentTokenKind.name, start, position,
        text: buffer.toString());
  }

  PdfContentToken _readNumber(int start) {
    while (position < end) {
      final byte = data[position];
      final isDigit = byte >= 0x30 && byte <= 0x39;
      final isSign = byte == 0x2B || byte == 0x2D;
      final isDot = byte == 0x2E;
      final isExp = byte == 0x45 || byte == 0x65; // E e
      if (!isDigit && !isSign && !isDot && !isExp) break;
      position++;
    }
    if (position == start) position++; // safety
    final text = String.fromCharCodes(data, start, position);
    return PdfContentToken(PdfContentTokenKind.number, start, position,
        text: text);
  }

  PdfContentToken _readKeyword(int start) {
    while (position < end && !isTokenBoundary(data[position])) {
      position++;
    }
    if (position == start) position++; // unexpected isolated byte
    final text = String.fromCharCodes(data, start, position);
    return PdfContentToken(PdfContentTokenKind.keyword, start, position,
        text: text);
  }

  /// Reads `( … )` resolving escapes and nested parentheses.
  PdfContentToken _readLiteralString(int start) {
    position++; // (
    final out = <int>[];
    var depth = 1;

    while (position < end) {
      var byte = data[position++];

      if (byte == 0x5C) {
        // backslash
        if (position >= end) break;
        final escaped = data[position++];
        switch (escaped) {
          case 0x6E: // n
            out.add(0x0A);
            break;
          case 0x72: // r
            out.add(0x0D);
            break;
          case 0x74: // t
            out.add(0x09);
            break;
          case 0x62: // b
            out.add(0x08);
            break;
          case 0x66: // f
            out.add(0x0C);
            break;
          case 0x28: // (
          case 0x29: // )
          case 0x5C: // \
            out.add(escaped);
            break;
          case 0x0D: // line continuation
            if (position < end && data[position] == 0x0A) position++;
            break;
          case 0x0A: // line continuation
            break;
          default:
            if (escaped >= 0x30 && escaped <= 0x37) {
              var value = escaped - 0x30;
              for (var i = 0; i < 2; i++) {
                if (position >= end) break;
                final digit = data[position];
                if (digit < 0x30 || digit > 0x37) break;
                value = value * 8 + (digit - 0x30);
                position++;
              }
              out.add(value & 0xFF);
            } else {
              // Unknown `\X`: the specification says to ignore the slash.
              out.add(escaped);
            }
        }
        continue;
      }

      if (byte == 0x28) {
        depth++;
        out.add(byte);
        continue;
      }
      if (byte == 0x29) {
        depth--;
        if (depth == 0) break;
        out.add(byte);
        continue;
      }
      if (byte == 0x0D) {
        // An EOL inside a literal string counts as \n (ISO 32000-1,
        // 7.3.4.2).
        if (position < end && data[position] == 0x0A) position++;
        byte = 0x0A;
      }
      out.add(byte);
    }

    return PdfContentToken(PdfContentTokenKind.literalString, start, position,
        bytes: Uint8List.fromList(out),
        text: '');
  }

  /// Reads `< … >` ignoring whitespace; a trailing odd digit is padded with
  /// `0`.
  PdfContentToken _readHexString(int start) {
    position++; // <
    final out = <int>[];
    int? pending;

    while (position < end) {
      final byte = data[position++];
      if (byte == 0x3E) break; // >
      final value = _hexValue(byte);
      if (value < 0) continue; // whitespace and garbage
      if (pending == null) {
        pending = value;
      } else {
        out.add(pending * 16 + value);
        pending = null;
      }
    }
    if (pending != null) out.add(pending * 16);

    return PdfContentToken(PdfContentTokenKind.hexString, start, position,
        bytes: Uint8List.fromList(out), text: '');
  }

  static int _hexValue(int byte) {
    if (byte >= 0x30 && byte <= 0x39) return byte - 0x30;
    if (byte >= 0x41 && byte <= 0x46) return byte - 0x37;
    if (byte >= 0x61 && byte <= 0x66) return byte - 0x57;
    return -1;
  }

  /// Converts the lexeme of a number, tolerating the forms real producers
  /// emit: `4.`, `.5`, `--3`, `6.-2`, `1e3`.
  static double parseNumber(String text) {
    final direct = double.tryParse(text);
    if (direct != null && direct.isFinite) return direct;

    final buffer = StringBuffer();
    var negative = false;
    var seenDot = false;
    var seenDigit = false;
    var seenSign = false;
    for (var i = 0; i < text.length; i++) {
      final char = text[i];
      if (char == '-' || char == '+') {
        // A sign after a digit ends the number: `6.-2` reads as 6, the way
        // tolerant readers do it. Repeated signs before the first digit are
        // ignored, only the first one counts.
        if (seenDigit || seenDot) break;
        if (!seenSign) {
          seenSign = true;
          negative = char == '-';
        }
        continue;
      }
      if (char == '.') {
        if (seenDot) break;
        seenDot = true;
        buffer.write('.');
        continue;
      }
      if (char.codeUnitAt(0) >= 0x30 && char.codeUnitAt(0) <= 0x39) {
        seenDigit = true;
        buffer.write(char);
        continue;
      }
      break; // invalid exponent or garbage
    }
    if (!seenDigit) return 0;
    final value = double.tryParse(buffer.toString()) ?? 0;
    return negative ? -value : value;
  }
}
