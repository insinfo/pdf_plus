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

import 'pdf_content_operator.dart';

/// Reserializes a list of operators back into content stream bytes.
///
/// ## What is preserved
///
/// Literals are re-emitted from the original lexeme when there is one (numbers
/// with the same notation, names with the same `#xx` escapes, strings with the
/// same escapes and delimiters), and the bytes of an inline image come out
/// identical to the input.
///
/// ## What changes
///
/// The spacing between tokens is normalized: one space between operands and
/// one line break after every operator. So the output is **not** byte-for-byte
/// equal to the input for an arbitrary stream — the guarantee that holds is
/// equivalence: reparsing the output produces the same list of operators.
/// Comments only survive if the parser was created with
/// `keepComments: true`.
class PdfContentWriter {
  /// Creates a writer.
  const PdfContentWriter({this.lineBreak = 0x0A});

  /// Byte used to separate operators (`\n` by default).
  final int lineBreak;

  /// Serializes [operators] into bytes.
  static Uint8List write(List<PdfContentOperator> operators) =>
      const PdfContentWriter().serialize(operators);

  /// Serializes [operators] into bytes.
  Uint8List serialize(List<PdfContentOperator> operators) {
    final out = BytesBuilder(copy: false);
    for (final operator in operators) {
      _writeOperator(out, operator);
    }
    return out.toBytes();
  }

  void _writeOperator(BytesBuilder out, PdfContentOperator operator) {
    if (operator is PdfContentComment) {
      out.addByte(0x25); // %
      out.add(_latin1(operator.text));
      out.addByte(lineBreak);
      return;
    }

    if (operator is PdfInlineImage) {
      _writeInlineImage(out, operator);
      return;
    }

    for (final operand in operator.operands) {
      _writeValue(out, operand);
      out.addByte(0x20);
    }
    out.add(_latin1(operator.operator));
    out.addByte(lineBreak);
  }

  void _writeInlineImage(BytesBuilder out, PdfInlineImage image) {
    out.add(_latin1('BI'));
    for (final entry in image.dict.values.entries) {
      out.addByte(0x20);
      out.add(_latin1(entry.key));
      out.addByte(0x20);
      _writeValue(out, entry.value);
    }
    out.addByte(0x20);
    out.add(_latin1('ID'));
    if (image.separator.isEmpty) {
      out.addByte(0x20);
    } else {
      out.add(image.separator);
    }
    out.add(image.data);
    out.addByte(lineBreak);
    out.add(_latin1('EI'));
    out.addByte(lineBreak);
  }

  void _writeValue(BytesBuilder out, PdfContentValue value) {
    if (value is PdfContentNumber) {
      out.add(_latin1(value.raw ?? formatNumber(value.value)));
      return;
    }
    if (value is PdfContentName) {
      out.add(_latin1(value.raw ?? escapeName(value.value)));
      return;
    }
    if (value is PdfContentString) {
      final raw = value.raw;
      if (raw != null) {
        out.add(raw);
      } else if (value.hex) {
        _writeHexString(out, value.bytes);
      } else {
        _writeLiteralString(out, value.bytes);
      }
      return;
    }
    if (value is PdfContentArray) {
      out.addByte(0x5B); // [
      for (var i = 0; i < value.values.length; i++) {
        if (i > 0) out.addByte(0x20);
        _writeValue(out, value.values[i]);
      }
      out.addByte(0x5D); // ]
      return;
    }
    if (value is PdfContentDict) {
      out.add(_latin1('<<'));
      var first = true;
      for (final entry in value.values.entries) {
        if (!first) out.addByte(0x20);
        first = false;
        out.add(_latin1(entry.key));
        out.addByte(0x20);
        _writeValue(out, entry.value);
      }
      out.add(_latin1('>>'));
      return;
    }
    if (value is PdfContentBool) {
      out.add(_latin1(value.value ? 'true' : 'false'));
      return;
    }
    out.add(_latin1('null'));
  }

  void _writeHexString(BytesBuilder out, Uint8List bytes) {
    const digits = '0123456789ABCDEF';
    out.addByte(0x3C); // <
    for (final byte in bytes) {
      out.addByte(digits.codeUnitAt((byte >> 4) & 0x0F));
      out.addByte(digits.codeUnitAt(byte & 0x0F));
    }
    out.addByte(0x3E); // >
  }

  void _writeLiteralString(BytesBuilder out, Uint8List bytes) {
    out.addByte(0x28); // (
    for (final byte in bytes) {
      switch (byte) {
        case 0x28: // (
        case 0x29: // )
        case 0x5C: // \
          out.addByte(0x5C);
          out.addByte(byte);
          break;
        case 0x0A:
          out.add(_latin1(r'\n'));
          break;
        case 0x0D:
          out.add(_latin1(r'\r'));
          break;
        case 0x09:
          out.add(_latin1(r'\t'));
          break;
        case 0x08:
          out.add(_latin1(r'\b'));
          break;
        case 0x0C:
          out.add(_latin1(r'\f'));
          break;
        default:
          if (byte < 0x20 || byte > 0x7E) {
            out.addByte(0x5C);
            out.add(_latin1(byte.toRadixString(8).padLeft(3, '0')));
          } else {
            out.addByte(byte);
          }
      }
    }
    out.addByte(0x29); // )
  }

  /// Formats a number the PDF way: no exponent, no unnecessary trailing
  /// zeros, and no `.0` for integers.
  static String formatNumber(double value) {
    if (!value.isFinite) return '0';
    if (value == value.roundToDouble() && value.abs() < 1e15) {
      return value.toInt().toString();
    }
    var text = value.toStringAsFixed(6);
    if (text.contains('.')) {
      text = text.replaceFirst(RegExp(r'0+$'), '');
      if (text.endsWith('.')) text = text.substring(0, text.length - 1);
    }
    return text.isEmpty ? '0' : text;
  }

  /// Applies the `#xx` escapes required in a PDF name.
  static String escapeName(String name) {
    final body = name.startsWith('/') ? name.substring(1) : name;
    final buffer = StringBuffer('/');
    for (final unit in body.codeUnits) {
      final regular = unit > 0x20 &&
          unit < 0x7F &&
          unit != 0x23 && // #
          unit != 0x28 &&
          unit != 0x29 &&
          unit != 0x3C &&
          unit != 0x3E &&
          unit != 0x5B &&
          unit != 0x5D &&
          unit != 0x7B &&
          unit != 0x7D &&
          unit != 0x2F &&
          unit != 0x25;
      if (regular) {
        buffer.writeCharCode(unit);
      } else {
        buffer.write('#');
        buffer.write((unit & 0xFF).toRadixString(16).padLeft(2, '0'));
      }
    }
    return buffer.toString();
  }

  static Uint8List _latin1(String text) {
    final out = Uint8List(text.length);
    for (var i = 0; i < text.length; i++) {
      out[i] = text.codeUnitAt(i) & 0xFF;
    }
    return out;
  }
}
