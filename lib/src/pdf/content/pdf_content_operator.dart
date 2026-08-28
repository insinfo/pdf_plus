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

/// Value that can appear as an operand of a content stream.
///
/// The model is deliberately kept apart from the file parser model
/// (`PdfDictToken`, `PdfArrayToken`, …) because a content stream has rules of
/// its own: there are no indirect references, there are inline images, and the
/// original lexeme of every literal must be preserved so that reserialization
/// stays as close as possible to the input bytes.
abstract class PdfContentValue {
  /// Base constructor.
  const PdfContentValue();

  /// Textual representation used in debug messages.
  @override
  String toString() => runtimeType.toString();
}

/// Integer or real number.
///
/// [raw] holds the lexeme exactly as it came from the stream (for example
/// `0.0000` or `+3`), which allows reserializing without changing the numeric
/// notation.
class PdfContentNumber extends PdfContentValue {
  /// Creates a number with [value] and, optionally, the original lexeme
  /// [raw].
  const PdfContentNumber(this.value, [this.raw]);

  /// Creates an integer number.
  PdfContentNumber.fromInt(int value) : this(value.toDouble(), '$value');

  /// Numeric value, already converted.
  final double value;

  /// Original lexeme, when the number came from an existing stream.
  final String? raw;

  /// Value truncated to an integer.
  int get asInt => value.toInt();

  @override
  bool operator ==(Object other) =>
      other is PdfContentNumber && other.value == value;

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => raw ?? '$value';
}

/// PDF name (`/F1`, `/DeviceRGB`, …).
///
/// [value] includes the leading slash, as in the rest of the library.
class PdfContentName extends PdfContentValue {
  /// Creates a name; [value] must include the leading slash.
  const PdfContentName(this.value, [this.raw]);

  /// Name with the leading slash, with `#xx` already decoded.
  final String value;

  /// Original lexeme, including any `#xx` escapes.
  final String? raw;

  /// Name without the leading slash.
  String get name => value.startsWith('/') ? value.substring(1) : value;

  @override
  bool operator ==(Object other) =>
      other is PdfContentName && other.value == value;

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => value;
}

/// Literal string `(...)` or hexadecimal string `<...>`.
///
/// [bytes] are the already decoded bytes (escapes resolved). [raw] holds the
/// original slice, delimiters included, for faithful reserialization.
class PdfContentString extends PdfContentValue {
  /// Creates a content string.
  const PdfContentString(this.bytes, {this.hex = false, this.raw});

  /// Decoded bytes.
  final Uint8List bytes;

  /// `true` when the source was hexadecimal.
  final bool hex;

  /// Original slice, delimiters included.
  final Uint8List? raw;

  @override
  bool operator ==(Object other) {
    if (other is! PdfContentString) return false;
    if (other.bytes.length != bytes.length) return false;
    for (var i = 0; i < bytes.length; i++) {
      if (other.bytes[i] != bytes[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode {
    var hash = bytes.length;
    for (final byte in bytes) {
      hash = (hash * 31 + byte) & 0x3FFFFFFF;
    }
    return hash;
  }

  @override
  String toString() => '<${bytes.length} bytes>';
}

/// Array `[ … ]`.
class PdfContentArray extends PdfContentValue {
  /// Creates a content array.
  const PdfContentArray(this.values);

  /// Elements, in the original order.
  final List<PdfContentValue> values;

  @override
  bool operator ==(Object other) {
    if (other is! PdfContentArray) return false;
    if (other.values.length != values.length) return false;
    for (var i = 0; i < values.length; i++) {
      if (other.values[i] != values[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => values.length.hashCode;

  @override
  String toString() => '[${values.join(' ')}]';
}

/// Dictionary `<< … >>`, and also the dictionary of an inline image.
class PdfContentDict extends PdfContentValue {
  /// Creates a content dictionary.
  const PdfContentDict(this.values);

  /// Entries in insertion order; the keys include the leading slash.
  final Map<String, PdfContentValue> values;

  /// Reads an entry accepting either the full name or the inline image
  /// abbreviation (for example `/Width` and `/W`).
  PdfContentValue? lookup(String key, [String? alias]) =>
      values[key] ?? (alias == null ? null : values[alias]);

  @override
  bool operator ==(Object other) {
    if (other is! PdfContentDict) return false;
    if (other.values.length != values.length) return false;
    for (final entry in values.entries) {
      if (!other.values.containsKey(entry.key)) return false;
      if (other.values[entry.key] != entry.value) return false;
    }
    return true;
  }

  @override
  int get hashCode => values.length.hashCode;

  @override
  String toString() =>
      '<<${values.entries.map((e) => '${e.key} ${e.value}').join(' ')}>>';
}

/// `true` or `false`.
class PdfContentBool extends PdfContentValue {
  /// Creates a content boolean.
  const PdfContentBool(this.value);

  /// Logical value.
  final bool value;

  @override
  bool operator ==(Object other) =>
      other is PdfContentBool && other.value == value;

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => value ? 'true' : 'false';
}

/// `null`.
class PdfContentNull extends PdfContentValue {
  /// Creates the null value.
  const PdfContentNull();

  @override
  bool operator ==(Object other) => other is PdfContentNull;

  @override
  int get hashCode => 0x6E756C6C;

  @override
  String toString() => 'null';
}

/// A content stream operator with its operands.
///
/// The order of [operands] is the order they appeared in the stream, that is,
/// the same order the specification describes them in (`x y Td`,
/// `a b c d e f cm`).
class PdfContentOperator {
  /// Creates an operator.
  const PdfContentOperator(this.operator,
      [this.operands = const <PdfContentValue>[]]);

  /// Operator name (`Tj`, `cm`, `Do`, …).
  final String operator;

  /// Operands, in stream order.
  final List<PdfContentValue> operands;

  /// Numeric operand at position [index], when there is one.
  double? numberAt(int index) {
    if (index < 0 || index >= operands.length) return null;
    final value = operands[index];
    return value is PdfContentNumber ? value.value : null;
  }

  /// Name operand at position [index] (with the slash), when there is one.
  String? nameAt(int index) {
    if (index < 0 || index >= operands.length) return null;
    final value = operands[index];
    return value is PdfContentName ? value.value : null;
  }

  @override
  bool operator ==(Object other) {
    if (other is! PdfContentOperator) return false;
    if (other.runtimeType != runtimeType) return false;
    if (other.operator != operator) return false;
    if (other.operands.length != operands.length) return false;
    for (var i = 0; i < operands.length; i++) {
      if (other.operands[i] != operands[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hash(operator, operands.length);

  @override
  String toString() => operands.isEmpty
      ? operator
      : '${operands.map((e) => e.toString()).join(' ')} $operator';
}

/// Comment `% …`.
///
/// Comments have no effect on rendering. The parser only returns them when
/// `keepComments` is on; in that case the writer re-emits them, which allows a
/// truly lossless round-trip on commented streams.
class PdfContentComment extends PdfContentOperator {
  /// Creates a comment; [text] does not include the leading `%`.
  const PdfContentComment(this.text) : super('%');

  /// Comment text, without the `%`.
  final String text;

  @override
  bool operator ==(Object other) =>
      other is PdfContentComment && other.text == text;

  @override
  int get hashCode => text.hashCode;

  @override
  String toString() => '%$text';
}

/// A complete inline image: `BI … ID <bytes> EI`.
///
/// The bytes between `ID` and `EI` are binary and are kept exactly as they
/// were in the source stream, along with the separator that follows the `ID`.
/// Re-emission is not byte for byte: the writer always puts a line break
/// before `EI`, the same spacing normalization it applies everywhere else.
class PdfInlineImage extends PdfContentOperator {
  /// Creates an inline image.
  PdfInlineImage(
    this.dict,
    this.data, {
    this.separator = const <int>[0x20],
    this.lengthWasDeclared = false,
  }) : super('BI', <PdfContentValue>[dict]);

  /// Image dictionary, with the keys as they came (abbreviated or not).
  final PdfContentDict dict;

  /// Image bytes, exactly as in the stream.
  final Uint8List data;

  /// Whitespace bytes between `ID` and the data.
  final List<int> separator;

  /// `true` when the end of the data came from `/L` (or `/Length`) and not
  /// from the heuristic search for `EI`.
  final bool lengthWasDeclared;

  @override
  bool operator ==(Object other) {
    if (other is! PdfInlineImage) return false;
    if (other.dict != dict) return false;
    if (other.data.length != data.length) return false;
    for (var i = 0; i < data.length; i++) {
      if (other.data[i] != data[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hash(dict.values.length, data.length);

  @override
  String toString() => 'BI ${dict.values.length} keys, ${data.length} bytes EI';
}
