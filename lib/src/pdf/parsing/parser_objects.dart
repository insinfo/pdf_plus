import 'dart:typed_data';

import '../format/array.dart';
import '../format/base.dart';
import '../format/bool.dart';
import '../format/dict.dart';
import '../format/indirect.dart';
import '../format/name.dart';
import '../format/null_value.dart';
import '../format/num.dart';
import '../format/string.dart';
import '../io/pdf_random_access_reader.dart';
import 'pdf_parser_constants.dart';
import 'pdf_parser_types.dart';
import 'parser_tokens.dart';

Uint8List? extractStream(Uint8List bytes, int dictEnd, int end, int? length) {
  int i = dictEnd;
  i = skipPdfWsAndComments(bytes, i, end);
  if (!matchToken(bytes, i, const <int>[0x73, 0x74, 0x72, 0x65, 0x61, 0x6D])) {
    return null;
  }
  i += 6;
  if (i < end && bytes[i] == 0x0D) i++;
  if (i < end && bytes[i] == 0x0A) i++;

  if (length != null) {
    final endPos = i + length;
    if (endPos <= end) {
      return bytes.sublist(i, endPos);
    }
  }

  final endPos = indexOfSequence(bytes, endStreamToken, i, end);
  if (endPos == -1) return null;
  return bytes.sublist(i, endPos);
}

ParsedIndirectObject? readIndirectObjectAt(
  Uint8List bytes,
  int offset,
  int end,
  ParsedIndirectObject? Function(int objId) getObject,
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
    final length = resolveLength(dict, getObject);
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

ParsedIndirectObject? readIndirectObjectAtNoStream(
  Uint8List bytes,
  int offset,
  int end,
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

  return ParsedIndirectObject(
    objId: obj.value,
    gen: gen.value,
    value: parsed.value,
    streamData: null,
  );
}

ParsedIndirectObject? readIndirectObjectAtFromReader(
  PdfRandomAccessReader reader,
  int offset,
  ParsedIndirectObject? Function(int objId) getObject,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return readIndirectObjectAt(reader.readAll(), offset, reader.length, getObject);
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
      final length = resolveLength(dict, getObject);
      final data =
          extractStream(window, parsed.dictEnd!, window.length, length);
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

  return null;
}

ParsedIndirectObject? readIndirectObjectAtFromReaderNoStream(
  PdfRandomAccessReader reader,
  int offset,
) {
  if (reader is PdfMemoryRandomAccessReader) {
    return readIndirectObjectAtNoStream(reader.readAll(), offset, reader.length);
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

ParsedIndirectObject? readCompressedObject(
  int objId,
  XrefEntry entry,
  ParsedIndirectObject? Function(int objId) getObject,
) {
  final objStmId = entry.offset;
  final objStm = getObject(objStmId);
  if (objStm == null || objStm.value is! PdfDictToken) return null;
  if (objStm.streamData == null) return null;

  final dict = objStm.value as PdfDictToken;
  final type = asName(dict.values[PdfKeys.type]);
  if (type != '/ObjStm') return null;

  final n = asInt(dict.values[PdfKeys.n]);
  final first = asInt(dict.values['/First']);
  if (n == null || first == null) return null;

  Uint8List data = objStm.streamData!;
  final header = readObjectStreamHeader(data, n);
  if (header == null) return null;
  final objOffset = header.index[objId];
  if (objOffset == null) return null;

  final parsed = parseObject(data, first + objOffset, data.length);
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

int? resolveLength(PdfDictToken dict, ParsedIndirectObject? Function(int objId) getObject) {
  final lenValue = dict.values[PdfKeys.length];
  if (lenValue is int) return lenValue;
  if (lenValue is double) return lenValue.toInt();
  if (lenValue is PdfRefToken) {
    final lenObj = getObject(lenValue.obj);
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
      PdfStringToken(str.bytes, PdfStringFormat.literal),
      str.nextIndex,
    );
  }
  if (b == 0x3C /* < */) {
    if (i + 1 < end && bytes[i + 1] == 0x3C) {
      final dict = readDict(bytes, i, end, depth: depth + 1);
      return ParseResult(dict.value, dict.nextIndex, dictEnd: dict.dictEnd);
    }
    final hex = readHexString(bytes, i, end);
    return ParseResult(
      PdfStringToken(hex.bytes, PdfStringFormat.binary),
      hex.nextIndex,
    );
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
    return (value: PdfRefToken(first.value as int, gen.value), nextIndex: i + 1);
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
