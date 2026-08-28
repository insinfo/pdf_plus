import 'dart:typed_data';

import 'package:archive/archive.dart';

import '../editing/object_graph/pdf_object_converter.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/string.dart';
import '../io/pdf_random_access_reader.dart';

import 'pdf_parser_types.dart';
import 'parser_tokens.dart';
import 'package:pdf_plus/src/pdf/pdf_names.dart';

class PdfParserObjects {
  static const int _maxStreamDecodeSize = 256 * 1024 * 1024;

  /// Index of the first stream data byte, right after the `stream` keyword
  /// and the EOL that follows it. `null` when there is no stream after the
  /// dictionary that ends at [dictEnd].
  static int? streamDataStart(Uint8List bytes, int dictEnd, int end) {
    int i = PdfParserTokens.skipPdfWsAndComments(bytes, dictEnd, end);
    if (!PdfParserTokens.matchToken(
        bytes, i, const <int>[0x73, 0x74, 0x72, 0x65, 0x61, 0x6D])) {
      return null;
    }
    i += 6;
    if (i < end && bytes[i] == 0x0D) i++;
    if (i < end && bytes[i] == 0x0A) i++;
    return i;
  }

  static Uint8List? extractStream(
      Uint8List bytes, int dictEnd, int end, int? length) {
    final i = streamDataStart(bytes, dictEnd, end);
    if (i == null) return null;

    if (length != null && length >= 0) {
      final endPos = i + length;
      if (endPos <= end) {
        return bytes.sublist(i, endPos);
      }
    }

    final endPos = PdfParserTokens.indexOfSequence(
        bytes, PdfParserTokens.endStreamToken, i, end);
    if (endPos == -1) return null;
    return bytes.sublist(i, _trimEolBefore(bytes, i, endPos));
  }

  /// Extracts the raw data of a stream by reading straight from the [reader],
  /// without depending on the whole stream fitting in the window already read.
  ///
  /// [objectOffset] is the absolute position of the object in the file and
  /// [window] the window read from it; [dictEnd] is relative to the window.
  static Uint8List? extractStreamFromReader(
    PdfRandomAccessReader reader,
    int objectOffset,
    Uint8List window,
    int dictEnd,
    int? length,
  ) {
    final dataStart = streamDataStart(window, dictEnd, window.length);
    if (dataStart == null) return null;

    final absStart = objectOffset + dataStart;
    final fileLength = reader.length;
    if (absStart >= fileLength) return null;

    // Fast path: the whole stream is already in the window.
    if (length != null && length >= 0 && dataStart + length <= window.length) {
      return window.sublist(dataStart, dataStart + length);
    }

    Uint8List? byLength;
    if (length != null && length >= 0 && absStart + length <= fileLength) {
      final data = reader.readRange(absStart, length);
      if (data.length == length &&
          _endstreamFollows(reader, absStart + length, fileLength)) {
        return data;
      }
      byLength = data.length == length ? data : null;
    }

    // /Length missing or inconsistent: scan for `endstream`.
    return _scanStreamUntilEndstream(reader, absStart, fileLength) ?? byLength;
  }

  /// Checks whether, ignoring whitespace, the word `endstream` starts at
  /// [position].
  static bool _endstreamFollows(
      PdfRandomAccessReader reader, int position, int fileLength) {
    if (position >= fileLength) return false;
    final probeLen =
        (position + 32 > fileLength) ? (fileLength - position) : 32;
    final probe = reader.readRange(position, probeLen);
    final i = PdfParserTokens.skipPdfWsAndComments(probe, 0, probe.length);
    return PdfParserTokens.matchToken(
        probe, i, PdfParserTokens.endStreamToken);
  }

  /// Reads from the file, in chunks, until `endstream` is found.
  static Uint8List? _scanStreamUntilEndstream(
    PdfRandomAccessReader reader,
    int absStart,
    int fileLength,
  ) {
    const chunkSize = 256 * 1024;
    final tokenLength = PdfParserTokens.endStreamToken.length;
    final builder = BytesBuilder(copy: false);
    var position = absStart;
    // Bytes already read and not yet confirmed, so that an `endstream` split
    // across two chunks still matches.
    var pending = Uint8List(0);

    while (position < fileLength) {
      final readLen = (position + chunkSize > fileLength)
          ? (fileLength - position)
          : chunkSize;
      final chunk = reader.readRange(position, readLen);
      if (chunk.isEmpty) break;
      position += chunk.length;

      final scan = Uint8List(pending.length + chunk.length)
        ..setRange(0, pending.length, pending)
        ..setRange(pending.length, pending.length + chunk.length, chunk);

      final found = PdfParserTokens.indexOfSequence(
          scan, PdfParserTokens.endStreamToken, 0, scan.length);
      if (found != -1) {
        builder.add(scan.sublist(0, found));
        final data = builder.toBytes();
        return data.sublist(0, _trimEolBefore(data, 0, data.length));
      }

      // Just enough so the token cannot slip past the chunk boundary.
      final keep =
          scan.length < tokenLength - 1 ? scan.length : tokenLength - 1;
      builder.add(scan.sublist(0, scan.length - keep));
      pending = scan.sublist(scan.length - keep);
    }

    return null;
  }

  /// Backs over the EOL preceding `endstream`, which is not part of the data.
  static int _trimEolBefore(Uint8List bytes, int start, int endPos) {
    var end = endPos;
    if (end > start && bytes[end - 1] == 0x0A) end--;
    if (end > start && bytes[end - 1] == 0x0D) end--;
    return end;
  }

  static ParsedIndirectObject? readIndirectObjectAt(
    Uint8List bytes,
    int offset,
    int end,
    ParsedIndirectObject? Function(int objId) getObject,
  ) {
    int i = PdfParserTokens.skipPdfWsAndComments(bytes, offset, end);
    if (i >= end || !PdfParserTokens.isDigit(bytes[i])) return null;
    final obj = PdfParserTokens.readInt(bytes, i, end);
    i = PdfParserTokens.skipPdfWsAndComments(bytes, obj.nextIndex, end);
    if (i >= end || !PdfParserTokens.isDigit(bytes[i])) return null;
    final gen = PdfParserTokens.readInt(bytes, i, end);
    i = PdfParserTokens.skipPdfWsAndComments(bytes, gen.nextIndex, end);
    if (!PdfParserTokens.matchToken(bytes, i, const <int>[0x6F, 0x62, 0x6A]))
      return null;
    i += 3;
    i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);

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

  static ParsedIndirectObject? readIndirectObjectAtNoStream(
    Uint8List bytes,
    int offset,
    int end,
  ) {
    int i = PdfParserTokens.skipPdfWsAndComments(bytes, offset, end);
    if (i >= end || !PdfParserTokens.isDigit(bytes[i])) return null;
    final obj = PdfParserTokens.readInt(bytes, i, end);
    i = PdfParserTokens.skipPdfWsAndComments(bytes, obj.nextIndex, end);
    if (i >= end || !PdfParserTokens.isDigit(bytes[i])) return null;
    final gen = PdfParserTokens.readInt(bytes, i, end);
    i = PdfParserTokens.skipPdfWsAndComments(bytes, gen.nextIndex, end);
    if (!PdfParserTokens.matchToken(bytes, i, const <int>[0x6F, 0x62, 0x6A]))
      return null;
    i += 3;
    i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);

    final parsed = parseObject(bytes, i, end);
    if (parsed == null) return null;

    return ParsedIndirectObject(
      objId: obj.value,
      gen: gen.value,
      value: parsed.value,
      streamData: null,
    );
  }

  static ParsedIndirectObject? readIndirectObjectAtFromReader(
    PdfRandomAccessReader reader,
    int offset,
    ParsedIndirectObject? Function(int objId) getObject,
  ) {
    if (reader is PdfMemoryRandomAccessReader) {
      return readIndirectObjectAt(
          reader.readAll(), offset, reader.length, getObject);
    }

    final len = reader.length;
    const windowSizes = <int>[
      8 * 1024,
      32 * 1024,
      128 * 1024,
      512 * 1024,
      2 * 1024 * 1024,
    ];
    ParsedIndirectObject? truncated;

    for (final size in windowSizes) {
      if (offset < 0 || offset >= len) return null;
      final windowSize = (offset + size > len) ? (len - offset) : size;
      final window = reader.readRange(offset, windowSize);
      final isLastWindow = windowSize >= len - offset;

      int i = PdfParserTokens.skipPdfWsAndComments(window, 0, window.length);
      if (i >= window.length || !PdfParserTokens.isDigit(window[i])) {
        if (isLastWindow) return null;
        continue;
      }
      final obj = PdfParserTokens.readInt(window, i, window.length);
      i = PdfParserTokens.skipPdfWsAndComments(
          window, obj.nextIndex, window.length);
      if (i >= window.length || !PdfParserTokens.isDigit(window[i])) {
        if (isLastWindow) return null;
        continue;
      }
      final gen = PdfParserTokens.readInt(window, i, window.length);
      i = PdfParserTokens.skipPdfWsAndComments(
          window, gen.nextIndex, window.length);
      if (!PdfParserTokens.matchToken(
          window, i, const <int>[0x6F, 0x62, 0x6A])) {
        if (isLastWindow) return null;
        continue;
      }
      i += 3;
      i = PdfParserTokens.skipPdfWsAndComments(window, i, window.length);

      ParseResult? parsed;
      try {
        parsed = parseObject(window, i, window.length);
      } catch (_) {
        // A value cut off by the window edge — the hexadecimal string of a
        // signature `/Contents`, for example — makes the token reader fail.
        // It only means the window is too small.
        parsed = null;
      }

      if (parsed == null || _isTruncatedDict(parsed, window.length)) {
        if (parsed != null) truncated = _build(obj, gen, parsed, null);
        if (isLastWindow) return truncated;
        continue;
      }

      Uint8List? streamData;
      if (parsed.value is PdfDictToken && parsed.dictEnd != null) {
        final dict = parsed.value as PdfDictToken;
        final length = resolveLength(dict, getObject);
        // Read the stream straight from the file: it can be much larger
        // than the window.
        streamData = extractStreamFromReader(
            reader, offset, window, parsed.dictEnd!, length);
      }

      return _build(obj, gen, parsed, streamData);
    }

    // The dictionary did not fit in the largest window. This happens with
    // signatures: the `/Contents` of a PKCS#7 can be megabytes of hexadecimal
    // string — and it is part of the dictionary, not of a stream. Here the
    // window is measured by the object's own `endobj`.
    final wide = _readUntilEndobj(reader, offset);
    if (wide != null && wide.length > windowSizes.last) {
      final result = _parseWindow(reader, offset, wide, getObject);
      if (result != null) return result;
    }

    return truncated;
  }

  /// Reads from the file starting at [offset] up to the `endobj` that closes
  /// the object.
  static Uint8List? _readUntilEndobj(PdfRandomAccessReader reader, int offset) {
    const chunkSize = 1024 * 1024;
    const maxObjectSize = 256 * 1024 * 1024;
    const token = <int>[0x65, 0x6E, 0x64, 0x6F, 0x62, 0x6A]; // endobj

    final fileLength = reader.length;
    if (offset < 0 || offset >= fileLength) return null;

    final limit = offset + maxObjectSize < fileLength
        ? offset + maxObjectSize
        : fileLength;

    var position = offset;
    var carry = 0; // bytes already read that still count for the match
    final builder = BytesBuilder(copy: false);

    while (position < limit) {
      final readLen =
          (position + chunkSize > limit) ? (limit - position) : chunkSize;
      final chunk = reader.readRange(position, readLen);
      if (chunk.isEmpty) break;
      builder.add(chunk);
      position += chunk.length;

      final data = builder.toBytes();
      final from = carry - token.length >= 0 ? carry - token.length : 0;
      final found =
          PdfParserTokens.indexOfSequence(data, token, from, data.length);
      if (found != -1) {
        return Uint8List.sublistView(data, 0, found + token.length);
      }
      carry = data.length;
      builder
        ..clear()
        ..add(data);
    }

    return null;
  }

  /// Parses an indirect object already materialized in [window].
  static ParsedIndirectObject? _parseWindow(
    PdfRandomAccessReader reader,
    int offset,
    Uint8List window,
    ParsedIndirectObject? Function(int objId) getObject,
  ) {
    int i = PdfParserTokens.skipPdfWsAndComments(window, 0, window.length);
    if (i >= window.length || !PdfParserTokens.isDigit(window[i])) return null;
    final obj = PdfParserTokens.readInt(window, i, window.length);
    i = PdfParserTokens.skipPdfWsAndComments(
        window, obj.nextIndex, window.length);
    if (i >= window.length || !PdfParserTokens.isDigit(window[i])) return null;
    final gen = PdfParserTokens.readInt(window, i, window.length);
    i = PdfParserTokens.skipPdfWsAndComments(
        window, gen.nextIndex, window.length);
    if (!PdfParserTokens.matchToken(window, i, const <int>[0x6F, 0x62, 0x6A])) {
      return null;
    }
    i += 3;
    i = PdfParserTokens.skipPdfWsAndComments(window, i, window.length);

    ParseResult? parsed;
    try {
      parsed = parseObject(window, i, window.length);
    } catch (_) {
      return null;
    }
    if (parsed == null) return null;

    Uint8List? streamData;
    if (parsed.value is PdfDictToken && parsed.dictEnd != null) {
      final dict = parsed.value as PdfDictToken;
      final length = resolveLength(dict, getObject);
      streamData = extractStreamFromReader(
          reader, offset, window, parsed.dictEnd!, length);
    }

    return _build(obj, gen, parsed, streamData);
  }

  /// A dictionary that ended together with the window was almost certainly
  /// cut off: the keys that came after it are missing.
  static bool _isTruncatedDict(ParseResult parsed, int windowLength) {
    if (parsed.value is! PdfDictToken) return false;
    if (parsed.dictEnd != null) return false;
    return parsed.nextIndex >= windowLength;
  }

  static ParsedIndirectObject _build(
    ({dynamic value, int nextIndex}) obj,
    ({dynamic value, int nextIndex}) gen,
    ParseResult parsed,
    Uint8List? streamData,
  ) {
    return ParsedIndirectObject(
      objId: obj.value,
      gen: gen.value,
      value: parsed.value,
      streamData: streamData,
    );
  }


  static ParsedIndirectObject? readIndirectObjectAtFromReaderNoStream(
    PdfRandomAccessReader reader,
    int offset,
  ) {
    if (reader is PdfMemoryRandomAccessReader) {
      return readIndirectObjectAtNoStream(
          reader.readAll(), offset, reader.length);
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

      int i = PdfParserTokens.skipPdfWsAndComments(window, 0, window.length);
      if (i >= window.length || !PdfParserTokens.isDigit(window[i])) continue;
      final obj = PdfParserTokens.readInt(window, i, window.length);
      i = PdfParserTokens.skipPdfWsAndComments(
          window, obj.nextIndex, window.length);
      if (i >= window.length || !PdfParserTokens.isDigit(window[i])) continue;
      final gen = PdfParserTokens.readInt(window, i, window.length);
      i = PdfParserTokens.skipPdfWsAndComments(
          window, gen.nextIndex, window.length);
      if (!PdfParserTokens.matchToken(window, i, const <int>[0x6F, 0x62, 0x6A]))
        continue;
      i += 3;
      i = PdfParserTokens.skipPdfWsAndComments(window, i, window.length);

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

  static ParsedIndirectObject? readCompressedObject(
    int objId,
    XrefEntry entry,
    ParsedIndirectObject? Function(int objId) getObject,
  ) {
    final objStmId = entry.offset;
    final objStm = getObject(objStmId);
    if (objStm == null || objStm.value is! PdfDictToken) return null;
    if (objStm.streamData == null) return null;

    final dict = objStm.value as PdfDictToken;
    final type = asName(dict.values[PdfNameTokens.type]);
    if (type != PdfNameTokens.objStm) return null;

    final n = asInt(dict.values[PdfNameTokens.n]);
    final first = asInt(dict.values[PdfNameTokens.first]);
    if (n == null || first == null) return null;

    Uint8List data = objStm.streamData!;
    final filter = asName(dict.values[PdfNameTokens.filter]);
    if (filter == PdfNameTokens.flateDecode) {
      if (data.length > _maxStreamDecodeSize) return null;
      data = Uint8List.fromList(ZLibDecoder().decodeBytes(data));
    }

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

  static ObjStmHeader? readObjectStreamHeader(Uint8List data, int n) {
    int i = 0;
    final index = <int, int>{};
    for (int k = 0; k < n; k++) {
      i = PdfParserTokens.skipPdfWsAndComments(data, i, data.length);
      final obj = readNumber(data, i, data.length);
      if (obj == null || obj.value is! int) return null;
      i = obj.nextIndex;

      i = PdfParserTokens.skipPdfWsAndComments(data, i, data.length);
      final offset = readNumber(data, i, data.length);
      if (offset == null || offset.value is! int) return null;
      i = offset.nextIndex;

      index[obj.value as int] = offset.value as int;
    }
    return ObjStmHeader(index);
  }

  static int? resolveLength(
      PdfDictToken dict, ParsedIndirectObject? Function(int objId) getObject) {
    final lenValue = dict.values[PdfNameTokens.length];
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

  static ParseResult? parseObject(Uint8List bytes, int start, int end,
      {int depth = 0}) {
    if (depth > 64) return null;
    int i = PdfParserTokens.skipPdfWsAndComments(bytes, start, end);
    if (i >= end) return null;

    final b = bytes[i];
    if (b == 0x2F /* / */) {
      final name = PdfParserTokens.readName(bytes, i, end);
      return ParseResult(PdfNameToken(name.value), name.nextIndex);
    }
    if (b == 0x28 /* ( */) {
      final str = PdfParserTokens.readLiteralString(bytes, i, end);
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
      final hex = PdfParserTokens.readHexString(bytes, i, end);
      return ParseResult(
        PdfStringToken(hex.bytes, PdfStringFormat.binary),
        hex.nextIndex,
      );
    }
    if (b == 0x5B /* [ */) {
      final arr = readArray(bytes, i, end, depth: depth + 1);
      return ParseResult(arr.value, arr.nextIndex);
    }
    if (PdfParserTokens.isDigit(b) || b == 0x2D || b == 0x2B || b == 0x2E) {
      final num = readNumber(bytes, i, end);
      if (num == null) return null;

      final maybeRef = tryReadRefAfterNumber(bytes, num, end);
      if (maybeRef != null) {
        return ParseResult(maybeRef.value, maybeRef.nextIndex);
      }
      return ParseResult(num.value, num.nextIndex);
    }

    if (PdfParserTokens.matchToken(
        bytes, i, const <int>[0x74, 0x72, 0x75, 0x65])) {
      return ParseResult(true, i + 4);
    }
    if (PdfParserTokens.matchToken(
        bytes, i, const <int>[0x66, 0x61, 0x6C, 0x73, 0x65])) {
      return ParseResult(false, i + 5);
    }
    if (PdfParserTokens.matchToken(
        bytes, i, const <int>[0x6E, 0x75, 0x6C, 0x6C])) {
      return ParseResult(null, i + 4);
    }

    return null;
  }

  static ParseResult readDict(Uint8List bytes, int start, int end,
      {int depth = 0}) {
    int i = start;
    if (bytes[i] != 0x3C || bytes[i + 1] != 0x3C) {
      return ParseResult(PdfDictToken(<String, dynamic>{}), i);
    }
    i += 2;
    final values = <String, dynamic>{};
    while (i < end) {
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
      if (i + 1 < end && bytes[i] == 0x3E && bytes[i + 1] == 0x3E) {
        i += 2;
        return ParseResult(PdfDictToken(values), i, dictEnd: i);
      }

      if (bytes[i] == 0x2F) {
        final key = PdfParserTokens.readName(bytes, i, end);
        i = PdfParserTokens.skipPdfWsAndComments(bytes, key.nextIndex, end);
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

  static ParseResult readArray(Uint8List bytes, int start, int end,
      {int depth = 0}) {
    int i = start;
    if (bytes[i] != 0x5B) {
      return ParseResult(PdfArrayToken(<dynamic>[]), i);
    }
    i++;
    final values = <dynamic>[];
    while (i < end) {
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
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

  static ({dynamic value, int nextIndex})? tryReadRefAfterNumber(
    Uint8List bytes,
    ({dynamic value, int nextIndex}) first,
    int end,
  ) {
    if (first.value is! int) return null;
    int i = PdfParserTokens.skipPdfWsAndComments(bytes, first.nextIndex, end);
    if (i >= end || !PdfParserTokens.isDigit(bytes[i])) return null;
    final gen = PdfParserTokens.readInt(bytes, i, end);
    i = PdfParserTokens.skipPdfWsAndComments(bytes, gen.nextIndex, end);
    if (i < end && bytes[i] == 0x52 /* R */) {
      return (
        value: PdfRefToken(first.value as int, gen.value),
        nextIndex: i + 1
      );
    }
    return null;
  }

  static ({dynamic value, int nextIndex})? readNumber(
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
      if (PdfParserTokens.isDigit(b)) {
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

  /// Single converter from the tokenized model to the writing model.
  ///
  /// Reading a loaded document preserves the object numbers from the file,
  /// which is why the reference policy is [PdfReferencePolicy.preserve].
  static const PdfObjectConverter _converter = PdfObjectConverter.preserving;

  static PdfDict<PdfDataType> toPdfDict(
    PdfDictToken dict, {
    Set<String> ignoreKeys = const {},
  }) =>
      _converter.convertDict(dict, ignoreKeys: ignoreKeys);

  static PdfArray toPdfArray(PdfArrayToken array) =>
      _converter.convertArray(array);

  static PdfDataType? toPdfDataType(dynamic value) => _converter.convert(value);

  static void mergeDictIntoPdfDict(
    PdfDict<PdfDataType> target,
    PdfDictToken source, {
    Set<String> ignoreKeys = const {},
  }) =>
      _converter.mergeDictInto(target, source, ignoreKeys: ignoreKeys);

  static PdfRefToken? asRef(dynamic value) {
    if (value is PdfRefToken) return value;
    return null;
  }

  static String? asName(dynamic value) {
    if (value is PdfNameToken) return value.value;
    return null;
  }

  static int? asInt(dynamic value) {
    if (value is int) return value;
    if (value is double) return value.toInt();
    return null;
  }

  static List<double>? asNumArray(dynamic value) {
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
}
