import 'dart:typed_data';

import 'package:archive/archive.dart';

import '../io/pdf_random_access_reader.dart';
import 'parser_misc.dart';
import 'parser_objects.dart';
import 'parser_scan.dart';
import 'parser_tokens.dart';

import 'pdf_parser_types.dart';
import 'package:pdf_plus/src/pdf/pdf_names.dart';

class PdfParserXref {
  static const int maxStreamDecodeSize = 256 * 1024 * 1024;

  static int findStartXref(Uint8List bytes) {
    const token = <int>[0x73, 0x74, 0x61, 0x72, 0x74, 0x78, 0x72, 0x65, 0x66];

    // Procura do fim para o começo, limitando a janela para robustez/perf.
    final int windowStart =
        bytes.length > 4 * 1024 ? bytes.length - 4 * 1024 : 0;
    final int pos = PdfParserTokens.lastIndexOfSequence(
        bytes, token, windowStart, bytes.length);
    if (pos == -1) return 0;

    int i = pos + token.length;
    i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
    final parsed = PdfParserTokens.readInt(bytes, i, bytes.length);
    return parsed.value;
  }

  static int findStartXrefFromReader(PdfRandomAccessReader reader) {
    const token = <int>[0x73, 0x74, 0x61, 0x72, 0x74, 0x78, 0x72, 0x65, 0x66];
    final len = reader.length;
    final windowSize = len > 4 * 1024 ? 4 * 1024 : len;
    final windowStart = len - windowSize;
    final window = reader.readRange(windowStart, windowSize);
    final pos =
        PdfParserTokens.lastIndexOfSequence(window, token, 0, window.length);
    if (pos == -1) return 0;

    int i = pos + token.length;
    i = PdfParserTokens.skipPdfWsAndComments(window, i, window.length);
    final parsed = PdfParserTokens.readInt(window, i, window.length);
    return parsed.value;
  }

  static int _computeXrefOffset(Uint8List bytes) {
    final startXref = findStartXref(bytes);
    if (startXref > 0 && startXref < bytes.length) {
      return startXref;
    }

    // Fallback: procurar a última ocorrência de 'xref'
    const xrefToken = <int>[0x78, 0x72, 0x65, 0x66]; // xref
    final windowStart =
        bytes.length > 1024 * 1024 ? bytes.length - 1024 * 1024 : 0;
    final pos = PdfParserTokens.lastIndexOfSequence(
        bytes, xrefToken, windowStart, bytes.length);
    if (pos != -1) {
      return pos;
    }

    return 0;
  }

  static int computeXrefOffsetFromReader(PdfRandomAccessReader reader) {
    final len = reader.length;
    final startXref = findStartXrefFromReader(reader);
    if (startXref > 0 && startXref < len) {
      return startXref;
    }

    const xrefToken = <int>[0x78, 0x72, 0x65, 0x66];
    final windowSize = len > 1024 * 1024 ? 1024 * 1024 : len;
    final windowStart = len - windowSize;
    final window = reader.readRange(windowStart, windowSize);
    final pos = PdfParserTokens.lastIndexOfSequence(
        window, xrefToken, 0, window.length);
    if (pos != -1) {
      return windowStart + pos;
    }
    return 0;
  }

  static int _computeSize(Uint8List bytes, TrailerInfo? trailerInfo) {
    if (trailerInfo?.size != null && trailerInfo!.size! > 0) {
      return trailerInfo.size!;
    }
    if (trailerInfo == null) {
      final info = _readTrailerInfo(bytes, _computeXrefOffset(bytes));
      if (info.size != null && info.size! > 0) {
        return info.size!;
      }
    }
    return PdfParserMisc.maxObjectId(bytes) + 1;
  }

  static int computeSizeFromReader(
    PdfRandomAccessReader reader,
    TrailerInfo? trailerInfo,
  ) {
    if (reader is PdfMemoryRandomAccessReader) {
      return _computeSize(reader.readAll(), trailerInfo);
    }
    if (trailerInfo?.size != null && trailerInfo!.size! > 0) {
      return trailerInfo.size!;
    }

    final info =
        readTrailerInfoFromReader(reader, computeXrefOffsetFromReader(reader));
    if (info.size != null && info.size! > 0) {
      return info.size!;
    }

    return PdfParserMisc.maxObjectIdFromReader(reader) + 1;
  }

  static TrailerInfo mergeTrailerInfo(TrailerInfo? a, TrailerInfo b) {
    if (a == null) return b;
    return TrailerInfo(
      size: a.size ?? b.size,
      prev: a.prev ?? b.prev,
      rootObj: a.rootObj ?? b.rootObj,
      infoObj: a.infoObj ?? b.infoObj,
      id: a.id ?? b.id,
    );
  }

  static TrailerInfo _readTrailerInfo(Uint8List bytes, int startXref) {
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

    return TrailerInfo();
  }

  static TrailerInfo readTrailerInfoFromReader(
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

    return TrailerInfo();
  }

  static TrailerInfo _tryReadTrailerNearOffset(Uint8List bytes, int offset) {
    // Skip ws
    int i = PdfParserTokens.skipPdfWsAndComments(bytes, offset, bytes.length);

    // xref table?
    if (PdfParserTokens.matchToken(
        bytes, i, const <int>[0x78, 0x72, 0x65, 0x66])) {
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

    return TrailerInfo();
  }

  static TrailerInfo _tryReadLastTrailer(Uint8List bytes) {
    const trailerToken = <int>[
      0x74,
      0x72,
      0x61,
      0x69,
      0x6C,
      0x65,
      0x72
    ]; // trailer
    final windowStart =
        bytes.length > 1024 * 1024 ? bytes.length - 1024 * 1024 : 0;
    final pos = PdfParserTokens.lastIndexOfSequence(
        bytes, trailerToken, windowStart, bytes.length);
    if (pos == -1) {
      return TrailerInfo();
    }
    return _scanForTrailerDict(bytes, pos + trailerToken.length, bytes.length);
  }

  static TrailerInfo _scanForTrailerDict(Uint8List bytes, int start, int end) {
    int i = PdfParserTokens.skipPdfWsAndComments(bytes, start, end);
    // buscar '<<'
    for (; i + 1 < end; i++) {
      if (bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
        break;
      }
    }
    if (i + 1 >= end) {
      return TrailerInfo();
    }

    final dict = PdfParserScan.parseTrailerDict(bytes, i, end);
    return TrailerInfo(
      size: dict.size,
      prev: dict.prev,
      rootObj: dict.rootObj,
      infoObj: dict.infoObj,
      id: dict.id,
    );
  }

  static TrailerInfo _tryReadXrefStreamDict(Uint8List bytes, int offset) {
    // Verifica padrão: "<obj> <gen> obj" seguido de "<<" com /Type /XRef
    final header = _tryReadIndirectObjectHeader(bytes, offset, bytes.length);
    if (header == null) {
      return TrailerInfo();
    }

    final dict = _parseXrefStreamDict(bytes, header.dictStart, bytes.length);
    if (dict.type == PdfNameTokens.xRef) {
      return TrailerInfo(
        size: dict.size,
        prev: dict.prev,
        rootObj: dict.rootObj,
        infoObj: dict.infoObj,
        id: dict.id,
      );
    }
    return TrailerInfo();
  }

  static IndirectHeader? _tryReadIndirectObjectHeader(
    Uint8List bytes,
    int start,
    int end,
  ) {
    int i = PdfParserTokens.skipPdfWsAndComments(bytes, start, end);
    if (i >= end || !PdfParserTokens.isDigit(bytes[i])) return null;
    final obj = PdfParserTokens.readInt(bytes, i, end);
    i = obj.nextIndex;
    i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
    if (i >= end || !PdfParserTokens.isDigit(bytes[i])) return null;
    final gen = PdfParserTokens.readInt(bytes, i, end);
    i = gen.nextIndex;
    i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
    if (!PdfParserTokens.matchToken(bytes, i, const <int>[0x6F, 0x62, 0x6A]))
      return null; // obj
    i += 3;
    i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
    if (i + 1 >= end || bytes[i] != 0x3C || bytes[i + 1] != 0x3C) return null;
    final dictEnd = PdfParserScan.findDictEnd(bytes, i, end);
    if (dictEnd == -1) return null;
    return IndirectHeader(i, dictEnd);
  }

  static TrailerInfo? _parseXrefAtOffset(
    Uint8List bytes,
    int offset,
    Map<int, XrefEntry> entries,
  ) {
    int i = PdfParserTokens.skipPdfWsAndComments(bytes, offset, bytes.length);

    // xref table?
    if (PdfParserTokens.matchToken(
        bytes, i, const <int>[0x78, 0x72, 0x65, 0x66])) {
      return _parseXrefTable(bytes, i + 4, entries);
    }

    // xref stream?
    return _parseXrefStream(bytes, i, entries);
  }

  static TrailerInfo? parseXrefAtOffsetFromReader(
    PdfRandomAccessReader reader,
    int offset,
    Map<int, XrefEntry> entries,
  ) {
    if (reader is PdfMemoryRandomAccessReader) {
      return _parseXrefAtOffset(reader.readAll(), offset, entries);
    }

    final len = reader.length;
    const windowSizes = <int>[
      256 * 1024,
      1024 * 1024,
      4 * 1024 * 1024,
      16 * 1024 * 1024
    ];
    for (final size in windowSizes) {
      if (offset < 0 || offset >= len) return null;
      final windowSize = (offset + size > len) ? (len - offset) : size;
      final window = reader.readRange(offset, windowSize);
      int i = PdfParserTokens.skipPdfWsAndComments(window, 0, window.length);

      if (PdfParserTokens.matchToken(
          window, i, const <int>[0x78, 0x72, 0x65, 0x66])) {
        final info = _parseXrefTableFromWindow(window, entries, reader);
        if (info != null) return info;
      } else {
        final info =
            _parseXrefStreamFromWindow(window, offset, entries, reader);
        if (info != null) return info;
      }
    }

    return null;
  }

  static void _setXrefEntryIfAbsent(
    Map<int, XrefEntry> entries,
    int objId,
    XrefEntry entry,
  ) {
    entries.putIfAbsent(objId, () => entry);
  }

  static TrailerInfo? _parseXrefTableFromWindow(
    Uint8List bytes,
    Map<int, XrefEntry> entries,
    PdfRandomAccessReader reader,
  ) {
    int i = 0;

    while (i < bytes.length) {
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length) break;

      if (PdfParserTokens.matchToken(
          bytes, i, const <int>[0x74, 0x72, 0x61, 0x69, 0x6C, 0x65, 0x72])) {
        return _scanForTrailerDict(bytes, i + 7, bytes.length);
      }

      if (!PdfParserTokens.isDigit(bytes[i])) {
        i++;
        continue;
      }

      final startObj = PdfParserTokens.readInt(bytes, i, bytes.length);
      i = startObj.nextIndex;
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length || !PdfParserTokens.isDigit(bytes[i])) {
        continue;
      }
      final count = PdfParserTokens.readInt(bytes, i, bytes.length);
      i = count.nextIndex;

      for (int j = 0; j < count.value; j++) {
        i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
        if (i >= bytes.length) break;

        final off = PdfParserTokens.readInt(bytes, i, bytes.length);
        i = off.nextIndex;
        i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
        final gen = PdfParserTokens.readInt(bytes, i, bytes.length);
        i = gen.nextIndex;
        i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);

        final flag = bytes[i];
        i++;
        if (flag == 0x6E /* n */) {
          final objId = startObj.value + j;
          final fixed = _fixOffsetReader(reader, objId, gen.value, off.value);
          _setXrefEntryIfAbsent(
            entries,
            objId,
            XrefEntry(
              offset: fixed,
              gen: gen.value,
              type: XrefType.inUse,
            ),
          );
        } else if (flag == 0x66 /* f */) {
          final objId = startObj.value + j;
          _setXrefEntryIfAbsent(
            entries,
            objId,
            XrefEntry(
              offset: off.value,
              gen: gen.value,
              type: XrefType.free,
            ),
          );
        }

        while (i < bytes.length && bytes[i] != 0x0A && bytes[i] != 0x0D) {
          i++;
        }
      }
    }

    return null;
  }

  static TrailerInfo? _parseXrefStreamFromWindow(
    Uint8List bytes,
    int baseOffset,
    Map<int, XrefEntry> entries,
    PdfRandomAccessReader reader,
  ) {
    final header = _tryReadIndirectObjectHeader(bytes, 0, bytes.length);
    if (header == null) return null;

    final dict = _parseXrefStreamDict(bytes, header.dictStart, bytes.length);
    if (dict.type != PdfNameTokens.xRef) return null;

    Uint8List? stream = PdfParserObjects.extractStream(
        bytes, header.dictEnd, bytes.length, dict.length);
    if (stream == null && dict.length != null) {
      final streamStart = PdfParserScan.findStreamStart(bytes, header.dictEnd);
      if (streamStart != null) {
        final abs = baseOffset + streamStart;
        stream = reader.readRange(abs, dict.length!);
      }
    }

    if (stream == null && dict.length == null) {
      final streamStart = PdfParserScan.findStreamStart(bytes, header.dictEnd);
      if (streamStart != null) {
        final absStart = baseOffset + streamStart;
        final endAbs = PdfParserScan.skipUnknownLengthStreamReader(
            reader, absStart, reader.length);
        if (endAbs != null) {
          final dataEnd = endAbs - PdfParserTokens.endStreamToken.length;
          final len = dataEnd - absStart;
          if (len > 0 && absStart + len <= reader.length) {
            stream = reader.readRange(absStart, len);
          }
        }
      }
    }

    if (stream == null) {
      return TrailerInfo(
        size: dict.size,
        prev: dict.prev,
        rootObj: dict.rootObj,
        infoObj: dict.infoObj,
        id: dict.id,
      );
    }

    Uint8List data = stream;
    if (dict.filter == PdfNameTokens.flateDecode) {
      if (stream.length > maxStreamDecodeSize) {
        return TrailerInfo(
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
      return TrailerInfo(
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
          _setXrefEntryIfAbsent(
            entries,
            objId,
            XrefEntry(
              offset: fixed,
              gen: f2,
              type: XrefType.inUse,
            ),
          );
        } else if (type == 2) {
          _setXrefEntryIfAbsent(
            entries,
            objId,
            XrefEntry(
              offset: f1,
              gen: f2,
              type: XrefType.compressed,
            ),
          );
        }
      }
    }

    return TrailerInfo(
      size: dict.size,
      prev: dict.prev,
      rootObj: dict.rootObj,
      infoObj: dict.infoObj,
      id: dict.id,
    );
  }

  static int _fixOffsetReader(
    PdfRandomAccessReader reader,
    int objId,
    int gen,
    int offset,
  ) {
    if (offset < 0) {
      final corrected = offset + 0x100000000;
      if (_isValidObjAtOffsetReader(reader, objId, gen, corrected))
        return corrected;
    }
    if (_isValidObjAtOffsetReader(reader, objId, gen, offset)) return offset;

    const radius = 1024;
    final start = offset - radius < 0 ? 0 : offset - radius;
    final end =
        offset + radius > reader.length ? reader.length : offset + radius;
    final found = _findObjectHeaderReader(reader, objId, gen, start, end);
    return found ?? offset;
  }

  static bool _isValidObjAtOffsetReader(
    PdfRandomAccessReader reader,
    int objId,
    int gen,
    int offset,
  ) {
    if (offset < 0 || offset >= reader.length) return false;
    final win = reader.readRange(offset, 64);
    int i = PdfParserTokens.skipPdfWsAndComments(win, 0, win.length);
    if (i >= win.length || !PdfParserTokens.isDigit(win[i])) return false;
    final obj = PdfParserTokens.readInt(win, i, win.length);
    if (obj.value != objId) return false;
    i = PdfParserTokens.skipPdfWsAndComments(win, obj.nextIndex, win.length);
    if (i >= win.length || !PdfParserTokens.isDigit(win[i])) return false;
    final genRead = PdfParserTokens.readInt(win, i, win.length);
    if (genRead.value != gen) return false;
    i = PdfParserTokens.skipPdfWsAndComments(
        win, genRead.nextIndex, win.length);
    return PdfParserTokens.matchToken(win, i, const <int>[0x6F, 0x62, 0x6A]);
  }

  static int? _findObjectHeaderReader(
    PdfRandomAccessReader reader,
    int objId,
    int gen,
    int start,
    int end,
  ) {
    final window = reader.readRange(start, end - start);
    final found =
        PdfParserScan.findObjectHeader(window, objId, gen, 0, window.length);
    if (found == null) return null;
    return start + found;
  }

  static TrailerInfo? _parseXrefTable(
    Uint8List bytes,
    int start,
    Map<int, XrefEntry> entries,
  ) {
    int i = start;

    while (i < bytes.length) {
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length) break;

      if (PdfParserTokens.matchToken(
          bytes, i, const <int>[0x74, 0x72, 0x61, 0x69, 0x6C, 0x65, 0x72])) {
        return _scanForTrailerDict(bytes, i + 7, bytes.length);
      }

      if (!PdfParserTokens.isDigit(bytes[i])) {
        i++;
        continue;
      }

      final startObj = PdfParserTokens.readInt(bytes, i, bytes.length);
      i = startObj.nextIndex;
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
      if (!PdfParserTokens.isDigit(bytes[i])) {
        continue;
      }
      final count = PdfParserTokens.readInt(bytes, i, bytes.length);
      i = count.nextIndex;

      for (int j = 0; j < count.value; j++) {
        i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
        if (i >= bytes.length) break;

        final off = PdfParserTokens.readInt(bytes, i, bytes.length);
        i = off.nextIndex;
        i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
        final gen = PdfParserTokens.readInt(bytes, i, bytes.length);
        i = gen.nextIndex;
        i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);

        final flag = bytes[i];
        i++;
        if (flag == 0x6E /* n */) {
          final objId = startObj.value + j;
          final fixed = _fixOffset(bytes, objId, gen.value, off.value);
          _setXrefEntryIfAbsent(
            entries,
            objId,
            XrefEntry(
              offset: fixed,
              gen: gen.value,
              type: XrefType.inUse,
            ),
          );
        } else if (flag == 0x66 /* f */) {
          final objId = startObj.value + j;
          _setXrefEntryIfAbsent(
            entries,
            objId,
            XrefEntry(
              offset: off.value,
              gen: gen.value,
              type: XrefType.free,
            ),
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

  static TrailerInfo? _parseXrefStream(
    Uint8List bytes,
    int offset,
    Map<int, XrefEntry> entries,
  ) {
    final header = _tryReadIndirectObjectHeader(bytes, offset, bytes.length);
    if (header == null) return null;

    final dict = _parseXrefStreamDict(bytes, header.dictStart, bytes.length);
    if (dict.type != PdfNameTokens.xRef) return null;

    final stream = PdfParserObjects.extractStream(
        bytes, header.dictEnd, bytes.length, dict.length);
    if (stream == null)
      return TrailerInfo(
        size: dict.size,
        prev: dict.prev,
        rootObj: dict.rootObj,
        infoObj: dict.infoObj,
        id: dict.id,
      );

    Uint8List data = stream;
    if (dict.filter == PdfNameTokens.flateDecode) {
      if (stream.length > maxStreamDecodeSize) {
        return TrailerInfo(
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
      return TrailerInfo(
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
          _setXrefEntryIfAbsent(
            entries,
            objId,
            XrefEntry(
              offset: fixed,
              gen: f2,
              type: XrefType.inUse,
            ),
          );
        } else if (type == 2) {
          _setXrefEntryIfAbsent(
            entries,
            objId,
            XrefEntry(
              offset: f1,
              gen: f2,
              type: XrefType.compressed,
            ),
          );
        }
      }
    }

    return TrailerInfo(
      size: dict.size,
      prev: dict.prev,
      rootObj: dict.rootObj,
      infoObj: dict.infoObj,
      id: dict.id,
    );
  }

  static XrefStreamDict _parseXrefStreamDict(
      Uint8List bytes, int start, int end) {
    final parsed = PdfParserObjects.readDict(bytes, start, end);
    final v = parsed.value;
    if (v is! PdfDictToken) {
      return XrefStreamDict();
    }

    final m = v.values;

    final String? type = PdfParserObjects.asName(m[PdfNameTokens.type]);
    final int? size = PdfParserObjects.asInt(m[PdfNameTokens.size]);
    final int? prev = PdfParserObjects.asInt(m[PdfNameTokens.prev]);

    int? rootObj;
    int? infoObj;
    final rootRef = PdfParserObjects.asRef(m[PdfNameTokens.root]);
    if (rootRef != null) rootObj = rootRef.obj;
    final infoRef = PdfParserObjects.asRef(m[PdfNameTokens.info]);
    if (infoRef != null) infoObj = infoRef.obj;

    Uint8List? id;
    final idVal = m[PdfNameTokens.id];
    if (idVal is PdfArrayToken && idVal.values.isNotEmpty) {
      final first = idVal.values.first;
      if (first is PdfStringToken) {
        id = first.bytes;
      }
    }

    int? length;
    final lenVal = m[PdfNameTokens.length];
    if (lenVal is int) length = lenVal;
    if (lenVal is double) length = lenVal.toInt();

    String? filter;
    final filterVal = m[PdfNameTokens.filter];
    if (filterVal is PdfNameToken) {
      filter = filterVal.value;
    } else if (filterVal is PdfArrayToken && filterVal.values.isNotEmpty) {
      final f0 = filterVal.values.first;
      if (f0 is PdfNameToken) filter = f0.value;
    }

    List<int>? w;
    final wVal = m[PdfNameTokens.w];
    if (wVal is PdfArrayToken) {
      final tmp = <int>[];
      for (final e in wVal.values) {
        final vi = PdfParserObjects.asInt(e);
        if (vi != null) tmp.add(vi);
      }
      if (tmp.isNotEmpty) w = tmp;
    }

    List<int>? index;
    final idxVal = m[PdfNameTokens.index];
    if (idxVal is PdfArrayToken) {
      final tmp = <int>[];
      for (final e in idxVal.values) {
        final vi = PdfParserObjects.asInt(e);
        if (vi != null) tmp.add(vi);
      }
      if (tmp.isNotEmpty) index = tmp;
    }

    return XrefStreamDict(
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

  static int _readField(Uint8List data, int offset, int width) {
    if (width == 0) return 0;
    int value = 0;
    for (int i = 0; i < width; i++) {
      value = (value << 8) | data[offset + i];
    }
    return value;
  }

  static int _fixOffset(Uint8List bytes, int objId, int gen, int offset) {
    if (offset < 0) {
      final corrected = offset + 0x100000000;
      if (PdfParserScan.isValidObjAtOffset(bytes, objId, gen, corrected))
        return corrected;
    }
    if (PdfParserScan.isValidObjAtOffset(bytes, objId, gen, offset))
      return offset;

    // Heurística: procurar o header do objeto num raio de 1KB
    const radius = 1024;
    final start = offset - radius < 0 ? 0 : offset - radius;
    final end = offset + radius > bytes.length ? bytes.length : offset + radius;
    final found = PdfParserScan.findObjectHeader(bytes, objId, gen, start, end);
    return found ?? offset;
  }

  static int _repairXrefByScan(
    Uint8List bytes,
    Map<int, XrefEntry> entries,
    void Function(int? rootObj) onRootFound,
  ) {
    final tailRoot = PdfParserScan.findRootFromTail(bytes);
    if (tailRoot != null) {
      final found = PdfParserScan.findObjectHeaderAnyGen(bytes, tailRoot.obj);
      if (found != null) {
        entries[tailRoot.obj] = XrefEntry(
          offset: found.offset,
          gen: found.gen,
          type: XrefType.inUse,
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
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length) break;

      if (PdfParserTokens.isDigit(bytes[i]) ||
          bytes[i] == 0x2D ||
          bytes[i] == 0x2B) {
        ({int value, int nextIndex}) num;
        try {
          num = PdfParserTokens.readInt(bytes, i, bytes.length);
        } catch (_) {
          i++;
          continue;
        }
        prevInt = lastInt;
        prevIntPos = lastIntPos;
        lastInt = num.value;
        lastIntPos = i;
        i = num.nextIndex;

        final j = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
        if (j < bytes.length &&
            PdfParserTokens.matchToken(
                bytes, j, const <int>[0x6F, 0x62, 0x6A])) {
          // padrão: <prevInt> <lastInt> obj
          if (prevInt != null && prevIntPos != null) {
            final objId = prevInt;
            final gen = lastInt;

            if (objId > maxObjId) maxObjId = objId;
            final existing = entries[objId];
            if (existing == null || prevIntPos > existing.offset) {
              entries[objId] = XrefEntry(
                offset: prevIntPos,
                gen: gen,
                type: XrefType.inUse,
              );
            }

            final dictInfo =
                PdfParserScan.scanObjectDictAndSkipStream(bytes, j + 3);
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

  static int repairXrefByScanFromReader(
    PdfRandomAccessReader reader,
    Map<int, XrefEntry> entries,
    void Function(int? rootObj) onRootFound,
  ) {
    if (reader is PdfMemoryRandomAccessReader) {
      return _repairXrefByScan(reader.readAll(), entries, onRootFound);
    }

    final tailRoot = PdfParserScan.findRootFromTailFromReader(reader);
    if (tailRoot != null) {
      final found =
          PdfParserScan.findObjectHeaderAnyGenReader(reader, tailRoot.obj);
      if (found != null) {
        entries[tailRoot.obj] = XrefEntry(
          offset: found.offset,
          gen: found.gen,
          type: XrefType.inUse,
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
      final windowSize =
          (offset + chunkSize > len) ? (len - offset) : chunkSize;
      final window = reader.readRange(offset, windowSize);
      final bytes = window;
      final end = bytes.length;
      int i = 0;
      bool jumped = false;

      while (i < end) {
        i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
        if (i >= end) break;

        final b = bytes[i];
        if (b >= 0x30 && b <= 0x39) {
          final res = PdfParserTokens.readIntFast(bytes, i, end);
          if (res.value == -1) {
            i++;
            continue;
          }

          prevInt = lastInt;
          prevIntPosAbs = lastIntPosAbs;
          lastInt = res.value;
          lastIntPosAbs = offset + i;
          i = res.nextIndex;

          final j = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
          if (j < end &&
              PdfParserTokens.matchToken(
                  bytes, j, const <int>[0x6F, 0x62, 0x6A])) {
            if (prevInt != null && prevIntPosAbs != null) {
              final objId = prevInt;
              final gen = lastInt;

              if (objId > maxObjId) maxObjId = objId;
              final existing = entries[objId];
              if (existing == null || prevIntPosAbs > existing.offset) {
                entries[objId] = XrefEntry(
                  offset: prevIntPosAbs,
                  gen: gen,
                  type: XrefType.inUse,
                );
              }

              final dictInfo =
                  PdfParserScan.scanObjectDictAndSkipStreamFromWindow(
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
                final skipAbs = PdfParserScan.skipUnknownLengthStreamReader(
                  reader,
                  dictInfo.streamStartAbs!,
                  len,
                );

                if (skipAbs != null && skipAbs > offset && skipAbs <= len) {
                  offset = skipAbs;
                } else {
                  offset = (offset + end <= len) ? (offset + end) : len;
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
}
