import 'dart:typed_data';

import 'package:pdf_plus/src/pdf/pdf_names.dart';

import '../io/pdf_random_access_reader.dart';

import 'pdf_parser_types.dart';
import 'parser_tokens.dart';

class PdfParserScan {
  static ScanDictInfoReader scanObjectDictAndSkipStreamFromWindow(
    Uint8List bytes,
    int start,
    int baseOffset,
    int fileLength,
  ) {
    int i = PdfParserTokens.skipPdfWsAndComments(bytes, start, bytes.length);
    int? streamLength;
    bool isCatalog = false;
    if (i + 1 < bytes.length && bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
      final dict = readDictLight(bytes, i, bytes.length);
      streamLength = dict.length;
      isCatalog = dict.isCatalog;
      i = dict.nextIndex;
    }

    i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);

    final streamStart = findStreamStart(bytes, i);
    if (streamStart == null) {
      return ScanDictInfoReader(i, isCatalog, null, null);
    }

    if (streamLength != null && streamLength > 0) {
      final skipAbs = baseOffset + streamStart + streamLength;
      if (skipAbs > 0 && skipAbs <= fileLength) {
        final nextIndex = (skipAbs <= baseOffset + bytes.length)
            ? (skipAbs - baseOffset)
            : bytes.length;
        return ScanDictInfoReader(nextIndex, isCatalog, skipAbs, null);
      }
    }

    final endPos = PdfParserTokens.indexOfSequenceBmh(
      bytes,
      PdfParserTokens.endStreamToken,
      streamStart,
      bytes.length,
    );
    if (endPos != -1) {
      final skipAbs =
          baseOffset + endPos + PdfParserTokens.endStreamToken.length;
      return ScanDictInfoReader(
        endPos + PdfParserTokens.endStreamToken.length,
        isCatalog,
        skipAbs,
        null,
      );
    }

    return ScanDictInfoReader(
      bytes.length,
      isCatalog,
      null,
      baseOffset + streamStart,
    );
  }

  static int? skipUnknownLengthStreamReader(
    PdfRandomAccessReader reader,
    int startAbs,
    int fileLength,
  ) {
    const chunkSize = 4 * 1024 * 1024;
    final overlap = PdfParserTokens.endStreamToken.length + 32;

    int offset = startAbs;
    while (offset < fileLength) {
      final windowSize =
          (offset + chunkSize > fileLength) ? (fileLength - offset) : chunkSize;
      if (windowSize <= 0) return null;

      final window = reader.readRange(offset, windowSize);
      final pos = PdfParserTokens.indexOfSequenceBmh(
        window,
        PdfParserTokens.endStreamToken,
        0,
        window.length,
      );
      if (pos != -1) {
        return offset + pos + PdfParserTokens.endStreamToken.length;
      }

      if (offset + chunkSize >= fileLength) break;
      offset += chunkSize - overlap;
    }

    return null;
  }

  static PdfRefToken? findRootFromTailFromReader(PdfRandomAccessReader reader) {
    final tailSize = reader.length > 1024 * 1024 ? 1024 * 1024 : reader.length;
    final start = reader.length - tailSize;
    final tail = reader.readRange(start, tailSize);
    int i = 0;
    while (i < tail.length) {
      if (tail[i] == 0x2F /* / */) {
        final name = PdfParserTokens.readName(tail, i, tail.length);
        if (name.value == PdfNameTokens.root) {
          i = PdfParserTokens.skipPdfWsAndComments(
            tail,
            name.nextIndex,
            tail.length,
          );
          if (i < tail.length && PdfParserTokens.isDigit(tail[i])) {
            final ref = readRef(tail, i, tail.length);
            if (ref != null) return PdfRefToken(ref.obj, ref.gen);
          }
        }
      }
      i++;
    }
    return null;
  }

  static PdfRefToken? findInfoFromTailFromReader(PdfRandomAccessReader reader) {
    final tailSize = reader.length > 1024 * 1024 ? 1024 * 1024 : reader.length;
    final start = reader.length - tailSize;
    final tail = reader.readRange(start, tailSize);
    int i = 0;
    while (i < tail.length) {
      if (tail[i] == 0x2F /* / */) {
        final name = PdfParserTokens.readName(tail, i, tail.length);
        if (name.value == PdfNameTokens.info) {
          i = PdfParserTokens.skipPdfWsAndComments(
            tail,
            name.nextIndex,
            tail.length,
          );
          if (i < tail.length && PdfParserTokens.isDigit(tail[i])) {
            final ref = readRef(tail, i, tail.length);
            if (ref != null) return PdfRefToken(ref.obj, ref.gen);
          }
        }
      }
      i++;
    }
    return null;
  }

  static ({int offset, int gen})? findObjectHeaderAnyGenReader(
    PdfRandomAccessReader reader,
    int objId,
  ) {
    if (reader is PdfMemoryRandomAccessReader) {
      return findObjectHeaderAnyGen(reader.readAll(), objId);
    }

    final len = reader.length;
    final headSize = len > 16 * 1024 * 1024 ? 16 * 1024 * 1024 : len;
    final tailSize = len > 16 * 1024 * 1024 ? 16 * 1024 * 1024 : len;

    final head =
        findObjectHeaderAnyGenInRangeReader(reader, objId, 0, headSize);
    if (head != null) return head;

    final tailStart = len - tailSize;
    final tail =
        findObjectHeaderAnyGenInRangeReader(reader, objId, tailStart, len);
    if (tail != null) return tail;

    return findObjectHeaderAnyGenByScanReader(reader, objId);
  }

  static ({int offset, int gen})? findObjectHeaderAnyGenByScanReader(
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
      final found =
          _findObjectHeaderAnyGenInRange(window, objId, 0, window.length);
      if (found != null) {
        return (offset: offset + found.offset, gen: found.gen);
      }

      if (offset + chunkSize >= reader.length) break;
      offset += chunkSize - overlap;
    }

    return null;
  }

  static ({int offset, int gen})? findObjectHeaderAnyGenInRangeReader(
    PdfRandomAccessReader reader,
    int objId,
    int start,
    int end,
  ) {
    final window = reader.readRange(start, end - start);
    final found =
        _findObjectHeaderAnyGenInRange(window, objId, 0, window.length);
    if (found == null) return null;
    return (offset: start + found.offset, gen: found.gen);
  }

  static ScanDictInfo scanObjectDictAndSkipStream(Uint8List bytes, int start) {
    int i = PdfParserTokens.skipPdfWsAndComments(bytes, start, bytes.length);
    int? streamLength;
    bool isCatalog = false;

    if (i + 1 < bytes.length && bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
      final dict = readDictLight(bytes, i, bytes.length);
      streamLength = dict.length;
      isCatalog = dict.isCatalog;
      i = dict.nextIndex;
    }

    i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
    if (PdfParserTokens.matchToken(
        bytes, i, const <int>[0x73, 0x74, 0x72, 0x65, 0x61, 0x6D])) {
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
      final endPos = PdfParserTokens.indexOfSequence(
        bytes,
        PdfParserTokens.endStreamToken,
        i,
        bytes.length,
      );
      if (endPos != -1) {
        i = endPos + PdfParserTokens.endStreamToken.length;
      }
    }

    return ScanDictInfo(i, isCatalog);
  }

  static DictLightResult readDictLight(Uint8List bytes, int start, int end) {
    int i = start;
    if (i + 1 >= end || bytes[i] != 0x3C || bytes[i + 1] != 0x3C) {
      return DictLightResult(i, null, false);
    }
    i += 2;

    int? length;
    bool isCatalog = false;
    final limitEnd = (start + 4096 < end) ? (start + 4096) : end;

    const keyLength = [0x2F, 0x4C, 0x65, 0x6E, 0x67, 0x74, 0x68];
    const keyType = [0x2F, 0x54, 0x79, 0x70, 0x65];
    const valCatalog = [0x2F, 0x43, 0x61, 0x74, 0x61, 0x6C, 0x6F, 0x67];

    while (i < limitEnd) {
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, limitEnd);
      if (i >= limitEnd) break;

      if (bytes[i] == 0x3E && i + 1 < limitEnd && bytes[i + 1] == 0x3E) {
        return DictLightResult(i + 2, length, isCatalog);
      }

      if (bytes[i] == 0x2F) {
        final isKeyLength = PdfParserTokens.matchBytes(bytes, i, keyLength);
        final isKeyType =
            !isKeyLength && PdfParserTokens.matchBytes(bytes, i, keyType);

        i = PdfParserTokens.skipTokenRaw(bytes, i, limitEnd);
        i = PdfParserTokens.skipPdfWsAndComments(bytes, i, limitEnd);
        if (i >= limitEnd) break;

        if (isKeyLength) {
          if (PdfParserTokens.isDigit(bytes[i])) {
            final res = PdfParserTokens.readIntFast(bytes, i, limitEnd);
            if (res.value != -1) {
              final possibleLen = res.value;
              int nextI = res.nextIndex;

              int k =
                  PdfParserTokens.skipPdfWsAndComments(bytes, nextI, limitEnd);
              bool isRef = false;
              if (k < limitEnd) {
                if (PdfParserTokens.isDigit(bytes[k])) {
                  final resGen =
                      PdfParserTokens.readIntFast(bytes, k, limitEnd);
                  int afterGen = PdfParserTokens.skipPdfWsAndComments(
                      bytes, resGen.nextIndex, limitEnd);
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
          if (PdfParserTokens.matchBytes(bytes, i, valCatalog)) {
            isCatalog = true;
          }
        }

        i = PdfParserTokens.skipTokenRaw(bytes, i, limitEnd);
        continue;
      }

      i++;
    }

    return DictLightResult(i, length, isCatalog);
  }

  static PdfRefToken? findRootFromTail(Uint8List bytes) {
    final tailSize = bytes.length > 1024 * 1024 ? 1024 * 1024 : bytes.length;
    final start = bytes.length - tailSize;
    int i = start;
    while (i < bytes.length) {
      if (bytes[i] == 0x2F /* / */) {
        final name = PdfParserTokens.readName(bytes, i, bytes.length);
        if (name.value == PdfNameTokens.root) {
          i = PdfParserTokens.skipPdfWsAndComments(
            bytes,
            name.nextIndex,
            bytes.length,
          );
          if (i < bytes.length && PdfParserTokens.isDigit(bytes[i])) {
            final ref = readRef(bytes, i, bytes.length);
            if (ref != null) return PdfRefToken(ref.obj, ref.gen);
          }
        }
      }
      i++;
    }
    return null;
  }

  static ({int offset, int gen})? findObjectHeaderAnyGen(
    Uint8List bytes,
    int objId,
  ) {
    final headSize =
        bytes.length > 16 * 1024 * 1024 ? 16 * 1024 * 1024 : bytes.length;
    final tailSize =
        bytes.length > 16 * 1024 * 1024 ? 16 * 1024 * 1024 : bytes.length;

    final head = _findObjectHeaderAnyGenInRange(bytes, objId, 0, headSize);
    if (head != null) return head;

    final tailStart = bytes.length - tailSize;
    final tail =
        _findObjectHeaderAnyGenInRange(bytes, objId, tailStart, bytes.length);
    if (tail != null) return tail;

    return _findObjectHeaderAnyGenInRange(bytes, objId, 0, bytes.length);
  }

  static bool isValidObjAtOffset(
    Uint8List bytes,
    int objId,
    int gen,
    int offset,
  ) {
    if (offset < 0 || offset >= bytes.length) return false;
    int i = PdfParserTokens.skipPdfWsAndComments(bytes, offset, bytes.length);
    if (i >= bytes.length || !PdfParserTokens.isDigit(bytes[i])) return false;
    final obj = PdfParserTokens.readInt(bytes, i, bytes.length);
    if (obj.value != objId) return false;
    i = PdfParserTokens.skipPdfWsAndComments(
        bytes, obj.nextIndex, bytes.length);
    if (i >= bytes.length || !PdfParserTokens.isDigit(bytes[i])) return false;
    final genRead = PdfParserTokens.readInt(bytes, i, bytes.length);
    if (genRead.value != gen) return false;
    i = PdfParserTokens.skipPdfWsAndComments(
      bytes,
      genRead.nextIndex,
      bytes.length,
    );
    return PdfParserTokens.matchToken(bytes, i, const <int>[0x6F, 0x62, 0x6A]);
  }

  static int findDictEnd(Uint8List bytes, int start, int end) {
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

  static ({int obj, int gen})? readRef(Uint8List bytes, int i, int end) {
    if (!PdfParserTokens.isDigit(bytes[i])) return null;
    final obj = PdfParserTokens.readInt(bytes, i, end);
    i = PdfParserTokens.skipPdfWsAndComments(bytes, obj.nextIndex, end);
    if (i >= end || !PdfParserTokens.isDigit(bytes[i])) return null;
    final gen = PdfParserTokens.readInt(bytes, i, end);
    i = PdfParserTokens.skipPdfWsAndComments(bytes, gen.nextIndex, end);
    if (i >= end || bytes[i] != 0x52 /* R */) return null;
    return (obj: obj.value, gen: gen.value);
  }

  static TrailerDictValues parseTrailerDict(
    Uint8List bytes,
    int start,
    int end,
  ) {
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

      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
      if (i >= end) break;

      if (bytes[i] == 0x2F /* / */) {
        final name = PdfParserTokens.readName(bytes, i, end);
        currentKey = name.value;
        i = name.nextIndex;
        continue;
      }

      if (currentKey != null) {
        if (PdfParserTokens.isDigit(bytes[i]) || bytes[i] == 0x2D) {
          final num = PdfParserTokens.readInt(bytes, i, end);
          if (currentKey == PdfNameTokens.size) size = num.value;
          if (currentKey == PdfNameTokens.prev) prev = num.value;

          if (currentKey == PdfNameTokens.root ||
              currentKey == PdfNameTokens.info) {
            final ref = readRef(bytes, i, end);
            if (ref != null) {
              if (currentKey == PdfNameTokens.root) rootObj = ref.obj;
              if (currentKey == PdfNameTokens.info) infoObj = ref.obj;
            }
          }

          i = num.nextIndex;
          currentKey = null;
          continue;
        }

        if (currentKey == PdfNameTokens.id && bytes[i] == 0x5B /* [ */) {
          final parsed = PdfParserTokens.readIdArray(bytes, i, end);
          id = parsed.id;
          i = parsed.nextIndex;
          currentKey = null;
          continue;
        }
      }

      i++;
    }

    return TrailerDictValues(
      size: size,
      prev: prev,
      rootObj: rootObj,
      infoObj: infoObj,
      id: id,
    );
  }

  static int? findStreamStart(Uint8List bytes, int dictEnd) {
    int i = dictEnd;
    i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
    if (!PdfParserTokens.matchToken(
        bytes, i, const <int>[0x73, 0x74, 0x72, 0x65, 0x61, 0x6D])) {
      return null;
    }
    i += 6;
    if (i < bytes.length && bytes[i] == 0x0D) i++;
    if (i < bytes.length && bytes[i] == 0x0A) i++;
    return i;
  }

  static int? findObjectHeader(
    Uint8List bytes,
    int objId,
    int gen,
    int start,
    int end,
  ) {
    for (int i = start; i < end; i++) {
      if (!PdfParserTokens.isDigit(bytes[i])) continue;
      try {
        final obj = PdfParserTokens.readInt(bytes, i, end);
        if (obj.value != objId) continue;
        int j = PdfParserTokens.skipPdfWsAndComments(bytes, obj.nextIndex, end);
        if (j >= end || !PdfParserTokens.isDigit(bytes[j])) continue;
        final genRead = PdfParserTokens.readInt(bytes, j, end);
        if (genRead.value != gen) continue;
        j = PdfParserTokens.skipPdfWsAndComments(bytes, genRead.nextIndex, end);
        if (PdfParserTokens.matchToken(
            bytes, j, const <int>[0x6F, 0x62, 0x6A])) {
          return i;
        }
      } catch (_) {
        // ignore
      }
    }
    return null;
  }

  static ({int offset, int gen})? _findObjectHeaderAnyGenInRange(
    Uint8List bytes,
    int objId,
    int start,
    int end,
  ) {
    int i = start;
    while (i < end) {
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, end);
      if (i >= end) break;
      if (!PdfParserTokens.isDigit(bytes[i])) {
        i++;
        continue;
      }
      try {
        final obj = PdfParserTokens.readInt(bytes, i, end);
        if (obj.value != objId) {
          i = obj.nextIndex;
          continue;
        }
        int j = PdfParserTokens.skipPdfWsAndComments(bytes, obj.nextIndex, end);
        if (j >= end || !PdfParserTokens.isDigit(bytes[j])) {
          i = obj.nextIndex;
          continue;
        }
        final gen = PdfParserTokens.readInt(bytes, j, end);
        j = PdfParserTokens.skipPdfWsAndComments(bytes, gen.nextIndex, end);
        if (PdfParserTokens.matchToken(
            bytes, j, const <int>[0x6F, 0x62, 0x6A])) {
          return (offset: i, gen: gen.value);
        }
        i = gen.nextIndex;
      } catch (_) {
        i++;
      }
    }
    return null;
  }
}

class TrailerDictValues {
  TrailerDictValues({
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
