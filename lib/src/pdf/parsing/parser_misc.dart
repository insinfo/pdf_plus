import 'dart:typed_data';

import '../io/pdf_random_access_reader.dart';
import 'parser_tokens.dart';

class PdfParserMisc {
  static List<List<int>> findAllByteRangesFromBytes(Uint8List bytes) {
    const token = <int>[
      0x2F, 0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65
    ];
    final out = <List<int>>[];
    var offset = 0;
    while (offset < bytes.length) {
      final pos = PdfParserTokens.indexOfSequence(bytes, token, offset, bytes.length);
      if (pos == -1) break;
      var i = PdfParserTokens.skipPdfWsAndComments(
        bytes,
        pos + token.length,
        bytes.length,
      );
      if (i >= bytes.length || bytes[i] != 0x5B) {
        offset = pos + token.length;
        continue;
      }
      i++;
      final nums = <int>[];
      while (i < bytes.length && nums.length < 4) {
        i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
        if (i >= bytes.length) break;
        if (bytes[i] == 0x5D) {
          i++;
          break;
        }
        try {
          final parsed = PdfParserTokens.readInt(bytes, i, bytes.length);
          nums.add(parsed.value);
          i = parsed.nextIndex;
        } catch (_) {
          i++;
        }
      }
      if (nums.length == 4) {
        out.add(nums);
      }
      offset = pos + token.length;
    }
    return out;
  }

  static String? scanPdfStringValue(Uint8List bytes, List<int> key) {
    final pos = PdfParserTokens.indexOfSequence(bytes, key, 0, bytes.length);
    if (pos == -1) return null;
    var i = PdfParserTokens.skipPdfWsAndComments(
      bytes,
      pos + key.length,
      bytes.length,
    );
    if (i >= bytes.length) return null;
    if (bytes[i] == 0x28) {
      final parsed = PdfParserTokens.readLiteralString(bytes, i, bytes.length);
      return PdfParserTokens.decodePdfString(parsed.bytes);
    }
    if (bytes[i] == 0x3C) {
      try {
        final hex = PdfParserTokens.readHexString(bytes, i, bytes.length);
        return PdfParserTokens.decodePdfString(hex.bytes);
      } catch (_) {
        return null;
      }
    }
    if (bytes[i] == 0x2F) {
      i++;
      final start = i;
      while (i < bytes.length &&
          !PdfParserTokens.isWhitespace(bytes[i]) &&
          bytes[i] != 0x2F &&
          bytes[i] != 0x3E &&
          bytes[i] != 0x3C &&
          bytes[i] != 0x28 &&
          bytes[i] != 0x29 &&
          bytes[i] != 0x5B &&
          bytes[i] != 0x5D) {
        i++;
      }
      return String.fromCharCodes(bytes.sublist(start, i));
    }
    return null;
  }

  static String? scanPdfNameValue(Uint8List bytes, List<int> key) {
    final pos = PdfParserTokens.indexOfSequence(bytes, key, 0, bytes.length);
    if (pos == -1) return null;
    var i = PdfParserTokens.skipPdfWsAndComments(
      bytes,
      pos + key.length,
      bytes.length,
    );
    if (i >= bytes.length || bytes[i] != 0x2F) return null;
    i++;
    final start = i;
    while (i < bytes.length &&
        !PdfParserTokens.isWhitespace(bytes[i]) &&
        bytes[i] != 0x2F &&
        bytes[i] != 0x3E &&
        bytes[i] != 0x3C &&
        bytes[i] != 0x28 &&
        bytes[i] != 0x29 &&
        bytes[i] != 0x5B &&
        bytes[i] != 0x5D) {
      i++;
    }
    if (i <= start) return null;
    return '/' + String.fromCharCodes(bytes.sublist(start, i));
  }

  static int maxObjectId(Uint8List bytes) {
    var maxId = 0;
    var i = 0;
    while (i < bytes.length) {
      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length) break;

      // Object number.
      if (!PdfParserTokens.isDigit(bytes[i])) {
        i++;
        continue;
      }
      final objNum = PdfParserTokens.readInt(bytes, i, bytes.length);
      i = objNum.nextIndex;

      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length || !PdfParserTokens.isDigit(bytes[i])) {
        continue;
      }
      final genNum = PdfParserTokens.readInt(bytes, i, bytes.length);
      i = genNum.nextIndex;

      i = PdfParserTokens.skipPdfWsAndComments(bytes, i, bytes.length);
      if (i + 2 < bytes.length &&
          bytes[i] == 0x6F &&
          bytes[i + 1] == 0x62 &&
          bytes[i + 2] == 0x6A &&
          PdfParserTokens.isDelimiter(bytes, i + 3)) {
        if (objNum.value > maxId) {
          maxId = objNum.value;
        }
      }
    }
    return maxId;
  }

  static int maxObjectIdFromReader(PdfRandomAccessReader reader) {
    if (reader is PdfMemoryRandomAccessReader) {
      return maxObjectId(reader.readAll());
    }

    const chunkSize = 1024 * 1024;
    const overlap = 64;
    int offset = 0;
    int maxId = 0;

    while (offset < reader.length) {
      final windowSize = (offset + chunkSize > reader.length)
          ? (reader.length - offset)
          : chunkSize;
      final window = reader.readRange(offset, windowSize);
      int i = 0;

      while (i < window.length) {
        i = PdfParserTokens.skipPdfWsAndComments(window, i, window.length);
        if (i >= window.length) break;

        if (!PdfParserTokens.isDigit(window[i])) {
          i++;
          continue;
        }
        try {
          final objNum = PdfParserTokens.readInt(window, i, window.length);
          i = objNum.nextIndex;
          i = PdfParserTokens.skipPdfWsAndComments(window, i, window.length);
          if (i >= window.length || !PdfParserTokens.isDigit(window[i])) continue;
          final genNum = PdfParserTokens.readInt(window, i, window.length);
          i = genNum.nextIndex;
          i = PdfParserTokens.skipPdfWsAndComments(window, i, window.length);
          if (PdfParserTokens.matchToken(
              window, i, const <int>[0x6F, 0x62, 0x6A])) {
            if (objNum.value > maxId) maxId = objNum.value;
          }
        } catch (_) {
          i++;
        }
      }

      if (offset + chunkSize >= reader.length) break;
      offset += chunkSize - overlap;
    }

    return maxId;
  }
}
