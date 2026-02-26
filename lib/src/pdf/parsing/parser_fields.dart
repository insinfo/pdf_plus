import 'dart:typed_data';

import 'pdf_document_info.dart';
import 'parser_misc.dart';
import 'parser_tokens.dart';

class PdfParserFields {
  static bool hasPdfHeader(Uint8List bytes) {
    const token = <int>[0x25, 0x50, 0x44, 0x46, 0x2D]; // %PDF-
    final limit = bytes.length > 1024 ? 1024 : bytes.length;
    return PdfParserTokens.indexOfSequence(bytes, token, 0, limit) != -1;
  }

  static double readPdfVersion(Uint8List bytes) {
    const token = <int>[0x25, 0x50, 0x44, 0x46, 0x2D]; // %PDF-
    final limit = bytes.length > 1024 ? 1024 : bytes.length;
    final pos = PdfParserTokens.indexOfSequence(bytes, token, 0, limit);
    if (pos == -1 || pos + 8 > limit) return 1.4;

    final major = bytes[pos + 5];
    final dot = bytes[pos + 6];
    final minor = bytes[pos + 7];
    if (dot != 0x2E /* . */) return 1.4;
    if (major < 0x30 || major > 0x39) return 1.4;
    if (minor < 0x30 || minor > 0x39) return 1.4;
    final majorVal = major - 0x30;
    final minorVal = minor - 0x30;
    return majorVal + (minorVal / 10.0);
  }

  static bool hasEofMarker(Uint8List bytes) {
    const token = <int>[0x25, 0x25, 0x45, 0x4F, 0x46]; // %%EOF
    final windowStart = bytes.length > 8 * 1024 ? bytes.length - 8 * 1024 : 0;
    return PdfParserTokens.lastIndexOfSequence(
          bytes,
          token,
          windowStart,
          bytes.length,
        ) !=
        -1;
  }

  static int findByteRangeToken(Uint8List bytes) {
    const token = <int>[
      0x2F, // /
      0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65, // ByteRange
    ];
    return PdfParserTokens.indexOfSequence(bytes, token, 0, bytes.length);
  }

  static int findEncryptToken(Uint8List bytes) {
    const token = <int>[
      0x2F, // /
      0x45, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, // Encrypt
    ];
    const trailerToken = <int>[
      0x74, 0x72, 0x61, 0x69, 0x6C, 0x65, 0x72, // trailer
    ];
    const xrefToken = <int>[
      0x78, 0x72, 0x65, 0x66, // xref
    ];
    const xrefTypeToken = <int>[
      0x2F, 0x54, 0x79, 0x70, 0x65, // /Type
      0x20,
      0x2F, 0x58, 0x52, 0x65, 0x66, // /XRef
    ];

    final windowStart =
        bytes.length > 2 * 1024 * 1024 ? bytes.length - 2 * 1024 * 1024 : 0;
    var offset = windowStart;
    while (offset < bytes.length) {
      final pos = PdfParserTokens.indexOfSequence(bytes, token, offset, bytes.length);
      if (pos == -1) break;

      final before = pos > 0 ? bytes[pos - 1] : 0x20;
      final afterIndex = pos + token.length;
      final after = afterIndex < bytes.length ? bytes[afterIndex] : 0x20;
      if (!_isNameBoundary(before) || !_isNameBoundary(after)) {
        offset = pos + token.length;
        continue;
      }

      final contextStart = pos > 4096 ? pos - 4096 : 0;
      final contextEnd = pos + 4096 < bytes.length ? pos + 4096 : bytes.length;
      final hasTrailer = PdfParserTokens.indexOfSequence(
            bytes,
            trailerToken,
            contextStart,
            contextEnd,
          ) !=
          -1;
      final hasXref = PdfParserTokens.indexOfSequence(
            bytes,
            xrefToken,
            contextStart,
            contextEnd,
          ) !=
          -1;
      final hasXrefType = PdfParserTokens.indexOfSequence(
            bytes,
            xrefTypeToken,
            contextStart,
            contextEnd,
          ) !=
          -1;
      if (hasTrailer || hasXref || hasXrefType) {
        return pos;
      }

      offset = pos + token.length;
    }
    return -1;
  }

  static bool hasEncryptDictionary(Uint8List bytes) =>
      findEncryptToken(bytes) != -1;

  static bool _isNameBoundary(int b) {
    if (PdfParserTokens.isWhitespace(b)) return true;
    switch (b) {
      case 0x00:
      case 0x2F: // /
      case 0x3C: // <
      case 0x3E: // >
      case 0x28: // (
      case 0x29: // )
      case 0x5B: // [
      case 0x5D: // ]
      case 0x7B: // {
      case 0x7D: // }
      case 0x25: // %
        return true;
      default:
        return false;
    }
  }

  static int? extractDocMdpPermissionFromBytes(Uint8List bytes) {
    const docMdpToken = <int>[
      0x2F, // /
      0x44, 0x6F, 0x63, 0x4D, 0x44, 0x50, // DocMDP
    ];
    const pToken = <int>[0x2F, 0x50]; // /P

    int offset = 0;
    while (offset < bytes.length) {
      final pos = PdfParserTokens.indexOfSequence(
        bytes,
        docMdpToken,
        offset,
        bytes.length,
      );
      if (pos == -1) break;
      final windowStart = pos;
      final windowEnd = (pos + 4096 < bytes.length) ? (pos + 4096) : bytes.length;
      final pPos = PdfParserTokens.indexOfSequence(
        bytes,
        pToken,
        windowStart,
        windowEnd,
      );
      if (pPos != -1) {
        try {
          int i = pPos + pToken.length;
          i = PdfParserTokens.skipPdfWsAndComments(bytes, i, windowEnd);
          final parsed = PdfParserTokens.readInt(bytes, i, windowEnd);
          if (parsed.value >= 1 && parsed.value <= 3) {
            return parsed.value;
          }
        } catch (_) {}
      }
      offset = pos + docMdpToken.length;
    }
    return null;
  }

  static List<PdfSignatureFieldInfo> extractSignatureFieldsFromBytes(
    Uint8List bytes,
  ) {
    final ranges = PdfParserMisc.findAllByteRangesFromBytes(bytes);
    if (ranges.isEmpty) return const <PdfSignatureFieldInfo>[];

    final out = <PdfSignatureFieldInfo>[];
    for (final range in ranges) {
      final gapStart = range[0] + range[1];
      final gapEnd = range[2];
      const windowSize = 524288;
      final windowStart = gapStart - windowSize >= 0 ? gapStart - windowSize : 0;
      final windowEnd = gapEnd + windowSize <= bytes.length
          ? gapEnd + windowSize
          : bytes.length;
      final window = bytes.sublist(windowStart, windowEnd);

      final fieldName = PdfParserMisc.scanPdfStringValue(window, const <int>[
        0x2F, 0x54 // /T
      ]);
      final reason = PdfParserMisc.scanPdfStringValue(window, const <int>[
        0x2F, 0x52, 0x65, 0x61, 0x73, 0x6F, 0x6E // /Reason
      ]);
      final location = PdfParserMisc.scanPdfStringValue(window, const <int>[
        0x2F, 0x4C, 0x6F, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E // /Location
      ]);
      final name = PdfParserMisc.scanPdfStringValue(window, const <int>[
        0x2F, 0x4E, 0x61, 0x6D, 0x65 // /Name
      ]);
      final signingTime = PdfParserMisc.scanPdfStringValue(window, const <int>[
        0x2F, 0x4D // /M
      ]);
      final filter = PdfParserMisc.scanPdfNameValue(window, const <int>[
        0x2F, 0x46, 0x69, 0x6C, 0x74, 0x65, 0x72 // /Filter
      ]);
      final subFilter = PdfParserMisc.scanPdfNameValue(window, const <int>[
        0x2F, 0x53, 0x75, 0x62, 0x46, 0x69, 0x6C, 0x74, 0x65, 0x72 // /SubFilter
      ]);

      out.add(PdfSignatureFieldInfo(
        fieldName: fieldName,
        reason: reason,
        location: location,
        name: name,
        signingTimeRaw: signingTime,
        filter: filter,
        subFilter: subFilter,
        byteRange: range,
        signatureDictionaryPresent: true,
      ));
    }
    return out;
  }
}
