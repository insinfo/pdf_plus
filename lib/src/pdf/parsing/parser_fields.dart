import 'dart:typed_data';

import 'pdf_document_info.dart';
import 'parser_misc.dart';
import 'parser_tokens.dart';

class PdfParserFields {
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

  static int findByteRangeToken(Uint8List bytes) {
    const token = <int>[
      0x2F, // /
      0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65, // ByteRange
    ];
    return PdfParserTokens.indexOfSequence(bytes, token, 0, bytes.length);
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
