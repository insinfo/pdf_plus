import 'dart:typed_data';

import 'pdf_document_info.dart';
import 'parser_tokens.dart';

double readPdfVersion(Uint8List bytes) {
  const token = <int>[0x25, 0x50, 0x44, 0x46, 0x2D]; // %PDF-
  final limit = bytes.length > 1024 ? 1024 : bytes.length;
  final pos = indexOfSequence(bytes, token, 0, limit);
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

int findByteRangeToken(Uint8List bytes) {
  const token = <int>[
    0x2F, // /
    0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65, // ByteRange
  ];
  return indexOfSequence(bytes, token, 0, bytes.length);
}

int? extractDocMdpPermissionFromBytes(Uint8List bytes) {
  const docMdpToken = <int>[
    0x2F, // /
    0x44, 0x6F, 0x63, 0x4D, 0x44, 0x50, // DocMDP
  ];
  const pToken = <int>[0x2F, 0x50]; // /P

  int offset = 0;
  while (offset < bytes.length) {
    final pos = indexOfSequence(bytes, docMdpToken, offset, bytes.length);
    if (pos == -1) break;
    final windowStart = pos;
    final windowEnd = (pos + 4096 < bytes.length) ? (pos + 4096) : bytes.length;
    final pPos = indexOfSequence(bytes, pToken, windowStart, windowEnd);
    if (pPos != -1) {
      try {
        int i = pPos + pToken.length;
        i = skipPdfWsAndComments(bytes, i, windowEnd);
        final parsed = readInt(bytes, i, windowEnd);
        if (parsed.value >= 1 && parsed.value <= 3) {
          return parsed.value;
        }
      } catch (_) {}
    }
    offset = pos + docMdpToken.length;
  }
  return null;
}

List<PdfSignatureFieldInfo> extractSignatureFieldsFromBytes(Uint8List bytes) {
  final ranges = findAllByteRangesFromBytes(bytes);
  if (ranges.isEmpty) return const <PdfSignatureFieldInfo>[];

  final out = <PdfSignatureFieldInfo>[];
  for (final range in ranges) {
    final gapStart = range[0] + range[1];
    final gapEnd = range[2];
    const windowSize = 524288;
    final windowStart = gapStart - windowSize >= 0 ? gapStart - windowSize : 0;
    final windowEnd = gapEnd + windowSize <= bytes.length ? gapEnd + windowSize : bytes.length;
    final window = bytes.sublist(windowStart, windowEnd);

    final fieldName = scanPdfStringValue(window, const <int>[
      0x2F, 0x54 // /T
    ]);
    final reason = scanPdfStringValue(window, const <int>[
      0x2F, 0x52, 0x65, 0x61, 0x73, 0x6F, 0x6E // /Reason
    ]);
    final location = scanPdfStringValue(window, const <int>[
      0x2F, 0x4C, 0x6F, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E // /Location
    ]);
    final name = scanPdfStringValue(window, const <int>[
      0x2F, 0x4E, 0x61, 0x6D, 0x65 // /Name
    ]);
    final signingTime = scanPdfStringValue(window, const <int>[
      0x2F, 0x4D // /M
    ]);
    final filter = scanPdfNameValue(window, const <int>[
      0x2F, 0x46, 0x69, 0x6C, 0x74, 0x65, 0x72 // /Filter
    ]);
    final subFilter = scanPdfNameValue(window, const <int>[
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

List<List<int>> findAllByteRangesFromBytes(Uint8List bytes) {
  const token = <int>[
    0x2F, 0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65
  ];
  final out = <List<int>>[];
  var offset = 0;
  while (offset < bytes.length) {
    final pos = indexOfSequence(bytes, token, offset, bytes.length);
    if (pos == -1) break;
    var i = skipPdfWsAndComments(bytes, pos + token.length, bytes.length);
    if (i >= bytes.length || bytes[i] != 0x5B) {
      offset = pos + token.length;
      continue;
    }
    i++;
    final nums = <int>[];
    while (i < bytes.length && nums.length < 4) {
      i = skipPdfWsAndComments(bytes, i, bytes.length);
      if (i >= bytes.length) break;
      if (bytes[i] == 0x5D) {
        i++;
        break;
      }
      try {
        final parsed = readInt(bytes, i, bytes.length);
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

String? scanPdfStringValue(Uint8List bytes, List<int> key) {
  final pos = indexOfSequence(bytes, key, 0, bytes.length);
  if (pos == -1) return null;
  var i = skipPdfWsAndComments(bytes, pos + key.length, bytes.length);
  if (i >= bytes.length) return null;
  if (bytes[i] == 0x28) {
    final parsed = readLiteralString(bytes, i, bytes.length);
    return decodePdfString(parsed.bytes);
  }
  if (bytes[i] == 0x3C) {
    try {
      final hex = readHexString(bytes, i, bytes.length);
      return decodePdfString(hex.bytes);
    } catch (_) {
      return null;
    }
  }
  if (bytes[i] == 0x2F) {
    i++;
    final start = i;
    while (i < bytes.length &&
        !isWhitespace(bytes[i]) &&
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

String? scanPdfNameValue(Uint8List bytes, List<int> key) {
  final pos = indexOfSequence(bytes, key, 0, bytes.length);
  if (pos == -1) return null;
  var i = skipPdfWsAndComments(bytes, pos + key.length, bytes.length);
  if (i >= bytes.length || bytes[i] != 0x2F) return null;
  i++;
  final start = i;
  while (i < bytes.length &&
      !isWhitespace(bytes[i]) &&
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
