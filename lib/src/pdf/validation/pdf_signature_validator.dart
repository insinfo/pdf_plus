import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart' as crypto;

class PdfSignatureValidationResult {
  const PdfSignatureValidationResult({
    required this.signatureIndex,
    required this.cmsValid,
    required this.digestValid,
    required this.intact,
    this.message,
  });

  final int signatureIndex;
  final bool cmsValid;
  final bool digestValid;
  final bool intact;
  final String? message;
}

/// Validador básico de assinaturas (PAdES).
class PdfSignatureValidator {
  /// Valida todas as assinaturas do PDF.
  Future<List<PdfSignatureValidationResult>> validateAllSignatures(
    Uint8List pdfBytes, {
    List<Uint8List>? trustedRoots,
  }) async {
    trustedRoots = trustedRoots;
    final ranges = _findAllByteRanges(pdfBytes);
    final results = <PdfSignatureValidationResult>[];

    for (var i = 0; i < ranges.length; i++) {
      final range = ranges[i];
      final intact = _isValidByteRange(pdfBytes.length, range);
      var cmsValid = false;
      var digestValid = false;
      String? message;

      if (!intact) {
        results.add(PdfSignatureValidationResult(
          signatureIndex: i,
          cmsValid: false,
          digestValid: false,
          intact: false,
          message: 'ByteRange inconsistente.',
        ));
        continue;
      }

      final contents = _extractContentsFromByteRange(pdfBytes, range);
      if (contents == null || contents.isEmpty) {
        results.add(PdfSignatureValidationResult(
          signatureIndex: i,
          cmsValid: false,
          digestValid: false,
          intact: true,
          message: 'Conteúdo de assinatura ausente ou inválido.',
        ));
        continue;
      }

      cmsValid = _isValidDerSequence(contents);
      final contentDigest = _computeByteRangeDigest(pdfBytes, range);
      final messageDigest = _extractMessageDigest(contents);
      if (messageDigest != null) {
        digestValid = _listEquals(contentDigest, messageDigest);
      } else {
        message = 'Atributo messageDigest não encontrado no CMS.';
      }

      results.add(PdfSignatureValidationResult(
        signatureIndex: i,
        cmsValid: cmsValid,
        digestValid: digestValid,
        intact: true,
        message: message,
      ));
    }

    return results;
  }
}

List<List<int>> _findAllByteRanges(Uint8List bytes) {
  const token = <int>[
    0x2F, // /
    0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65, // ByteRange
  ];

  final ranges = <List<int>>[];
  var offset = 0;
  while (true) {
    final pos = _indexOfSequence(bytes, token, offset, bytes.length);
    if (pos == -1) break;
    final parsed = _parseByteRangeAt(bytes, pos + token.length);
    if (parsed != null) {
      ranges.add(parsed.range);
      offset = parsed.nextIndex;
    } else {
      offset = pos + token.length;
    }
  }
  return ranges;
}

({List<int> range, int nextIndex})? _parseByteRangeAt(
  Uint8List bytes,
  int start,
) {
  int i = _skipPdfWsAndComments(bytes, start, bytes.length);
  // buscar '['
  while (i < bytes.length && bytes[i] != 0x5B /* [ */) {
    i++;
  }
  if (i >= bytes.length) return null;
  i++;

  final values = <int>[];
  for (int k = 0; k < 4; k++) {
    i = _skipPdfWsAndComments(bytes, i, bytes.length);
    final parsed = _readInt(bytes, i, bytes.length);
    values.add(parsed.value);
    i = parsed.nextIndex;
  }

  return (range: values, nextIndex: i);
}

bool _isValidByteRange(int fileLength, List<int> range) {
  if (range.length != 4) return false;
  final start1 = range[0];
  final len1 = range[1];
  final start2 = range[2];
  final len2 = range[3];
  if (start1 < 0 || len1 < 0 || start2 < 0 || len2 < 0) return false;
  if (start1 + len1 > fileLength) return false;
  if (start2 + len2 > fileLength) return false;
  if (start2 < start1 + len1) return false;
  return true;
}

Uint8List _computeByteRangeDigest(Uint8List bytes, List<int> range) {
  final start1 = range[0];
  final len1 = range[1];
  final start2 = range[2];
  final len2 = range[3];
  final part1 = bytes.sublist(start1, start1 + len1);
  final part2 = bytes.sublist(start2, start2 + len2);
  final digest = crypto.sha256.convert(<int>[...part1, ...part2]);
  return Uint8List.fromList(digest.bytes);
}

Uint8List? _extractContentsFromByteRange(
  Uint8List bytes,
  List<int> range,
) {
  final gapStart = range[0] + range[1];
  final gapEnd = range[2];
  if (gapStart < 0 || gapEnd <= gapStart || gapEnd > bytes.length) {
    return null;
  }

  int lt = -1;
  for (int i = gapStart; i < gapEnd; i++) {
    if (bytes[i] == 0x3C /* < */) {
      lt = i;
      break;
    }
  }
  if (lt == -1) return null;
  int gt = -1;
  for (int i = lt + 1; i < gapEnd; i++) {
    if (bytes[i] == 0x3E /* > */) {
      gt = i;
      break;
    }
  }
  if (gt == -1 || gt <= lt) return null;

  final hex = bytes.sublist(lt + 1, gt);
  final cleaned = <int>[];
  for (final b in hex) {
    if (b == 0x20 || b == 0x0A || b == 0x0D || b == 0x09) continue;
    cleaned.add(b);
  }
  if (cleaned.length.isOdd) return null;
  return _hexToBytes(cleaned);
}

bool _isValidDerSequence(Uint8List bytes) {
  if (bytes.isEmpty || bytes.first != 0x30) return false;
  try {
    final obj = ASN1Parser(bytes).nextObject();
    return obj is ASN1Sequence;
  } catch (_) {
    return false;
  }
}

Uint8List? _extractMessageDigest(Uint8List cmsBytes) {
  final oid = ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.9.4')
      .encodedBytes;
  final pos = _indexOfSequence(cmsBytes, oid, 0, cmsBytes.length);
  if (pos == -1) return null;

  // procurar próximo OCTET STRING (0x04)
  int i = pos + oid.length;
  while (i < cmsBytes.length && cmsBytes[i] != 0x04) {
    i++;
  }
  if (i >= cmsBytes.length) return null;
  i++;
  if (i >= cmsBytes.length) return null;

  final lenByte = cmsBytes[i++];
  int length = 0;
  if ((lenByte & 0x80) == 0) {
    length = lenByte;
  } else {
    final lenLen = lenByte & 0x7F;
    if (i + lenLen > cmsBytes.length) return null;
    for (int k = 0; k < lenLen; k++) {
      length = (length << 8) | cmsBytes[i++];
    }
  }
  if (i + length > cmsBytes.length) return null;
  return cmsBytes.sublist(i, i + length);
}

Uint8List _hexToBytes(List<int> hexBytes) {
  final out = Uint8List(hexBytes.length ~/ 2);
  for (int i = 0; i < hexBytes.length; i += 2) {
    final hi = _hexValue(hexBytes[i]);
    final lo = _hexValue(hexBytes[i + 1]);
    if (hi < 0 || lo < 0) {
      throw FormatException('Hex inválido em /Contents.');
    }
    out[i ~/ 2] = (hi << 4) | lo;
  }
  return out;
}

int _hexValue(int b) {
  if (b >= 0x30 && b <= 0x39) return b - 0x30;
  if (b >= 0x41 && b <= 0x46) return b - 0x41 + 10;
  if (b >= 0x61 && b <= 0x66) return b - 0x61 + 10;
  return -1;
}

int _indexOfSequence(Uint8List bytes, List<int> pattern, int start, int end) {
  if (pattern.isEmpty) return -1;
  final max = end - pattern.length;
  for (int i = start; i <= max; i++) {
    var ok = true;
    for (int j = 0; j < pattern.length; j++) {
      if (bytes[i + j] != pattern[j]) {
        ok = false;
        break;
      }
    }
    if (ok) return i;
  }
  return -1;
}

int _skipPdfWsAndComments(Uint8List bytes, int i, int end) {
  while (i < end) {
    final b = bytes[i];
    if (b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0C || b == 0x0D || b == 0x20) {
      i++;
      continue;
    }
    if (b == 0x25 /* % */) {
      i++;
      while (i < end) {
        final c = bytes[i];
        if (c == 0x0A || c == 0x0D) break;
        i++;
      }
      continue;
    }
    break;
  }
  return i;
}

({int value, int nextIndex}) _readInt(Uint8List bytes, int i, int end) {
  if (i >= end) throw StateError('Fim inesperado ao ler inteiro');
  var neg = false;
  if (bytes[i] == 0x2D /* - */) {
    neg = true;
    i++;
  }
  var value = 0;
  var digits = 0;
  while (i < end) {
    final b = bytes[i];
    if (b < 0x30 || b > 0x39) break;
    value = (value * 10) + (b - 0x30);
    i++;
    digits++;
  }
  if (digits == 0) throw StateError('Inteiro inválido');
  return (value: neg ? -value : value, nextIndex: i);
}

bool _listEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
