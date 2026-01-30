import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../document.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/name.dart';
import '../format/num.dart';
import '../format/object_base.dart';
import '../format/stream.dart';
import '../format/string.dart';
import '../graphics.dart';
import '../parsing/pdf_document_parser.dart';
import '../obj/annotation.dart';
import '../obj/object.dart';
import '../obj/signature.dart';
import '../rect.dart';
import 'pdf_signature_config.dart';

class PdfExternalSigningPrepared {
  const PdfExternalSigningPrepared({
    required this.preparedPdfBytes,
    required this.byteRange,
    required this.hashBase64,
  });

  final Uint8List preparedPdfBytes;
  final List<int> byteRange;
  final String hashBase64;
}

/// Utilitários para assinatura externa (prepare + embed).
class PdfExternalSigning {
  static bool useInternalByteRangeParser = true;
  static bool useInternalContentsParser = true;

  /// Prepara o PDF com placeholder de assinatura e retorna ByteRange + hash.
  static Future<PdfExternalSigningPrepared> preparePdf({
    required Uint8List inputBytes,
    required int pageNumber,
    required PdfRect bounds,
    required String fieldName,
    PdfSignatureConfig? signature,
    List<List<int>> publicCertificates = const <List<int>>[],
    void Function(PdfGraphics graphics, PdfRect bounds)? drawAppearance,
    int contentsReserveSize = 16384,
    int byteRangeDigits = 10,
  }) async {
    publicCertificates = publicCertificates;
    final parser = PdfDocumentParser(inputBytes);
    final document = PdfDocument.load(parser);

    final pageIndex = pageNumber - 1;
    if (pageIndex < 0 || pageIndex >= document.pdfPageList.pages.length) {
      throw RangeError.index(pageIndex, document.pdfPageList.pages, 'pageNumber');
    }

    final placeholder = _PdfExternalSignaturePlaceholder(
      signature: signature,
      contentsReserveSize: contentsReserveSize,
      byteRangeDigits: byteRangeDigits,
    );

    document.sign = PdfSignature(
      document,
      value: placeholder,
      flags: {PdfSigFlags.signaturesExist, PdfSigFlags.appendOnly},
    );

    final page = document.pdfPageList.pages[pageIndex];
    final annot = PdfAnnotSign(rect: bounds, fieldName: fieldName);
    if (drawAppearance != null) {
      final g = annot.appearance(document, PdfAnnotAppearance.normal);
      final localBounds = PdfRect(0, 0, bounds.width, bounds.height);
      drawAppearance(g, localBounds);
    }
    PdfAnnot(page, annot);

    final preparedBytes = await document.save(useIsolate: false);
    final byteRange = placeholder.byteRange;
    final hashBytes = placeholder.hashBytes;
    if (byteRange == null || hashBytes == null) {
      throw StateError('Falha ao preparar assinatura externa (ByteRange).');
    }

    return PdfExternalSigningPrepared(
      preparedPdfBytes: Uint8List.fromList(preparedBytes),
      byteRange: byteRange,
      hashBase64: base64.encode(hashBytes),
    );
  }

  /// Embute PKCS#7 no placeholder /Contents.
  static Uint8List embedSignature({
    required Uint8List preparedPdfBytes,
    required Uint8List pkcs7Bytes,
  }) {
    final range = _findLastByteRange(preparedPdfBytes);
    if (range == null) {
      throw StateError('ByteRange não encontrado para embed da assinatura.');
    }

    final gapStart = range[0] + range[1];
    final gapEnd = range[2];
    if (gapStart < 0 || gapEnd <= gapStart || gapEnd > preparedPdfBytes.length) {
      throw StateError('ByteRange inválido no PDF preparado.');
    }

    int lt = -1;
    for (int i = gapStart; i < gapEnd; i++) {
      if (preparedPdfBytes[i] == 0x3C /* < */) {
        lt = i;
        break;
      }
    }
    if (lt == -1) {
      throw StateError('Delimitador < de /Contents não encontrado.');
    }

    int gt = -1;
    for (int i = lt + 1; i < gapEnd; i++) {
      if (preparedPdfBytes[i] == 0x3E /* > */) {
        gt = i;
        break;
      }
    }
    if (gt == -1 || gt <= lt) {
      throw StateError('Delimitador > de /Contents não encontrado.');
    }

    final bytes = Uint8List.fromList(preparedPdfBytes);
    _embedSignature(bytes, lt + 1, gt, pkcs7Bytes);
    return bytes;
  }
}

class _PdfExternalSignaturePlaceholder extends PdfSignatureBase {
  _PdfExternalSignaturePlaceholder({
    required this.signature,
    required this.contentsReserveSize,
    required this.byteRangeDigits,
  });

  final PdfSignatureConfig? signature;
  final int contentsReserveSize;
  final int byteRangeDigits;

  List<int>? byteRange;
  Uint8List? hashBytes;

  @override
  bool get hasMDP => signature?.docMdpPermissionP != null;

  @override
  void preSign(PdfObject object, PdfDict params) {
    params['/Filter'] = const PdfName('/Adobe.PPKLite');
    params['/SubFilter'] = const PdfName('/adbe.pkcs7.detached');
    params['/ByteRange'] = _PdfByteRangePlaceholder(digits: byteRangeDigits);
    params['/Contents'] = PdfString(
      Uint8List(contentsReserveSize),
      format: PdfStringFormat.binary,
      encrypted: false,
    );

    final when = (signature?.signingTime ?? DateTime.now()).toUtc();
    params['/M'] = PdfString.fromDate(when, encrypted: false);
    if (signature?.reason != null) {
      params['/Reason'] = PdfString.fromString(signature!.reason!);
    }
    if (signature?.location != null) {
      params['/Location'] = PdfString.fromString(signature!.location!);
    }
    if (signature?.contactInfo != null) {
      params['/ContactInfo'] = PdfString.fromString(signature!.contactInfo!);
    }
    if (signature?.name != null) {
      params['/Name'] = PdfString.fromString(signature!.name!);
    }

    final p = signature?.docMdpPermissionP;
    if (p != null) {
      params['/Reference'] = PdfArray<PdfDataType>([
        PdfDict.values({
          '/Type': const PdfName('/SigRef'),
          '/TransformMethod': const PdfName('/DocMDP'),
          '/DigestMethod': const PdfName('/SHA256'),
          '/TransformParams': PdfDict.values({
            '/Type': const PdfName('/TransformParams'),
            '/P': PdfNum(p),
            '/V': const PdfName('/1.2'),
          }),
        })
      ]);
    }
  }

  @override
  Future<void> sign(
    PdfObject object,
    PdfStream os,
    PdfDict params,
    int? offsetStart,
    int? offsetEnd,
  ) async {
    if (offsetStart == null || offsetEnd == null) {
      throw StateError('Offsets de assinatura inválidos.');
    }

    final bytes = os.output();
    final contentsRange = _findContentsRange(bytes, offsetStart, offsetEnd);
    final range = <int>[
      0,
      contentsRange.lt,
      contentsRange.gt + 1,
      bytes.length - (contentsRange.gt + 1),
    ];

    _writeByteRange(bytes, offsetStart, offsetEnd, range);
    byteRange = range;
    hashBytes = _computeByteRangeDigest(bytes, range);
    os.setBytes(0, bytes);
  }
}

class _PdfByteRangePlaceholder extends PdfDataType {
  const _PdfByteRangePlaceholder({required this.digits});

  final int digits;

  @override
  void output(PdfObjectBase o, PdfStream s, [int? indent]) {
    final zero = '0'.padLeft(digits, '0');
    s.putByte(0x5B); // [
    s.putString('$zero $zero $zero $zero');
    s.putByte(0x5D); // ]
  }
}

class _ContentsRange {
  _ContentsRange(this.lt, this.gt);
  final int lt;
  final int gt;

  int get start => lt + 1;
  int get end => gt;
}

_ContentsRange _findContentsRange(
  Uint8List bytes,
  int start,
  int end,
) {
  const contentsToken = <int>[
    0x2F, // /
    0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x73, // Contents
  ];

  final contentsPos = _indexOfSequence(bytes, contentsToken, start, end);
  if (contentsPos == -1) {
    throw StateError('Não foi possível localizar /Contents na assinatura.');
  }

  int lt = -1;
  for (int i = contentsPos + contentsToken.length; i < end; i++) {
    if (bytes[i] == 0x3C /* < */) {
      lt = i;
      break;
    }
  }
  if (lt == -1) {
    throw StateError('Delimitador < de /Contents não encontrado.');
  }

  int gt = -1;
  for (int i = lt + 1; i < end; i++) {
    if (bytes[i] == 0x3E /* > */) {
      gt = i;
      break;
    }
  }
  if (gt == -1 || gt <= lt) {
    throw StateError('Delimitador > de /Contents não encontrado.');
  }

  return _ContentsRange(lt, gt);
}

void _writeByteRange(
  Uint8List bytes,
  int start,
  int end,
  List<int> range,
) {
  const byteRangeToken = <int>[
    0x2F, // /
    0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65, // ByteRange
  ];

  final pos = _indexOfSequence(bytes, byteRangeToken, start, end);
  if (pos == -1) {
    throw StateError('Não foi possível localizar /ByteRange na assinatura.');
  }

  int i = pos + byteRangeToken.length;
  while (i < end && bytes[i] != 0x5B /* [ */) {
    i++;
  }
  if (i >= end) {
    throw StateError('Abertura [ do /ByteRange não encontrada.');
  }
  final bracketStart = i;
  int bracketEnd = -1;
  for (int j = bracketStart + 1; j < end; j++) {
    if (bytes[j] == 0x5D /* ] */) {
      bracketEnd = j;
      break;
    }
  }
  if (bracketEnd == -1) {
    throw StateError('Fechamento ] do /ByteRange não encontrado.');
  }

  final width = ((bracketEnd - bracketStart - 1) - 3) ~/ 4;
  if (width <= 0) {
    throw StateError('Placeholder de ByteRange inválido.');
  }

  final parts = range
      .map((v) => v.toString().padLeft(width, '0'))
      .toList(growable: false);
  final replacement = parts.join(' ');
  final repBytes = ascii.encode(replacement);
  if (repBytes.length > bracketEnd - bracketStart - 1) {
    throw StateError('ByteRange excede espaço reservado.');
  }

  bytes.setRange(bracketStart + 1, bracketStart + 1 + repBytes.length, repBytes);
  for (int k = bracketStart + 1 + repBytes.length; k < bracketEnd; k++) {
    bytes[k] = 0x20; // espaço
  }
}

Uint8List _computeByteRangeDigest(Uint8List bytes, List<int> range) {
  if (range.length != 4) {
    throw ArgumentError('ByteRange inválido.');
  }
  final start1 = range[0];
  final len1 = range[1];
  final start2 = range[2];
  final len2 = range[3];

  final part1 = bytes.sublist(start1, start1 + len1);
  final part2 = bytes.sublist(start2, start2 + len2);
  final digest = crypto.sha256.convert(<int>[...part1, ...part2]);
  return Uint8List.fromList(digest.bytes);
}

void _embedSignature(
  Uint8List bytes,
  int start,
  int end,
  Uint8List cms,
) {
  final available = end - start;
  var hex = _bytesToHex(cms).toUpperCase();
  if (hex.length.isOdd) {
    hex = '0$hex';
  }
  if (hex.length > available) {
    throw StateError('CMS maior que o espaço reservado em /Contents.');
  }
  final sigBytes = ascii.encode(hex);
  bytes.setRange(start, start + sigBytes.length, sigBytes);
  for (int i = start + sigBytes.length; i < end; i++) {
    bytes[i] = 0x30; // '0'
  }
}

String _bytesToHex(List<int> bytes) {
  final buffer = StringBuffer();
  for (final b in bytes) {
    buffer.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
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

List<int>? _findLastByteRange(Uint8List bytes) {
  const token = <int>[
    0x2F, // /
    0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65, // ByteRange
  ];

  final pos = _lastIndexOfSequence(bytes, token, 0, bytes.length);
  if (pos == -1) return null;
  final parsed = _parseByteRangeAt(bytes, pos + token.length);
  return parsed;
}

int _lastIndexOfSequence(Uint8List bytes, List<int> pattern, int start, int end) {
  if (pattern.isEmpty) return -1;
  final int max = end - pattern.length;
  for (int i = max; i >= start; i--) {
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

List<int>? _parseByteRangeAt(Uint8List bytes, int start) {
  int i = _skipPdfWsAndComments(bytes, start, bytes.length);
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

  return values;
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
