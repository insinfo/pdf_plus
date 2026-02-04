//C:\MyDartProjects\pdf_plus\lib\src\pdf\signing\pdf_external_signing.dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/sha256.dart';

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
import '../obj/graphic_stream.dart';
import '../obj/object.dart';
import '../obj/signature.dart';
import '../rect.dart';
import 'pdf_signature_config.dart';
import 'package:pdf_plus/src/pdf/pdf_names.dart';

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
  static bool useInternalByteRangeParser = false;
  static bool useFastByteRangeParser = true;
  static bool useInternalContentsParser = false;
  static bool useFastContentsParser = true;

  static const List<int> _byteRangeToken = <int>[
    0x2F, // /
    0x42, 0x79, 0x74, 0x65, // Byte
    0x52, 0x61, 0x6E, 0x67, 0x65, // Range
  ];

  static const List<int> _contentsToken = <int>[
    0x2F, // /
    0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x73, // Contents
  ];

  static const int _minContentsHexDigits = 64;

  static Uint8List computeByteRangeDigest(
    Uint8List pdfBytes,
    List<int> byteRange,
  ) {
    return _computeByteRangeDigest(pdfBytes, byteRange);
  }

  static String computeByteRangeHashBase64(
    Uint8List pdfBytes,
    List<int> byteRange,
  ) {
    return base64.encode(computeByteRangeDigest(pdfBytes, byteRange));
  }

  static List<int> extractByteRange(Uint8List pdfBytes) {
    if (useInternalByteRangeParser) {
      return _extractByteRangeInternal(pdfBytes);
    }

    if (useFastByteRangeParser) {
      try {
        final range = _extractByteRangeFast(pdfBytes);
        if (_isValidByteRange(pdfBytes.length, range)) {
          return range;
        }
      } catch (e) {
        if (e is StateError && e.message == 'ByteRange not found') {
          throw e;
        }
      }
    }

    try {
      final range = _extractByteRangeStringSearch(pdfBytes);
      if (_isValidByteRange(pdfBytes.length, range)) {
        return range;
      }
    } catch (_) {
      // fall through
    }

    final range = _extractByteRangeInternal(pdfBytes);
    if (!_isValidByteRange(pdfBytes.length, range)) {
      throw StateError('ByteRange encontrado mas inconsistente.');
    }
    return range;
  }

  static _ContentsRange findContentsRange(
    Uint8List pdfBytes, {
    bool strict = true,
  }) {
    if (useInternalContentsParser) {
      return _findContentsRangeInternal(pdfBytes);
    }

    if (useFastContentsParser) {
      try {
        final range = _findContentsRangeFast(pdfBytes);
        if ((strict && _isValidContentsRange(pdfBytes, range)) ||
            (!strict && _isPlausibleRange(pdfBytes, range))) {
          return range;
        }
      } catch (e) {
        if (e is StateError && e.message == 'ByteRange not found') {
          throw e;
        }
      }
    }

    try {
      final range = _findContentsRangeStringSearch(pdfBytes);
      if ((strict && _isValidContentsRange(pdfBytes, range)) ||
          (!strict && _isPlausibleRange(pdfBytes, range))) {
        return range;
      }
    } catch (_) {
      // fall through
    }

    final range = _findContentsRangeInternal(pdfBytes);
    if ((strict && !_isValidContentsRange(pdfBytes, range)) ||
        (!strict && !_isPlausibleRange(pdfBytes, range))) {
      throw StateError('Contents encontrado mas inconsistente.');
    }
    return range;
  }

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
    final parser = PdfDocumentParser(inputBytes);
    final document = PdfDocument.load(parser);

    final pageIndex = pageNumber - 1;
    if (pageIndex < 0 || pageIndex >= document.pdfPageList.pages.length) {
      throw RangeError.index(
          pageIndex, document.pdfPageList.pages, 'pageNumber');
    }

    final existingField = document.signatures.findByName(fieldName);
    PdfRect? fieldBounds;
    if (existingField != null && existingField.info.rect != null) {
      final rect = existingField.info.rect!;
      if (rect.length == 4) {
        fieldBounds = PdfRect(
          rect[0],
          rect[1],
          rect[2] - rect[0],
          rect[3] - rect[1],
        );
      }
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

    if (existingField == null) {
      final page = document.pdfPageList.pages[pageIndex];
      final annot = PdfAnnotSign(rect: bounds, fieldName: fieldName);
      if (drawAppearance != null) {
        final g = annot.appearance(document, PdfAnnotAppearance.normal);
        final localBounds = PdfRect(0, 0, bounds.width, bounds.height);
        drawAppearance(g, localBounds);
      }
      PdfAnnot(page, annot);
    } else {
      final updated = PdfDict<PdfDataType>.values(
        Map<String, PdfDataType>.from(existingField.fieldDict.values),
      );
      updated[PdfNameTokens.v] = document.sign!.ref();

      if (drawAppearance != null && fieldBounds != null) {
        final appearance = PdfGraphicXObject(document, '/Form');
        appearance.params[PdfNameTokens.bbox] = PdfArray.fromNum(
          [0, 0, fieldBounds.width, fieldBounds.height],
        );
        final g = PdfGraphics(appearance, appearance.buf);
        drawAppearance(g, PdfRect(0, 0, fieldBounds.width, fieldBounds.height));
        updated[PdfNameTokens.ap] = PdfDict.values({PdfNameTokens.n: appearance.ref()});
      }

      document.signatures.updateFieldDict(existingField, updated);
    }

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
    final contentsRange = findContentsRange(preparedPdfBytes, strict: false);
    final bytes = Uint8List.fromList(preparedPdfBytes);
    _embedSignature(bytes, contentsRange.start, contentsRange.end, pkcs7Bytes);
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
    params[PdfNameTokens.filter] = const PdfName(PdfNameTokens.adobePpkLite);
    if (signature?.isDocTimeStamp == true) {
      params[PdfNameTokens.type] = const PdfName(PdfNameTokens.docTimeStamp);
      params[PdfNameTokens.subFilter] = const PdfName(PdfNameTokens.etsiRfc3161);
    } else if (signature?.subFilter != null) {
      final raw = signature!.subFilter!;
      final name = raw.startsWith('/') ? raw : '/$raw';
      params[PdfNameTokens.subFilter] = PdfName(name);
    } else {
      params[PdfNameTokens.subFilter] = const PdfName(PdfNameTokens.adbePkcs7Detached);
    }
    params[PdfNameTokens.byteRange] = _PdfByteRangePlaceholder(digits: byteRangeDigits);
    params[PdfNameTokens.contents] = PdfString(
      Uint8List(contentsReserveSize),
      format: PdfStringFormat.binary,
      encrypted: false,
    );

    final when = (signature?.signingTime ?? DateTime.now()).toUtc();
    params[PdfNameTokens.m] = PdfString.fromDate(when, encrypted: false);
    if (signature?.reason != null) {
      params[PdfNameTokens.reason] = PdfString.fromString(signature!.reason!);
    }
    if (signature?.location != null) {
      params[PdfNameTokens.location] = PdfString.fromString(signature!.location!);
    }
    if (signature?.contactInfo != null) {
      params['/ContactInfo'] = PdfString.fromString(signature!.contactInfo!);
    }
    if (signature?.name != null) {
      params[PdfNameTokens.name] = PdfString.fromString(signature!.name!);
    }

    final p = signature?.docMdpPermissionP;
    if (p != null) {
      params['/Reference'] = PdfArray<PdfDataType>([
        PdfDict.values({
          PdfNameTokens.type: const PdfName(PdfNameTokens.sigRef),
          '/TransformMethod': const PdfName(PdfNameTokens.docMdp),
          '/DigestMethod': const PdfName('/SHA256'),
          PdfNameTokens.transformParams: PdfDict.values({
            PdfNameTokens.type: const PdfName(PdfNameTokens.transformParams),
            PdfNameTokens.p: PdfNum(p),
            PdfNameTokens.v: const PdfName(PdfNameTokens.v1_2),
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

  bytes.setRange(
      bracketStart + 1, bracketStart + 1 + repBytes.length, repBytes);
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
  final digest = sha256.convert(<int>[...part1, ...part2]);
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
  final pos = _lastIndexOfSequence(
    bytes,
    PdfExternalSigning._byteRangeToken,
    0,
    bytes.length,
  );
  if (pos == -1) return null;
  final parsed =
      _parseByteRangeAt(bytes, pos + PdfExternalSigning._byteRangeToken.length);
  return parsed;
}

int _lastIndexOfSequence(
    Uint8List bytes, List<int> pattern, int start, int end) {
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

List<int> _extractByteRangeFast(Uint8List pdfBytes) {
  final range = _findLastByteRange(pdfBytes);
  if (range == null) {
    throw StateError('ByteRange not found');
  }
  return range;
}

List<int> _extractByteRangeStringSearch(Uint8List pdfBytes) {
  final text = latin1.decode(pdfBytes, allowInvalid: true);
  final matches = RegExp(
    r'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]',
  ).allMatches(text);
  if (matches.isEmpty) {
    throw StateError('ByteRange not found');
  }
  final match = matches.last;
  return <int>[
    int.parse(match.group(1)!),
    int.parse(match.group(2)!),
    int.parse(match.group(3)!),
    int.parse(match.group(4)!),
  ];
}

List<int> _extractByteRangeInternal(Uint8List pdfBytes) {
  final fields = PdfDocumentParser(pdfBytes).extractSignatureFields();
  List<int>? last;
  for (final field in fields) {
    final range = field.byteRange;
    if (range != null && range.length >= 4) {
      last = range.sublist(0, 4);
    }
  }
  if (last == null) {
    throw StateError('ByteRange not found via internal parser');
  }
  return last;
}

_ContentsRange _findContentsRangeFast(Uint8List pdfBytes) {
  final range = _extractByteRangeFast(pdfBytes);
  if (range.length != 4) {
    throw StateError('Invalid ByteRange length');
  }
  final gapStart = range[0] + range[1];
  final gapEnd = range[2];
  if (gapStart < 0 || gapEnd <= gapStart || gapEnd > pdfBytes.length) {
    throw StateError('Invalid ByteRange gap for /Contents');
  }

  final contentsPos = _indexOfSequence(
    pdfBytes,
    PdfExternalSigning._contentsToken,
    gapStart,
    gapEnd,
  );
  if (contentsPos == -1) {
    return _findHexStringInGap(pdfBytes, gapStart, gapEnd);
  }

  int i = contentsPos + PdfExternalSigning._contentsToken.length;
  i = _skipPdfWsAndComments(pdfBytes, i, gapEnd);

  int lt = -1;
  for (int j = i; j < gapEnd; j++) {
    if (pdfBytes[j] == 0x3C /* < */) {
      lt = j;
      break;
    }
  }
  if (lt == -1) {
    throw StateError('Contents hex string not found');
  }

  int gt = -1;
  for (int j = lt + 1; j < gapEnd; j++) {
    if (pdfBytes[j] == 0x3E /* > */) {
      gt = j;
      break;
    }
  }
  if (gt == -1 || gt <= lt) {
    throw StateError('Contents hex string not found');
  }
  return _ContentsRange(lt, gt);
}

_ContentsRange _findHexStringInGap(
  Uint8List pdfBytes,
  int gapStart,
  int gapEnd,
) {
  int lt = -1;
  for (int i = gapStart; i < gapEnd; i++) {
    if (pdfBytes[i] == 0x3C /* < */) {
      lt = i;
      break;
    }
  }
  if (lt == -1) {
    throw StateError('Contents hex string not found');
  }

  int gt = -1;
  for (int i = lt + 1; i < gapEnd; i++) {
    if (pdfBytes[i] == 0x3E /* > */) {
      gt = i;
      break;
    }
  }
  if (gt == -1 || gt <= lt) {
    throw StateError('Contents hex string not found');
  }
  return _ContentsRange(lt, gt);
}

_ContentsRange _findContentsRangeStringSearch(Uint8List pdfBytes) {
  final text = latin1.decode(pdfBytes, allowInvalid: true);
  final sigPos = text.lastIndexOf('/Type /Sig');
  if (sigPos == -1) {
    throw StateError('No /Type /Sig');
  }
  final dictStart = text.lastIndexOf('<<', sigPos);
  final dictEnd = text.indexOf('>>', sigPos);
  if (dictStart == -1 || dictEnd == -1 || dictEnd <= dictStart) {
    throw StateError('Could not find signature dictionary bounds');
  }
  final contentsLabelPos = text.indexOf(PdfNameTokens.contents, dictStart);
  if (contentsLabelPos == -1 || contentsLabelPos > dictEnd) {
    throw StateError('No /Contents found in signature dictionary');
  }
  final lt = text.indexOf('<', contentsLabelPos);
  final gt = text.indexOf('>', lt + 1);
  if (lt == -1 || gt == -1 || gt > dictEnd || gt <= lt) {
    throw StateError('Contents hex string not found');
  }
  return _ContentsRange(lt, gt);
}

_ContentsRange _findContentsRangeInternal(Uint8List pdfBytes) {
  final range = _extractByteRangeInternal(pdfBytes);
  if (range.length != 4) {
    throw StateError('Invalid ByteRange length');
  }
  final gapStart = range[0] + range[1];
  final gapEnd = range[2];
  if (gapStart < 0 || gapEnd <= gapStart || gapEnd > pdfBytes.length) {
    throw StateError('Invalid ByteRange gap for /Contents');
  }
  final contentsPos = _indexOfSequence(
    pdfBytes,
    PdfExternalSigning._contentsToken,
    gapStart,
    gapEnd,
  );
  if (contentsPos == -1) {
    return _findHexStringInGap(pdfBytes, gapStart, gapEnd);
  }

  int i = contentsPos + PdfExternalSigning._contentsToken.length;
  i = _skipPdfWsAndComments(pdfBytes, i, gapEnd);

  int lt = -1;
  for (int j = i; j < gapEnd; j++) {
    if (pdfBytes[j] == 0x3C /* < */) {
      lt = j;
      break;
    }
  }
  if (lt == -1) {
    throw StateError('Contents hex string not found');
  }

  int gt = -1;
  for (int j = lt + 1; j < gapEnd; j++) {
    if (pdfBytes[j] == 0x3E /* > */) {
      gt = j;
      break;
    }
  }
  if (gt == -1 || gt <= lt) {
    throw StateError('Contents hex string not found');
  }
  return _ContentsRange(lt, gt);
}

bool _isValidByteRange(int fileLength, List<int> byteRange) {
  if (byteRange.length != 4) return false;
  final start1 = byteRange[0];
  final len1 = byteRange[1];
  final start2 = byteRange[2];
  final len2 = byteRange[3];
  if (start1 < 0 || len1 < 0 || start2 < 0 || len2 < 0) return false;
  if (start1 > fileLength) return false;
  if (start1 + len1 > fileLength) return false;
  if (start2 > fileLength) return false;
  if (start2 + len2 > fileLength) return false;
  if (start2 < start1 + len1) return false;
  return true;
}

bool _isValidContentsRange(Uint8List pdfBytes, _ContentsRange r) {
  if (r.start < 0 || r.end < 0) return false;
  if (r.start >= r.end) return false;
  if (r.end > pdfBytes.length) return false;
  return _isValidContentsHex(pdfBytes, r.start, r.end);
}

bool _isPlausibleRange(Uint8List pdfBytes, _ContentsRange r) {
  if (r.start < 0 || r.end < 0) return false;
  if (r.start >= r.end) return false;
  if (r.end > pdfBytes.length) return false;
  return true;
}

bool _isValidContentsHex(Uint8List pdfBytes, int start, int end) {
  int hexDigits = 0;
  for (int i = start; i < end; i++) {
    final b = pdfBytes[i];
    final isWs = b == 0x00 ||
        b == 0x09 ||
        b == 0x0A ||
        b == 0x0C ||
        b == 0x0D ||
        b == 0x20;
    if (isWs) continue;
    final isHex = (b >= 0x30 && b <= 0x39) ||
        (b >= 0x41 && b <= 0x46) ||
        (b >= 0x61 && b <= 0x66);
    if (!isHex) return false;
    hexDigits++;
  }

  if (hexDigits < PdfExternalSigning._minContentsHexDigits) {
    return false;
  }
  if (hexDigits.isOdd) {
    return false;
  }
  return true;
}

int _skipPdfWsAndComments(Uint8List bytes, int i, int end) {
  while (i < end) {
    final b = bytes[i];
    if (b == 0x00 ||
        b == 0x09 ||
        b == 0x0A ||
        b == 0x0C ||
        b == 0x0D ||
        b == 0x20) {
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




