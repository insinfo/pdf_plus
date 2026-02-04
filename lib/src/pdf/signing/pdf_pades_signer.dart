import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/sha256.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/name.dart';
import '../format/string.dart';
import '../format/stream.dart';
import '../format/object_base.dart';
import '../obj/object.dart';
import '../obj/signature.dart';
import 'pdf_cms_signer.dart';
import 'pdf_external_signer.dart';
import 'package:pdf_plus/src/pdf/pdf_names.dart';

/// PAdES implementation based on [PdfSignatureBase].
class PdfPadesSigner extends PdfSignatureBase {
  /// Creates a PAdES signer using an external signer and CMS builder.
  PdfPadesSigner({
    required this.externalSigner,
    PdfCmsSigner? cmsSigner,
    this.contentsReserveSize = 16384,
    this.byteRangeDigits = 10,
    this.signingTime,
    this.reason,
    this.location,
    this.contactInfo,
    this.name,
  }) : cmsSigner = cmsSigner ?? PdfCmsSigner();

  /// External signer used to sign CMS attributes.
  final PdfExternalSigner externalSigner;
  /// CMS builder used to build detached signatures.
  final PdfCmsSigner cmsSigner;
  /// Reserved size for /Contents.
  final int contentsReserveSize;
  /// Fixed width for ByteRange numbers.
  final int byteRangeDigits;
  /// Signing time to embed.
  final DateTime? signingTime;
  /// Reason for signing.
  final String? reason;
  /// Location of signing.
  final String? location;
  /// Contact information.
  final String? contactInfo;
  /// Signer name.
  final String? name;

  @override
  /// Populates the signature dictionary before hashing.
  void preSign(PdfObject object, PdfDict params) {
    params[PdfNameTokens.filter] = const PdfName(PdfNameTokens.adobePpkLite);
    params[PdfNameTokens.subFilter] = const PdfName(PdfNameTokens.adbePkcs7Detached);
    params[PdfNameTokens.byteRange] = _PdfByteRangePlaceholder(digits: byteRangeDigits);
    params[PdfNameTokens.contents] = PdfString(
      Uint8List(contentsReserveSize),
      format: PdfStringFormat.binary,
      encrypted: false,
    );

    final when = (signingTime ?? DateTime.now()).toUtc();
    params[PdfNameTokens.m] = PdfString.fromDate(when, encrypted: false);
    if (reason != null) {
      params[PdfNameTokens.reason] = PdfString.fromString(reason!);
    }
    if (location != null) {
      params[PdfNameTokens.location] = PdfString.fromString(location!);
    }
    if (contactInfo != null) {
      params[PdfNameTokens.contactinfo] = PdfString.fromString(contactInfo!);
    }
    if (name != null) {
      params[PdfNameTokens.name] = PdfString.fromString(name!);
    }
  }

  @override
  /// Computes the ByteRange digest, builds CMS, and embeds /Contents.
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
    final byteRange = <int>[
      0,
      contentsRange.lt,
      contentsRange.gt + 1,
      bytes.length - (contentsRange.gt + 1),
    ];

    _writeByteRange(bytes, offsetStart, offsetEnd, byteRange);

    final contentDigest = _computeByteRangeDigest(bytes, byteRange);

    final signerCerts = externalSigner.certificates;
    if (signerCerts.isEmpty) {
      throw StateError('Nenhum certificado fornecido pelo signer externo.');
    }

    final cms = await cmsSigner.buildDetachedCms(
      contentDigest: contentDigest,
      signerCertDer: signerCerts.first,
      extraCertsDer: signerCerts.skip(1).toList(growable: false),
      signingTime: signingTime,
      signCallback: (signedAttrsDer, signedAttrsDigest) async {
        return externalSigner.signDigest(signedAttrsDigest);
      },
    );

    _embedSignature(bytes, contentsRange.start, contentsRange.end, cms);

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





