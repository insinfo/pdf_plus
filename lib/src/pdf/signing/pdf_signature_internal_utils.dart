import 'dart:convert';
import 'dart:typed_data';

import '../crypto/pdf_crypto.dart';
import '../format/base.dart';
import '../format/object_base.dart';
import '../format/stream.dart';
import '../parsing/parser_tokens.dart';
import '../../utils/convert/hex/hex_case.dart';

class PdfByteRangePlaceholder extends PdfDataType {
  const PdfByteRangePlaceholder({required this.digits});

  final int digits;

  @override
  void output(PdfObjectBase o, PdfStream s, [int? indent]) {
    final zero = '0'.padLeft(digits, '0');
    s.putByte(0x5B); // [
    s.putString('$zero $zero $zero $zero');
    s.putByte(0x5D); // ]
  }
}

class PdfContentsRange {
  PdfContentsRange(this.lt, this.gt);

  final int lt;
  final int gt;

  int get start => lt + 1;
  int get end => gt;
}

PdfContentsRange findContentsRangeInWindow(
  Uint8List bytes,
  int start,
  int end,
) {
  const contentsToken = <int>[
    0x2F, // /
    0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x73, // Contents
  ];

  final contentsPos =
      PdfParserTokens.indexOfSequence(bytes, contentsToken, start, end);
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

  return PdfContentsRange(lt, gt);
}

void writeByteRangeInWindow(
  Uint8List bytes,
  int start,
  int end,
  List<int> range,
) {
  const byteRangeToken = <int>[
    0x2F, // /
    0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65, // ByteRange
  ];

  final pos =
      PdfParserTokens.indexOfSequence(bytes, byteRangeToken, start, end);
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
    bracketStart + 1,
    bracketStart + 1 + repBytes.length,
    repBytes,
  );
  for (int k = bracketStart + 1 + repBytes.length; k < bracketEnd; k++) {
    bytes[k] = 0x20; // espaço
  }
}

Uint8List computeByteRangeDigest(Uint8List bytes, List<int> range) {
  if (range.length != 4) {
    throw ArgumentError('ByteRange inválido.');
  }
  final start1 = range[0];
  final len1 = range[1];
  final start2 = range[2];
  final len2 = range[3];

  final part1 = bytes.sublist(start1, start1 + len1);
  final part2 = bytes.sublist(start2, start2 + len2);
  return PdfCrypto.digestConcatSha256(part1, part2);
}

void embedSignatureHex(
  Uint8List bytes,
  int start,
  int end,
  Uint8List cms,
) {
  final available = end - start;
  var hex = bytesToHexUpper(cms);
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

String bytesToHex(List<int> bytes) {
  return hexLower(bytes);
}

String bytesToHexUpper(List<int> bytes) => hexUpper(bytes);
