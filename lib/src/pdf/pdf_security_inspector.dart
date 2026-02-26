import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/platform_crypto.dart';

import 'parsing/parser_misc.dart';
import 'parsing/parser_tokens.dart';
import 'parsing/parser_xref.dart';
import 'parsing/pdf_document_info.dart';
import 'validation/pdf_signature_validator.dart';

class PdfSecurityInspectionResult {
  const PdfSecurityInspectionResult({
    required this.isPdf,
    required this.isEncrypted,
    required this.isSigned,
    required this.isCorrupted,
    required this.signatureCount,
    required this.pdfVersion,
    required this.startXref,
    required this.hasEofMarker,
    required this.hasValidByteRanges,
    required this.issues,
    required this.subFilters,
    required this.supportedSubFilters,
    this.allSignaturesIntact,
    this.sha256Hex,
  });

  final bool isPdf;
  final bool isEncrypted;
  final bool isSigned;
  final bool isCorrupted;
  final int signatureCount;
  final double pdfVersion;
  final int startXref;
  final bool hasEofMarker;
  final bool hasValidByteRanges;
  final List<String> issues;
  final List<String> subFilters;
  final bool supportedSubFilters;
  final bool? allSignaturesIntact;
  final String? sha256Hex;
}

class PdfSecurityInspector {
  PdfSecurityInspector({PlatformCrypto? crypto})
      : _crypto = crypto ?? createPlatformCrypto();

  final PlatformCrypto _crypto;

  PdfSecurityInspectionResult quickInspect(Uint8List pdfBytes) {
    final quick = PdfQuickInfo.fromBytes(pdfBytes);
    final ranges = PdfParserMisc.findAllByteRangesFromBytes(pdfBytes);
    var startXref = PdfParserXref.findStartXref(pdfBytes);
    final subFilters = _extractSubFilters(pdfBytes);
    final supportedSubFilters = subFilters.every(_isSupportedSubFilter);
    final hasValidByteRanges = ranges.every((range) {
      return _isByteRangeValid(pdfBytes.length, range);
    });

    final issues = <String>[];
    if (!quick.hasPdfHeader) issues.add('Cabecalho %PDF- ausente.');
    if (!quick.hasEofMarker) issues.add('Marcador %%EOF ausente.');
    if (startXref <= 0) {
      final repairedXref = _findFallbackXrefOffset(pdfBytes);
      if (repairedXref > 0) {
        startXref = repairedXref;
        issues.add(
          'startxref ausente ou invalido; xref localizado por varredura (modo reparo).',
        );
      } else {
        issues.add('startxref ausente ou invalido.');
      }
    }
    if (startXref >= pdfBytes.length) {
      issues.add('startxref fora dos limites do arquivo.');
    }
    if (!hasValidByteRanges) {
      issues.add('ByteRange inconsistente com o tamanho do arquivo.');
    }
    if (quick.hasSignatures && subFilters.isEmpty) {
      issues.add('SubFilter ausente em assinatura PDF.');
    }
    if (!supportedSubFilters) {
      issues.add('SubFilter não suportado detectado.');
    }
    if (ranges.isNotEmpty) {
      final last = ranges.last;
      final end = last[2] + last[3];
      if (pdfBytes.length > end) {
        issues.add(
          'Dados extras após ByteRange final (possível alteração).',
        );
      }
    }

    final isCorrupted = issues.isNotEmpty;

    return PdfSecurityInspectionResult(
      isPdf: quick.hasPdfHeader,
      isEncrypted: quick.isEncrypted,
      isSigned: quick.hasSignatures,
      isCorrupted: isCorrupted,
      signatureCount: ranges.length,
      pdfVersion: quick.pdfVersion,
      startXref: startXref,
      hasEofMarker: quick.hasEofMarker,
      hasValidByteRanges: hasValidByteRanges,
      issues: List.unmodifiable(issues),
      subFilters: List.unmodifiable(subFilters),
      supportedSubFilters: supportedSubFilters,
      allSignaturesIntact: null,
      sha256Hex: null,
    );
  }

  Future<PdfSecurityInspectionResult> inspect(
    Uint8List pdfBytes, {
    bool validateSignatures = false,
    bool includeSha256 = false,
  }) async {
    var result = quickInspect(pdfBytes);

    bool? allSignaturesIntact;
    if (validateSignatures && result.isSigned) {
      final report = await PdfSignatureValidator().validateAllSignatures(
        pdfBytes,
        includeCertificates: false,
        includeSignatureFields: false,
      );
      allSignaturesIntact = report.signatures.isNotEmpty &&
          report.signatures.every((sig) => sig.intact);
    }

    String? sha256Hex;
    if (includeSha256) {
      final digest = await _crypto.sha256(pdfBytes);
      sha256Hex = bytesToHex(digest);
    }

    final mergedIssues = <String>[...result.issues];
    var isCorrupted = result.isCorrupted;
    if (allSignaturesIntact == false) {
      mergedIssues.add('Assinatura presente, mas integridade do documento falhou.');
      isCorrupted = true;
    }

    result = PdfSecurityInspectionResult(
      isPdf: result.isPdf,
      isEncrypted: result.isEncrypted,
      isSigned: result.isSigned,
      isCorrupted: isCorrupted,
      signatureCount: result.signatureCount,
      pdfVersion: result.pdfVersion,
      startXref: result.startXref,
      hasEofMarker: result.hasEofMarker,
      hasValidByteRanges: result.hasValidByteRanges,
      issues: List.unmodifiable(mergedIssues),
      subFilters: result.subFilters,
      supportedSubFilters: result.supportedSubFilters,
      allSignaturesIntact: allSignaturesIntact,
      sha256Hex: sha256Hex,
    );
    return result;
  }
}

bool _isByteRangeValid(int fileLength, List<int> range) {
  if (range.length != 4) return false;
  final a = range[0];
  final b = range[1];
  final c = range[2];
  final d = range[3];
  if (a < 0 || b < 0 || c < 0 || d < 0) return false;
  if (a + b > c) return false;
  if (c + d > fileLength) return false;
  return true;
}

List<String> _extractSubFilters(Uint8List pdfBytes) {
  const key = <int>[
    0x2F, // /
    0x53, 0x75, 0x62, 0x46, 0x69, 0x6C, 0x74, 0x65, 0x72, // SubFilter
  ];
  final out = <String>[];
  var offset = 0;

  while (offset < pdfBytes.length) {
    final pos = PdfParserTokens.indexOfSequence(
      pdfBytes,
      key,
      offset,
      pdfBytes.length,
    );
    if (pos == -1) break;

    var i = pos + key.length;
    i = PdfParserTokens.skipPdfWsAndComments(pdfBytes, i, pdfBytes.length);
    if (i < pdfBytes.length && pdfBytes[i] == 0x2F) {
      i++;
      final start = i;
      while (i < pdfBytes.length && !_isNameDelimiter(pdfBytes[i])) {
        i++;
      }
      if (i > start) {
        out.add(String.fromCharCodes(pdfBytes.sublist(start, i)));
      }
    }

    offset = pos + key.length;
  }

  return out;
}

bool _isSupportedSubFilter(String value) {
  final normalized = value.trim().toLowerCase();
  return normalized == 'adbe.pkcs7.detached' ||
      normalized == 'etsi.cades.detached';
}

int _findFallbackXrefOffset(Uint8List bytes) {
  const xrefToken = <int>[0x78, 0x72, 0x65, 0x66]; // xref
  final windowStart =
      bytes.length > 2 * 1024 * 1024 ? bytes.length - 2 * 1024 * 1024 : 0;
  var searchEnd = bytes.length;

  for (int attempts = 0; attempts < 64; attempts++) {
    final pos = PdfParserTokens.lastIndexOfSequence(
      bytes,
      xrefToken,
      windowStart,
      searchEnd,
    );
    if (pos == -1) return 0;

    final before = pos > 0 ? bytes[pos - 1] : 0x20;
    final afterIndex = pos + xrefToken.length;
    final after = afterIndex < bytes.length ? bytes[afterIndex] : 0x20;
    final likelyBoundary = _isNameDelimiter(before) && _isNameDelimiter(after);
    if (likelyBoundary) {
      return pos;
    }

    searchEnd = pos;
    if (searchEnd <= windowStart) break;
  }

  return 0;
}

bool _isNameDelimiter(int b) {
  return PdfParserTokens.isWhitespace(b) ||
      b == 0x00 ||
      b == 0x2F || // /
      b == 0x3C || // <
      b == 0x3E || // >
      b == 0x28 || // (
      b == 0x29 || // )
      b == 0x5B || // [
      b == 0x5D || // ]
      b == 0x7B || // {
      b == 0x7D || // }
      b == 0x25; // %
}
