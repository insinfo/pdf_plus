import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:pdf_plus/pdf.dart';

import 'package:test/test.dart';

void main() {
  group('PdfDocumentParser.extractInfo', () {
    test('lê Info e MediaBox de PDF simples', () {
      final bytes = _readAsset('test/assets/pdfs/sample_no_signature.pdf');
      final parser = PdfDocumentParser(bytes);
      final info = parser.extractInfo();

      expect(info.pageCount, 1);
      expect(info.mediaBoxes, hasLength(1));
      expect(info.mediaBoxes.first.box.length, 4);
      expect(info.mediaBoxes.first.box[2] > info.mediaBoxes.first.box[0], isTrue);
      expect(info.mediaBoxes.first.box[3] > info.mediaBoxes.first.box[1], isTrue);
      expect(info.infoDict?[PdfNameTokens.title], 'sample');
      expect(info.infoDict?[PdfNameTokens.author], 'Philip Hutchison');
    });

    test('respeita maxPages e extrai imagens', () {
      final bytes =
          _readAsset('test/assets/pdfs/relatorio_de_conformidade.pdf');
      final parser = PdfDocumentParser(bytes);

      final limited = parser.extractInfo(maxPages: 3);
      expect(limited.pageCount, 3);
      expect(limited.mediaBoxes, hasLength(3));

      final full = parser.extractInfo();
      expect(full.pageCount, 15);
      expect(full.images.isNotEmpty, isTrue);
      final firstImage = full.images.first;
      expect(firstImage.width, isNotNull);
      expect(firstImage.height, isNotNull);
    });
  });

  group('PdfQuickInfo', () {
    test('detecta assinatura e versão 1.5+', () {
      final bytes =
          _readAsset('test/assets/pdfs/generated_doc_mdp_allow_signatures.pdf');
      final quick = PdfQuickInfo.fromBytes(bytes);

      expect(quick.isPdf15OrAbove, isTrue);
      expect(quick.hasSignatures, isTrue);
      expect(quick.docMdpPermissionP, 2);
    });

    test('detecta PDF sem assinatura', () {
      final bytes = _readAsset('test/assets/pdfs/sample_no_signature.pdf');
      final quick = PdfQuickInfo.fromBytes(bytes);

      expect(quick.isPdf15OrAbove, isFalse);
      expect(quick.hasSignatures, isFalse);
      expect(quick.docMdpPermissionP, isNull);
    });
  });

  group('xref e trailer', () {
    test('xrefOffset coincide com startxref', () {
      final bytes = _readAsset('test/assets/pdfs/sample_no_signature.pdf');
      final parser = PdfDocumentParser.fromReader(
        PdfMemoryRandomAccessReader(bytes),
      );
      final expected = _findStartXref(bytes);
      expect(expected, greaterThan(0));
      expect(parser.xrefOffset, expected);
    });

    test('size coincide com /Size do trailer', () {
      final bytes = _readAsset('test/assets/pdfs/sample_no_signature.pdf');
      final parser = PdfDocumentParser(bytes);
      final expected = _extractTrailerSize(bytes);
      expect(expected, isNotNull);
      expect(parser.size, expected);
    });
  });

  group('PDFs problemáticos iText 2.1.3', () {
    test('bad startxref não quebra o parser', () {
      final bytes =
          _readAsset('test/assets/pdfs/itext_2_1_3_bad_startxref.pdf');
      final info = PdfDocumentParser(bytes).extractInfo();
      expect(info.pageCount, 0);
      expect(info.infoDict, isNull);
    });

    test('missing eof ainda permite extrair infos', () {
      final bytes =
          _readAsset('test/assets/pdfs/itext_2_1_3_missing_eof.pdf');
      final info = PdfDocumentParser(bytes).extractInfo();
      expect(info.pageCount, 3);
      expect(info.infoDict?[PdfNameTokens.title], 'PDF multipaginas');
    });

    test('truncado não quebra o parser', () {
      final bytes =
          _readAsset('test/assets/pdfs/itext_2_1_3_truncated.pdf');
      final info = PdfDocumentParser(bytes).extractInfo();
      expect(info.pageCount, 0);
      expect(info.infoDict, isNull);
    });
  });

  test('mergeDocument importa páginas', () {
    final bytes = _readAsset('test/assets/pdfs/sample_no_signature.pdf');
    final parser = PdfDocumentParser(bytes);
    final info = parser.extractInfo();

    final doc = PdfDocument.load(parser);
    expect(doc.pdfPageList.pages.isNotEmpty, isTrue);
    expect(doc.pdfPageList.pages.length, greaterThanOrEqualTo(info.pageCount));
  });
}

Uint8List _readAsset(String path) => File(path).readAsBytesSync();

int _findStartXref(Uint8List bytes) {
  final token = ascii.encode('startxref');
  final pos = _lastIndexOfSequence(bytes, token, 0, bytes.length);
  if (pos == -1) return 0;

  int i = pos + token.length;
  i = _skipWsAndComments(bytes, i, bytes.length);
  final parsed = _readInt(bytes, i, bytes.length);
  return parsed.value;
}

int? _extractTrailerSize(Uint8List bytes) {
  final trailerToken = ascii.encode('trailer');
  final sizeToken = <int>[0x2F, 0x53, 0x69, 0x7A, 0x65]; // /Size
  final trailerPos = _lastIndexOfSequence(bytes, trailerToken, 0, bytes.length);
  if (trailerPos == -1) return null;

  final windowEnd = math.min(bytes.length, trailerPos + 4096);
  final sizePos = _indexOfSequence(bytes, sizeToken, trailerPos, windowEnd);
  if (sizePos == -1) return null;

  int i = sizePos + sizeToken.length;
  i = _skipWsAndComments(bytes, i, windowEnd);
  final parsed = _readInt(bytes, i, windowEnd);
  return parsed.value;
}

int _lastIndexOfSequence(
  Uint8List bytes,
  List<int> pattern,
  int start,
  int end,
) {
  if (pattern.isEmpty) return -1;
  final max = end - pattern.length;
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

int _indexOfSequence(
  Uint8List bytes,
  List<int> pattern,
  int start,
  int end,
) {
  if (pattern.isEmpty) return -1;
  final limit = end - pattern.length;
  for (int i = start; i <= limit; i++) {
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

int _skipWsAndComments(Uint8List bytes, int i, int end) {
  while (i < end) {
    final b = bytes[i];
    if (_isWhitespace(b)) {
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
  var value = 0;
  var digits = 0;
  if (i < end && (bytes[i] == 0x2B || bytes[i] == 0x2D)) {
    i++;
  }
  while (i < end) {
    final b = bytes[i];
    if (b < 0x30 || b > 0x39) break;
    value = (value * 10) + (b - 0x30);
    i++;
    digits++;
  }
  if (digits == 0) {
    throw StateError('Inteiro inválido');
  }
  return (value: value, nextIndex: i);
}

bool _isWhitespace(int b) =>
    b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0C || b == 0x0D || b == 0x20;

