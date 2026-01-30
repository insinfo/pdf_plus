import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:test/test.dart';

void main() {
  test('save incremental appends data and sets /Prev in trailer', () async {
    final docOriginal = PdfDocument();
    final page = PdfPage(docOriginal);
    final g = page.getGraphics();
    g.drawString(
      PdfFont.helvetica(docOriginal),
      12,
      'Incremental update test.',
      72,
      720,
    );

    final Uint8List original =
        Uint8List.fromList(await docOriginal.save(useIsolate: false));

    final newDoc = PdfDocument.parseFromBytes(original);
    newDoc.updateInfo(title: 'updated');

    final updated = Uint8List.fromList(await newDoc.save(useIsolate: false));

    expect(_startsWith(updated, original), isTrue);
    expect(_countOccurrences(updated, ascii.encode('startxref')),
        greaterThanOrEqualTo(2));

    final trailerPos = _lastIndexOfSequence(
      updated,
      ascii.encode('trailer'),
      0,
      updated.length,
    );
    expect(trailerPos, greaterThanOrEqualTo(0));

    final windowEnd = (trailerPos + 2048 < updated.length)
        ? trailerPos + 2048
        : updated.length;
    final prevPos = _indexOfSequence(
      updated,
      const <int>[0x2F, 0x50, 0x72, 0x65, 0x76], // /Prev
      trailerPos,
      windowEnd,
    );
    expect(prevPos, greaterThanOrEqualTo(0));
  });
}

bool _startsWith(Uint8List bytes, Uint8List prefix) {
  if (prefix.length > bytes.length) return false;
  for (int i = 0; i < prefix.length; i++) {
    if (bytes[i] != prefix[i]) return false;
  }
  return true;
}

int _countOccurrences(Uint8List bytes, List<int> pattern) {
  if (pattern.isEmpty) return 0;
  int count = 0;
  int i = 0;
  while (i <= bytes.length - pattern.length) {
    var ok = true;
    for (int j = 0; j < pattern.length; j++) {
      if (bytes[i + j] != pattern[j]) {
        ok = false;
        break;
      }
    }
    if (ok) {
      count++;
      i += pattern.length;
    } else {
      i++;
    }
  }
  return count;
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
