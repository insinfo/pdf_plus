import 'dart:io';

import 'package:pdf_plus/src/pdf/parsing/pdf_document_parser.dart';
import 'package:test/test.dart';

void main() {
  test('extract signature field info from signed PDFs', () {
    final file = File('test/assets/pdfs/2 ass leonardo e mauricio.pdf');
    expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

    final bytes = file.readAsBytesSync();
    final parser = PdfDocumentParser(bytes);
    final fields = parser.extractSignatureFields();

    expect(fields.length, 2);
    for (final field in fields) {
      expect(field.byteRange, isNotNull);
      expect(field.byteRange!.length, 4);
      expect(field.subFilter, isNotNull);
    }
  });
}
