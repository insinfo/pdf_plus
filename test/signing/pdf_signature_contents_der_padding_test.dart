import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  group('PDF signature /Contents DER padding compliance', () {
    test('preserves a legitimate trailing zero byte inside DER', () {
      final der = Uint8List.fromList(<int>[
        0x30, 0x03, // SEQUENCE, 3 bytes
        0x02, 0x01, 0x00, // INTEGER 0; final 00 is part of DER
      ]);
      final pdfBytes = _buildPdfWithSignatureContents(<int>[
        ...der,
        0x00,
        0x00,
        0x00,
      ]);

      final contents =
          PdfSignatureValidator.extractAllSignatureContents(pdfBytes);

      expect(contents, hasLength(1));
      expect(contents.single, orderedEquals(der));
      expect(contents.single.last, 0x00);
    });

    test('uses the DER element length before discarding reserved padding', () {
      final der = Uint8List.fromList(<int>[
        0x30, 0x81, 0x80, // SEQUENCE, long-form length 128
        ...List<int>.filled(128, 0x05), // invalid CMS but valid DER length
      ]);
      final pdfBytes = _buildPdfWithSignatureContents(<int>[
        ...der,
        ...List<int>.filled(64, 0x00),
      ]);

      final contents =
          PdfSignatureValidator.extractAllSignatureContents(pdfBytes);

      expect(contents, hasLength(1));
      expect(contents.single.length, der.length);
      expect(contents.single, orderedEquals(der));
    });
  });
}

Uint8List _buildPdfWithSignatureContents(List<int> contents) {
  final hex = contents
      .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
      .join()
      .toUpperCase();
  const width = 10;
  final suffix = ascii.encode('> >>\nendobj\n%%EOF\n');

  String buildPrefix({
    required int firstLength,
    required int secondStart,
    required int secondLength,
  }) {
    String pad(int value) => value.toString().padLeft(width, '0');

    return '%PDF-1.7\n'
        '1 0 obj\n'
        '<< /Type /Sig '
        '/ByteRange [0 ${pad(firstLength)} ${pad(secondStart)} ${pad(secondLength)}] '
        '/Contents <';
  }

  final placeholderPrefix = buildPrefix(
    firstLength: 0,
    secondStart: 0,
    secondLength: 0,
  );
  final firstLength = ascii.encode(placeholderPrefix).length - 1;
  final secondStart = firstLength + 1 + hex.length + 1;
  final secondLength = suffix.length;
  final prefix = ascii.encode(buildPrefix(
    firstLength: firstLength,
    secondStart: secondStart,
    secondLength: secondLength,
  ));

  final out = BytesBuilder(copy: false)
    ..add(prefix)
    ..add(ascii.encode(hex))
    ..add(suffix);
  return out.takeBytes();
}
