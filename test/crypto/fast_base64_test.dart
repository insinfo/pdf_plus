import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/crypto.dart';
import 'package:test/test.dart';

void main() {
  group('Fast Base64', () {
    test('bytes encode/decode roundtrip', () {
      final source =
          Uint8List.fromList(List<int>.generate(2048, (i) => i & 0xff));
      final encoded = base64EncodeBytes(source);
      final decoded = base64DecodeToBytes(encoded);

      expect(decoded, source);
      expect(encoded, base64.encode(source));
    });

    test('UTF-8 encode/decode roundtrip with unicode', () {
      const text = 'Olá 你好, world! 👋';
      final encoded = base64EncodeUtf8(text);
      final decoded = base64DecodeUtf8(encoded);

      expect(decoded, text);
      expect(encoded, base64.encode(utf8.encode(text)));
    });

    test('decode accepts line breaks and spaces', () {
      final encoded = base64EncodeUtf8('pdf_plus base64');
      final decorated = '${encoded.substring(0, 4)} \n${encoded.substring(4)}';
      final decoded = base64DecodeUtf8(decorated);
      expect(decoded, 'pdf_plus base64');
    });

    test('invalid base64 throws FormatException', () {
      expect(
        () => base64DecodeToBytes('@@@='),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
