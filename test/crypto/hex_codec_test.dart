import 'package:pdf_plus/src/utils/convert/hex/hex.dart';
import 'package:test/test.dart';

void main() {
  group('Hex codec', () {
    test('encode/decode roundtrip preserves bytes', () {
      final bytes = <int>[0x00, 0x01, 0x0f, 0x10, 0xff];
      final encoded = hex.encode(bytes);
      expect(encoded, '00010f10ff');

      final decoded = hex.decode(encoded);
      expect(decoded, bytes);
    });

    test('decode supports uppercase hex input', () {
      final decoded = hex.decode('0A0BFF');
      expect(decoded, <int>[0x0a, 0x0b, 0xff]);
    });

    test('decode rejects odd-length input', () {
      expect(
        () => hex.decode('abc'),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
