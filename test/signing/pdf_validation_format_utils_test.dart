import 'package:pdf_plus/src/pdf/validation/pdf_validation_format_utils.dart';
import 'package:test/test.dart';

void main() {
  group('pdf_validation_format_utils', () {
    test('parsePdfDateLocal preserves wall clock fields', () {
      final dt = parsePdfDateLocal("D:20251229135822-03'00'");
      expect(dt, isNotNull);
      expect(dt!.year, 2025);
      expect(dt.month, 12);
      expect(dt.day, 29);
      expect(dt.hour, 13);
      expect(dt.minute, 58);
      expect(dt.second, 22);
    });

    test('parsePdfDateToUtc normalizes timezone offset', () {
      final dt = parsePdfDateToUtc("D:20251229135822-03'00'");
      expect(dt, isNotNull);
      expect(dt!.isUtc, isTrue);
      expect(dt.year, 2025);
      expect(dt.month, 12);
      expect(dt.day, 29);
      expect(dt.hour, 16);
      expect(dt.minute, 58);
      expect(dt.second, 22);
    });

    test('hex helpers keep casing contract', () {
      const bytes = <int>[0xab, 0xcd, 0xef];
      expect(bytesToHexLower(bytes), 'abcdef');
      expect(bytesToHexUpper(bytes), 'ABCDEF');
      expect(bigIntToHexUpper(BigInt.parse('65535')), 'FFFF');
    });
  });
}
