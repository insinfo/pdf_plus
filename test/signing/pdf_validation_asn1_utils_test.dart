import 'package:pdf_plus/src/crypto/asn1/asn1.dart';
import 'package:pdf_plus/src/pdf/validation/pdf_validation_asn1_utils.dart';
import 'package:test/test.dart';

void main() {
  group('pdf_validation_asn1_utils', () {
    test('asn1ObjectIdentifierToString reads OID identifier', () {
      final oid = ASN1ObjectIdentifier.fromComponentString(
        '1.2.840.113549.1.1.11',
      );

      expect(asn1ObjectIdentifierToString(oid), '1.2.840.113549.1.1.11');
      expect(asn1ObjectIdentifierToString(ASN1Integer(BigInt.one)), isNull);
    });

    test('parseAsn1TimeLoose parses UTC and Generalized times', () {
      final utc = ASN1UtcTime(DateTime.utc(2026, 1, 2, 3, 4, 5));
      final generalized =
          ASN1GeneralizedTime(DateTime.utc(2026, 2, 3, 4, 5, 6));

      final utcDt = parseAsn1TimeLoose(utc);
      final genDt = parseAsn1TimeLoose(generalized);

      expect(utcDt, isNotNull);
      expect(utcDt!.isUtc, isTrue);
      expect(utcDt.year, 2026);
      expect(utcDt.month, 1);
      expect(utcDt.day, 2);

      expect(genDt, isNotNull);
      expect(genDt!.isUtc, isTrue);
      expect(genDt.year, 2026);
      expect(genDt.month, 2);
      expect(genDt.day, 3);
    });

    test('parseAsn1TimeLoose returns null for non-time object', () {
      expect(parseAsn1TimeLoose(ASN1Integer(BigInt.from(123))), isNull);
    });
  });
}
