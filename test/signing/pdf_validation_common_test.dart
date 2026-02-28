import 'dart:typed_data';

import 'package:pdf_plus/src/pdf/validation/pdf_validation_common.dart';
import 'package:test/test.dart';

void main() {
  group('pdf_validation_common', () {
    test('validationSha256Hex returns deterministic lowercase digest', () {
      final digest = validationSha256Hex(Uint8List.fromList('abc'.codeUnits));
      expect(
        digest,
        'ba7816bf8f01cfea414140de5dae2223'
        'b00361a396177a9cb410ff61f20015ad',
      );
    });

    test('normalizeValidationName lowercases and strips non-alnum', () {
      expect(
        normalizeValidationName('CN=Example-CA, O=Gov BR'),
        'cnexamplecaogovbr',
      );
      expect(normalizeValidationName('---'), isNull);
      expect(normalizeValidationName(null), isNull);
    });

    test('subjectMatchesValidationIssuer supports both contain directions', () {
      final subjects = <String>{'acraizgovbr', 'acintermediaria'};
      expect(subjectMatchesValidationIssuer('acraiz', subjects), isTrue);
      expect(
        subjectMatchesValidationIssuer('acraizgovbrunidade', subjects),
        isTrue,
      );
      expect(subjectMatchesValidationIssuer('outracadeia', subjects), isFalse);
    });
  });
}
