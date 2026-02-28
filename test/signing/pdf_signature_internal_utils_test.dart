import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/src/pdf/crypto/pdf_crypto.dart';
import 'package:pdf_plus/src/pdf/signing/pdf_signature_internal_utils.dart';
import 'package:test/test.dart';

void main() {
  group('pdf_signature_internal_utils', () {
    test('find, write and embed operate in signature window', () {
      final bytes = Uint8List.fromList(
        ascii.encode(
          '<< /ByteRange [0000 0000 0000 0000] /Contents <000000000000> >>',
        ),
      );

      final contents = findContentsRangeInWindow(bytes, 0, bytes.length);
      expect(contents.start, lessThan(contents.end));

      writeByteRangeInWindow(bytes, 0, bytes.length, const [1, 2, 3, 4]);
      final afterRange = ascii.decode(bytes);
      expect(afterRange, contains('/ByteRange [0001 0002 0003 0004]'));

      embedSignatureHex(
        bytes,
        contents.start,
        contents.end,
        Uint8List.fromList(const [0xAB, 0xCD]),
      );
      final embedded =
          ascii.decode(bytes.sublist(contents.start, contents.end));
      expect(embedded, 'ABCD00000000');
    });

    test('computeByteRangeDigest matches concat sha256', () {
      final bytes = Uint8List.fromList(List<int>.generate(20, (i) => i));
      const range = [0, 8, 10, 5];
      final expected = PdfCrypto.digestConcatSha256(
        bytes.sublist(0, 8),
        bytes.sublist(10, 15),
      );

      final digest = computeByteRangeDigest(bytes, range);
      expect(digest, expected);
    });

    test('guards invalid range and oversized CMS payload', () {
      final bytes = Uint8List.fromList(
        ascii.encode('<< /ByteRange [0000 0000 0000 0000] /Contents <0000> >>'),
      );
      final contents = findContentsRangeInWindow(bytes, 0, bytes.length);

      expect(
        () => computeByteRangeDigest(bytes, const [0, 1, 2]),
        throwsArgumentError,
      );
      expect(
        () => embedSignatureHex(
          bytes,
          contents.start,
          contents.end,
          Uint8List.fromList(const [0x01, 0x02, 0x03]),
        ),
        throwsStateError,
      );
    });
  });
}
