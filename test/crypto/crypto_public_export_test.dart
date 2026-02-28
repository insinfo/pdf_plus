import 'dart:typed_data';

import 'package:pdf_plus/crypto.dart';
import 'package:test/test.dart';

void main() {
  test('public crypto entrypoint exposes platform crypto facade', () async {
    final crypto = createPlatformCrypto();
    final digest = await crypto.sha256(Uint8List.fromList('abc'.codeUnits));

    expect(crypto, isA<PlatformCrypto>());
    expect(digest.length, 32);
  });
}
