import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/platform_crypto.dart';

/// Helper centralizado de hash para módulos de assinatura/validação PDF.
class PdfCrypto {
  static final PlatformCrypto _crypto = createPlatformCrypto();

  static Uint8List digestSync(String algorithm, Uint8List data) {
    return _crypto.digestSync(algorithm, data);
  }

  static Uint8List sha1(Uint8List data) => _crypto.sha1Sync(data);
  static Uint8List sha256(Uint8List data) => _crypto.sha256Sync(data);
  static Uint8List sha384(Uint8List data) => _crypto.sha384Sync(data);
  static Uint8List sha512(Uint8List data) => _crypto.sha512Sync(data);
  static Uint8List randomBytes(int length) => _crypto.randomBytes(length);

  static Uint8List digestForOid(Uint8List data, String? digestOid) {
    if (digestOid == '1.3.14.3.2.26') return sha1(data);
    if (digestOid == '2.16.840.1.101.3.4.2.2') return sha384(data);
    if (digestOid == '2.16.840.1.101.3.4.2.3') return sha512(data);
    return sha256(data);
  }

  static Uint8List digestConcatSha256(Uint8List part1, Uint8List part2) {
    final data = Uint8List(part1.length + part2.length);
    data.setRange(0, part1.length, part1);
    data.setRange(part1.length, data.length, part2);
    return sha256(data);
  }
}
