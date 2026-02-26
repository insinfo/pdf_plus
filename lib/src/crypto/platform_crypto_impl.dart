import 'dart:math' as math;
import 'dart:typed_data';

import 'platform_crypto.dart';
import 'platform_crypto_common.dart';
import 'pure_ecdsa.dart';
import 'pure_ed25519.dart';

class DartPlatformCrypto extends PlatformCrypto {
  const DartPlatformCrypto();

  @override
  Uint8List digestSync(String algorithm, Uint8List data) {
    return digestByName(algorithm, data);
  }

  @override
  Future<Uint8List> digest(String algorithm, Uint8List data) async {
    return digestSync(algorithm, data);
  }

  @override
  Future<Uint8List> sha256(Uint8List data) async {
    return digestSync('SHA-256', data);
  }

  @override
  Future<Uint8List> hmacSha256(Uint8List key, Uint8List data) async {
    return hmacSha256Sync(key, data);
  }

  @override
  Uint8List hmacSha256Sync(Uint8List key, Uint8List data) {
    return hmacByName('SHA-256', key, data);
  }

  @override
  Future<Uint8List> hmacSha1(Uint8List key, Uint8List data) async {
    return hmacSha1Sync(key, data);
  }

  @override
  Uint8List hmacSha1Sync(Uint8List key, Uint8List data) {
    return hmacByName('SHA-1', key, data);
  }

  @override
  Future<Uint8List> hmac(
    String hashAlgorithm,
    Uint8List key,
    Uint8List data,
  ) async {
    return hmacSync(hashAlgorithm, key, data);
  }

  @override
  Uint8List hmacSync(String hashAlgorithm, Uint8List key, Uint8List data) {
    return hmacByName(hashAlgorithm, key, data);
  }

  @override
  Uint8List pbkdf2Sync({
    required String hashAlgorithm,
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int length,
  }) {
    return pbkdf2ByName(
      hashAlgorithm: hashAlgorithm,
      password: password,
      salt: salt,
      iterations: iterations,
      length: length,
    );
  }

  @override
  Future<Uint8List> pbkdf2({
    required String hashAlgorithm,
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int length,
  }) async {
    return pbkdf2Sync(
      hashAlgorithm: hashAlgorithm,
      password: password,
      salt: salt,
      iterations: iterations,
      length: length,
    );
  }

  @override
  Uint8List hkdfSync({
    required String hashAlgorithm,
    required Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    required int length,
  }) {
    return hkdfByName(
      hashAlgorithm: hashAlgorithm,
      ikm: ikm,
      salt: salt,
      info: info,
      length: length,
    );
  }

  @override
  Future<Uint8List> hkdf({
    required String hashAlgorithm,
    required Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    required int length,
  }) async {
    return hkdfSync(
      hashAlgorithm: hashAlgorithm,
      ikm: ikm,
      salt: salt,
      info: info,
      length: length,
    );
  }

  @override
  Future<Uint8List> ecdsaSign({
    required String namedCurve,
    required String hashAlgorithm,
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) async {
    return PureEcDsa.sign(
      namedCurve: namedCurve,
      hashAlgorithm: hashAlgorithm,
      pkcs8PrivateKey: pkcs8PrivateKey,
      data: data,
    );
  }

  @override
  Future<bool> ecdsaVerify({
    required String namedCurve,
    required String hashAlgorithm,
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
  }) async {
    return PureEcDsa.verify(
      namedCurve: namedCurve,
      hashAlgorithm: hashAlgorithm,
      spkiPublicKey: spkiPublicKey,
      data: data,
      signature: signature,
    );
  }

  @override
  Future<Uint8List> ed25519Sign({
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) async {
    return PureEd25519.sign(
      pkcs8PrivateKey: pkcs8PrivateKey,
      data: data,
    );
  }

  @override
  Future<bool> ed25519Verify({
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
  }) async {
    return PureEd25519.verify(
      spkiPublicKey: spkiPublicKey,
      data: data,
      signature: signature,
    );
  }

  @override
  Uint8List randomBytes(int length) {
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'Deve ser >= 0');
    }
    final out = Uint8List(length);
    if (length == 0) return out;
    final random = math.Random.secure();
    for (var i = 0; i < out.length; i++) {
      out[i] = random.nextInt(256);
    }
    return out;
  }

  @override
  String randomUuid() {
    final b = randomBytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    final hex = bytesToHex(b);
    return '${hex.substring(0, 8)}-'
        '${hex.substring(8, 12)}-'
        '${hex.substring(12, 16)}-'
        '${hex.substring(16, 20)}-'
        '${hex.substring(20, 32)}';
  }
}

PlatformCrypto createPlatformCryptoImpl() => const DartPlatformCrypto();
