import 'dart:typed_data';

import 'platform_crypto_impl.dart'
    if (dart.library.html) 'platform_crypto_web.dart';

abstract class PlatformCrypto {
  const PlatformCrypto();

  Uint8List digestSync(String algorithm, Uint8List data);

  Future<Uint8List> digest(String algorithm, Uint8List data);

  Future<Uint8List> sha1(Uint8List data) => digest('SHA-1', data);
  Uint8List sha1Sync(Uint8List data) => digestSync('SHA-1', data);

  Future<Uint8List> sha256(Uint8List data);
  Uint8List sha256Sync(Uint8List data) => digestSync('SHA-256', data);

  Future<Uint8List> sha384(Uint8List data) => digest('SHA-384', data);
  Uint8List sha384Sync(Uint8List data) => digestSync('SHA-384', data);

  Future<Uint8List> sha512(Uint8List data) => digest('SHA-512', data);
  Uint8List sha512Sync(Uint8List data) => digestSync('SHA-512', data);

  Future<Uint8List> md5(Uint8List data) => digest('MD5', data);
  Uint8List md5Sync(Uint8List data) => digestSync('MD5', data);

  Future<Uint8List> hmacSha256(Uint8List key, Uint8List data);
  Uint8List hmacSha256Sync(Uint8List key, Uint8List data);

  Future<Uint8List> hmacSha1(Uint8List key, Uint8List data);
  Uint8List hmacSha1Sync(Uint8List key, Uint8List data);

  Future<Uint8List> hmac(String hashAlgorithm, Uint8List key, Uint8List data) {
    if (hashAlgorithm.toUpperCase() == 'SHA-1') {
      return hmacSha1(key, data);
    }
    return hmacSha256(key, data);
  }

  Uint8List hmacSync(String hashAlgorithm, Uint8List key, Uint8List data) {
    if (hashAlgorithm.toUpperCase() == 'SHA-1') {
      return hmacSha1Sync(key, data);
    }
    return hmacSha256Sync(key, data);
  }

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

  Uint8List pbkdf2Sync({
    required String hashAlgorithm,
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int length,
  });

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

  Uint8List hkdfSync({
    required String hashAlgorithm,
    required Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    required int length,
  });

  Future<Uint8List> aesGcmEncrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List plaintext,
    Uint8List? additionalData,
    int tagLengthBits = 128,
  }) {
    throw UnsupportedError('AES-GCM nao suportado nesta plataforma');
  }

  Future<Uint8List> aesGcmDecrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List ciphertextWithTag,
    Uint8List? additionalData,
    int tagLengthBits = 128,
  }) {
    throw UnsupportedError('AES-GCM nao suportado nesta plataforma');
  }

  Future<Uint8List> aesCbcEncrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List plaintext,
  }) {
    throw UnsupportedError('AES-CBC nao suportado nesta plataforma');
  }

  Future<Uint8List> aesCbcDecrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List ciphertext,
  }) {
    throw UnsupportedError('AES-CBC nao suportado nesta plataforma');
  }

  Future<Uint8List> rsaPkcs1v15Sign({
    required String hashAlgorithm,
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) {
    throw UnsupportedError('RSASSA-PKCS1-v1_5 nao suportado nesta plataforma');
  }

  Future<bool> rsaPkcs1v15Verify({
    required String hashAlgorithm,
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
  }) {
    throw UnsupportedError('RSASSA-PKCS1-v1_5 nao suportado nesta plataforma');
  }

  Future<Uint8List> rsaPssSign({
    required String hashAlgorithm,
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
    int saltLength = 32,
  }) {
    throw UnsupportedError('RSA-PSS nao suportado nesta plataforma');
  }

  Future<bool> rsaPssVerify({
    required String hashAlgorithm,
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
    int saltLength = 32,
  }) {
    throw UnsupportedError('RSA-PSS nao suportado nesta plataforma');
  }

  Future<Uint8List> ecdsaSign({
    required String namedCurve,
    required String hashAlgorithm,
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) {
    throw UnsupportedError('ECDSA nao suportado nesta plataforma');
  }

  Future<bool> ecdsaVerify({
    required String namedCurve,
    required String hashAlgorithm,
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
  }) {
    throw UnsupportedError('ECDSA nao suportado nesta plataforma');
  }

  Future<Uint8List> ed25519Sign({
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) {
    throw UnsupportedError('Ed25519 nao suportado nesta plataforma');
  }

  Future<bool> ed25519Verify({
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
  }) {
    throw UnsupportedError('Ed25519 nao suportado nesta plataforma');
  }

  Uint8List randomBytes(int length);

  String randomUuid();
}

PlatformCrypto createPlatformCrypto() => createPlatformCryptoImpl();

Future<Uint8List> sha256Bytes(Uint8List data) {
  return createPlatformCrypto().sha256(data);
}

Future<Uint8List> digestBytes(String algorithm, Uint8List data) {
  return createPlatformCrypto().digest(algorithm, data);
}

String bytesToHex(Uint8List bytes) {
  final b = StringBuffer();
  for (final v in bytes) {
    b.write(v.toRadixString(16).padLeft(2, '0'));
  }
  return b.toString();
}
