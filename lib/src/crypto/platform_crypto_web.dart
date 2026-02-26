import 'dart:html' as html;
import 'dart:js_util' as js_util;
import 'dart:math' as math;
import 'dart:typed_data';

import 'platform_crypto.dart';
import 'platform_crypto_common.dart';

class WebPlatformCrypto extends PlatformCrypto {
  const WebPlatformCrypto();

  @override
  Uint8List digestSync(String algorithm, Uint8List data) {
    return digestByName(algorithm.toUpperCase(), data);
  }

  @override
  Future<Uint8List> digest(String algorithm, Uint8List data) async {
    final normalized = algorithm.toUpperCase();
    try {
      final subtle = html.window.crypto?.subtle;
      if (subtle == null) {
        return digestByName(normalized, data);
      }
      final digestBuffer = await js_util.promiseToFuture<Object>(
        js_util.callMethod<Object>(
          subtle,
          'digest',
          <Object>[normalized, data],
        ),
      );
      return Uint8List.view(digestBuffer as ByteBuffer);
    } catch (_) {
      return digestByName(normalized, data);
    }
  }

  @override
  Future<Uint8List> sha256(Uint8List data) async {
    return digest('SHA-256', data);
  }

  @override
  Future<Uint8List> hmacSha256(Uint8List key, Uint8List data) async {
    return hmac('SHA-256', key, data);
  }

  @override
  Uint8List hmacSha256Sync(Uint8List key, Uint8List data) {
    return hmacByName('SHA-256', key, data);
  }

  @override
  Future<Uint8List> hmacSha1(Uint8List key, Uint8List data) async {
    return hmac('SHA-1', key, data);
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
    try {
      final subtle = html.window.crypto?.subtle;
      if (subtle == null) {
        return hmacSync(hashAlgorithm, key, data);
      }
      final algorithm = js_util.jsify(<String, Object>{
        'name': 'HMAC',
        'hash': hashAlgorithm.toUpperCase(),
      });
      final cryptoKey = await js_util.promiseToFuture<Object>(
        js_util.callMethod<Object>(
          subtle,
          'importKey',
          <Object>[
            'raw',
            key,
            algorithm,
            false,
            <String>['sign'],
          ],
        ),
      );
      final signatureBuffer = await js_util.promiseToFuture<Object>(
        js_util.callMethod<Object>(
          subtle,
          'sign',
          <Object>[
            'HMAC',
            cryptoKey,
            data,
          ],
        ),
      );
      return Uint8List.view(signatureBuffer as ByteBuffer);
    } catch (_) {
      return hmacSync(hashAlgorithm, key, data);
    }
  }

  @override
  Uint8List hmacSync(String hashAlgorithm, Uint8List key, Uint8List data) {
    return hmacByName(hashAlgorithm, key, data);
  }

  @override
  Future<Uint8List> pbkdf2({
    required String hashAlgorithm,
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int length,
  }) async {
    try {
      final subtle = html.window.crypto?.subtle;
      if (subtle == null) {
        return pbkdf2Sync(
          hashAlgorithm: hashAlgorithm,
          password: password,
          salt: salt,
          iterations: iterations,
          length: length,
        );
      }
      final baseKey = await js_util.promiseToFuture<Object>(
        js_util.callMethod<Object>(subtle, 'importKey', <Object>[
          'raw',
          password,
          js_util.jsify(<String, Object>{'name': 'PBKDF2'}),
          false,
          <String>['deriveBits'],
        ]),
      );
      final params = js_util.jsify(<String, Object>{
        'name': 'PBKDF2',
        'hash': hashAlgorithm.toUpperCase(),
        'salt': salt,
        'iterations': iterations,
      });
      final bits = await js_util.promiseToFuture<Object>(
        js_util.callMethod<Object>(
          subtle,
          'deriveBits',
          <Object>[params, baseKey, length * 8],
        ),
      );
      return Uint8List.view(bits as ByteBuffer);
    } catch (_) {
      return pbkdf2Sync(
        hashAlgorithm: hashAlgorithm,
        password: password,
        salt: salt,
        iterations: iterations,
        length: length,
      );
    }
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
  Future<Uint8List> hkdf({
    required String hashAlgorithm,
    required Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    required int length,
  }) async {
    try {
      final subtle = html.window.crypto?.subtle;
      if (subtle == null) {
        return hkdfSync(
          hashAlgorithm: hashAlgorithm,
          ikm: ikm,
          salt: salt,
          info: info,
          length: length,
        );
      }
      final baseKey = await js_util.promiseToFuture<Object>(
        js_util.callMethod<Object>(subtle, 'importKey', <Object>[
          'raw',
          ikm,
          js_util.jsify(<String, Object>{'name': 'HKDF'}),
          false,
          <String>['deriveBits'],
        ]),
      );
      final params = js_util.jsify(<String, Object>{
        'name': 'HKDF',
        'hash': hashAlgorithm.toUpperCase(),
        'salt': salt ?? Uint8List(0),
        'info': info ?? Uint8List(0),
      });
      final bits = await js_util.promiseToFuture<Object>(
        js_util.callMethod<Object>(
          subtle,
          'deriveBits',
          <Object>[params, baseKey, length * 8],
        ),
      );
      return Uint8List.view(bits as ByteBuffer);
    } catch (_) {
      return hkdfSync(
        hashAlgorithm: hashAlgorithm,
        ikm: ikm,
        salt: salt,
        info: info,
        length: length,
      );
    }
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
  Future<Uint8List> aesGcmEncrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List plaintext,
    Uint8List? additionalData,
    int tagLengthBits = 128,
  }) async {
    final subtle = html.window.crypto?.subtle;
    if (subtle == null) {
      throw UnsupportedError('AES-GCM indisponivel sem SubtleCrypto');
    }
    final cryptoKey = await _importAesKey(
      subtle: subtle,
      key: key,
      algorithmName: 'AES-GCM',
      usages: const <String>['encrypt'],
    );
    final params = js_util.jsify(<String, Object>{
      'name': 'AES-GCM',
      'iv': iv,
      'tagLength': tagLengthBits,
      if (additionalData != null) 'additionalData': additionalData,
    });
    final encrypted = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(
        subtle,
        'encrypt',
        <Object>[params, cryptoKey, plaintext],
      ),
    );
    return Uint8List.view(encrypted as ByteBuffer);
  }

  @override
  Future<Uint8List> aesGcmDecrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List ciphertextWithTag,
    Uint8List? additionalData,
    int tagLengthBits = 128,
  }) async {
    final subtle = html.window.crypto?.subtle;
    if (subtle == null) {
      throw UnsupportedError('AES-GCM indisponivel sem SubtleCrypto');
    }
    final cryptoKey = await _importAesKey(
      subtle: subtle,
      key: key,
      algorithmName: 'AES-GCM',
      usages: const <String>['decrypt'],
    );
    final params = js_util.jsify(<String, Object>{
      'name': 'AES-GCM',
      'iv': iv,
      'tagLength': tagLengthBits,
      if (additionalData != null) 'additionalData': additionalData,
    });
    final decrypted = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(
        subtle,
        'decrypt',
        <Object>[params, cryptoKey, ciphertextWithTag],
      ),
    );
    return Uint8List.view(decrypted as ByteBuffer);
  }

  @override
  Future<Uint8List> aesCbcEncrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List plaintext,
  }) async {
    final subtle = html.window.crypto?.subtle;
    if (subtle == null) {
      throw UnsupportedError('AES-CBC indisponivel sem SubtleCrypto');
    }
    final cryptoKey = await _importAesKey(
      subtle: subtle,
      key: key,
      algorithmName: 'AES-CBC',
      usages: const <String>['encrypt'],
    );
    final params = js_util.jsify(<String, Object>{
      'name': 'AES-CBC',
      'iv': iv,
    });
    final encrypted = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(
        subtle,
        'encrypt',
        <Object>[params, cryptoKey, plaintext],
      ),
    );
    return Uint8List.view(encrypted as ByteBuffer);
  }

  @override
  Future<Uint8List> aesCbcDecrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List ciphertext,
  }) async {
    final subtle = html.window.crypto?.subtle;
    if (subtle == null) {
      throw UnsupportedError('AES-CBC indisponivel sem SubtleCrypto');
    }
    final cryptoKey = await _importAesKey(
      subtle: subtle,
      key: key,
      algorithmName: 'AES-CBC',
      usages: const <String>['decrypt'],
    );
    final params = js_util.jsify(<String, Object>{
      'name': 'AES-CBC',
      'iv': iv,
    });
    final decrypted = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(
        subtle,
        'decrypt',
        <Object>[params, cryptoKey, ciphertext],
      ),
    );
    return Uint8List.view(decrypted as ByteBuffer);
  }

  @override
  Future<Uint8List> rsaPkcs1v15Sign({
    required String hashAlgorithm,
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) async {
    final subtle = html.window.crypto?.subtle;
    if (subtle == null) {
      throw UnsupportedError('RSASSA-PKCS1-v1_5 indisponivel sem SubtleCrypto');
    }
    final algorithm = js_util.jsify(<String, Object>{
      'name': 'RSASSA-PKCS1-v1_5',
      'hash': {'name': hashAlgorithm.toUpperCase()},
    });
    final privateKey = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(subtle, 'importKey', <Object>[
        'pkcs8',
        pkcs8PrivateKey,
        algorithm,
        false,
        <String>['sign'],
      ]),
    );
    final signature = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(
        subtle,
        'sign',
        <Object>[
          js_util.jsify(<String, Object>{'name': 'RSASSA-PKCS1-v1_5'}),
          privateKey,
          data,
        ],
      ),
    );
    return Uint8List.view(signature as ByteBuffer);
  }

  @override
  Future<bool> rsaPkcs1v15Verify({
    required String hashAlgorithm,
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
  }) async {
    final subtle = html.window.crypto?.subtle;
    if (subtle == null) {
      throw UnsupportedError('RSASSA-PKCS1-v1_5 indisponivel sem SubtleCrypto');
    }
    final algorithm = js_util.jsify(<String, Object>{
      'name': 'RSASSA-PKCS1-v1_5',
      'hash': {'name': hashAlgorithm.toUpperCase()},
    });
    final publicKey = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(subtle, 'importKey', <Object>[
        'spki',
        spkiPublicKey,
        algorithm,
        false,
        <String>['verify'],
      ]),
    );
    return js_util.promiseToFuture<bool>(
      js_util.callMethod<Object>(
        subtle,
        'verify',
        <Object>[
          js_util.jsify(<String, Object>{'name': 'RSASSA-PKCS1-v1_5'}),
          publicKey,
          signature,
          data,
        ],
      ),
    );
  }

  @override
  Future<Uint8List> rsaPssSign({
    required String hashAlgorithm,
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
    int saltLength = 32,
  }) async {
    final subtle = html.window.crypto?.subtle;
    if (subtle == null) {
      throw UnsupportedError('RSA-PSS indisponivel sem SubtleCrypto');
    }
    final algorithm = js_util.jsify(<String, Object>{
      'name': 'RSA-PSS',
      'hash': {'name': hashAlgorithm.toUpperCase()},
    });
    final privateKey = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(subtle, 'importKey', <Object>[
        'pkcs8',
        pkcs8PrivateKey,
        algorithm,
        false,
        <String>['sign'],
      ]),
    );
    final signature = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(
        subtle,
        'sign',
        <Object>[
          js_util.jsify(<String, Object>{
            'name': 'RSA-PSS',
            'saltLength': saltLength,
          }),
          privateKey,
          data,
        ],
      ),
    );
    return Uint8List.view(signature as ByteBuffer);
  }

  @override
  Future<bool> rsaPssVerify({
    required String hashAlgorithm,
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
    int saltLength = 32,
  }) async {
    final subtle = html.window.crypto?.subtle;
    if (subtle == null) {
      throw UnsupportedError('RSA-PSS indisponivel sem SubtleCrypto');
    }
    final algorithm = js_util.jsify(<String, Object>{
      'name': 'RSA-PSS',
      'hash': {'name': hashAlgorithm.toUpperCase()},
    });
    final publicKey = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(subtle, 'importKey', <Object>[
        'spki',
        spkiPublicKey,
        algorithm,
        false,
        <String>['verify'],
      ]),
    );
    return js_util.promiseToFuture<bool>(
      js_util.callMethod<Object>(
        subtle,
        'verify',
        <Object>[
          js_util.jsify(<String, Object>{
            'name': 'RSA-PSS',
            'saltLength': saltLength,
          }),
          publicKey,
          signature,
          data,
        ],
      ),
    );
  }

  @override
  Future<Uint8List> ecdsaSign({
    required String namedCurve,
    required String hashAlgorithm,
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) async {
    final subtle = html.window.crypto?.subtle;
    if (subtle == null) {
      throw UnsupportedError('ECDSA indisponivel sem SubtleCrypto');
    }
    final importAlgorithm = js_util.jsify(<String, Object>{
      'name': 'ECDSA',
      'namedCurve': namedCurve,
    });
    final privateKey = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(subtle, 'importKey', <Object>[
        'pkcs8',
        pkcs8PrivateKey,
        importAlgorithm,
        false,
        <String>['sign'],
      ]),
    );
    final signAlgorithm = js_util.jsify(<String, Object>{
      'name': 'ECDSA',
      'hash': {'name': hashAlgorithm.toUpperCase()},
    });
    final signature = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(
        subtle,
        'sign',
        <Object>[signAlgorithm, privateKey, data],
      ),
    );
    return Uint8List.view(signature as ByteBuffer);
  }

  @override
  Future<bool> ecdsaVerify({
    required String namedCurve,
    required String hashAlgorithm,
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
  }) async {
    final subtle = html.window.crypto?.subtle;
    if (subtle == null) {
      throw UnsupportedError('ECDSA indisponivel sem SubtleCrypto');
    }
    final importAlgorithm = js_util.jsify(<String, Object>{
      'name': 'ECDSA',
      'namedCurve': namedCurve,
    });
    final publicKey = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(subtle, 'importKey', <Object>[
        'spki',
        spkiPublicKey,
        importAlgorithm,
        false,
        <String>['verify'],
      ]),
    );
    final verifyAlgorithm = js_util.jsify(<String, Object>{
      'name': 'ECDSA',
      'hash': {'name': hashAlgorithm.toUpperCase()},
    });
    return js_util.promiseToFuture<bool>(
      js_util.callMethod<Object>(
        subtle,
        'verify',
        <Object>[verifyAlgorithm, publicKey, signature, data],
      ),
    );
  }

  @override
  Future<Uint8List> ed25519Sign({
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) async {
    final subtle = html.window.crypto?.subtle;
    if (subtle == null) {
      throw UnsupportedError('Ed25519 indisponivel sem SubtleCrypto');
    }
    final privateKey = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(subtle, 'importKey', <Object>[
        'pkcs8',
        pkcs8PrivateKey,
        js_util.jsify(<String, Object>{'name': 'Ed25519'}),
        false,
        <String>['sign'],
      ]),
    );
    final signature = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(
        subtle,
        'sign',
        <Object>[js_util.jsify(<String, Object>{'name': 'Ed25519'}), privateKey, data],
      ),
    );
    return Uint8List.view(signature as ByteBuffer);
  }

  @override
  Future<bool> ed25519Verify({
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
  }) async {
    final subtle = html.window.crypto?.subtle;
    if (subtle == null) {
      throw UnsupportedError('Ed25519 indisponivel sem SubtleCrypto');
    }
    final publicKey = await js_util.promiseToFuture<Object>(
      js_util.callMethod<Object>(subtle, 'importKey', <Object>[
        'spki',
        spkiPublicKey,
        js_util.jsify(<String, Object>{'name': 'Ed25519'}),
        false,
        <String>['verify'],
      ]),
    );
    return js_util.promiseToFuture<bool>(
      js_util.callMethod<Object>(
        subtle,
        'verify',
        <Object>[js_util.jsify(<String, Object>{'name': 'Ed25519'}), publicKey, signature, data],
      ),
    );
  }

  @override
  Uint8List randomBytes(int length) {
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'Deve ser >= 0');
    }
    final out = Uint8List(length);
    if (length == 0) return out;
    try {
      final crypto = html.window.crypto;
      if (crypto != null) {
        var offset = 0;
        const maxChunk = 65536;
        while (offset < out.length) {
          final end = (offset + maxChunk < out.length)
              ? offset + maxChunk
              : out.length;
          final view = Uint8List.sublistView(out, offset, end);
          js_util.callMethod<Object>(crypto, 'getRandomValues', <Object>[view]);
          offset = end;
        }
        return out;
      }
    } catch (_) {}
    final fallback = math.Random();
    for (var i = 0; i < out.length; i++) {
      out[i] = fallback.nextInt(256);
    }
    return out;
  }

  @override
  String randomUuid() {
    try {
      final crypto = html.window.crypto;
      if (crypto != null && js_util.hasProperty(crypto, 'randomUUID')) {
        return js_util.callMethod<String>(crypto, 'randomUUID', const <Object>[]);
      }
    } catch (_) {}
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

PlatformCrypto createPlatformCryptoImpl() => const WebPlatformCrypto();

Future<Object> _importAesKey({
  required Object subtle,
  required Uint8List key,
  required String algorithmName,
  required List<String> usages,
}) async {
  return js_util.promiseToFuture<Object>(
    js_util.callMethod<Object>(subtle, 'importKey', <Object>[
      'raw',
      key,
      js_util.jsify(<String, Object>{'name': algorithmName}),
      false,
      usages,
    ]),
  );
}
