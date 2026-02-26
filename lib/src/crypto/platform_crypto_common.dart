import 'dart:typed_data';

import 'hmac.dart' as digest_hmac;
import 'md5.dart' as digest_md5;
import 'sha1.dart' as digest_sha1;
import 'sha256.dart' as digest_sha256;
import 'sha512.dart' as digest_sha512;

Uint8List digestByName(String algorithm, Uint8List data) {
  switch (algorithm.toUpperCase()) {
    case 'SHA-1':
      return Uint8List.fromList(digest_sha1.sha1.convert(data).bytes);
    case 'SHA-256':
      return Uint8List.fromList(digest_sha256.sha256.convert(data).bytes);
    case 'SHA-384':
      return Uint8List.fromList(digest_sha512.sha384.convert(data).bytes);
    case 'SHA-512':
      return Uint8List.fromList(digest_sha512.sha512.convert(data).bytes);
    case 'MD5':
      return digest_md5.MD5Digest().process(data);
    default:
      throw UnsupportedError('Algoritmo de digest nao suportado: $algorithm');
  }
}

Uint8List hmacByName(String algorithm, Uint8List key, Uint8List data) {
  final normalized = algorithm.toUpperCase();
  if (normalized == 'SHA-1') {
    return digest_hmac.hmacSha1(key, data);
  }

  final digestAlgorithm = _normalizeDigestAlgorithm(normalized);
  final blockSize = _hmacBlockSize(digestAlgorithm);

  var k = Uint8List.fromList(key);
  if (k.length > blockSize) {
    k = digestByName(digestAlgorithm, k);
  }
  if (k.length < blockSize) {
    final padded = Uint8List(blockSize);
    padded.setRange(0, k.length, k);
    k = padded;
  }

  final oKeyPad = Uint8List(blockSize);
  final iKeyPad = Uint8List(blockSize);
  for (var i = 0; i < blockSize; i++) {
    final b = k[i];
    oKeyPad[i] = b ^ 0x5c;
    iKeyPad[i] = b ^ 0x36;
  }

  final innerInput = Uint8List(iKeyPad.length + data.length);
  innerInput.setRange(0, iKeyPad.length, iKeyPad);
  innerInput.setRange(iKeyPad.length, innerInput.length, data);
  final innerHash = digestByName(digestAlgorithm, innerInput);

  final outerInput = Uint8List(oKeyPad.length + innerHash.length);
  outerInput.setRange(0, oKeyPad.length, oKeyPad);
  outerInput.setRange(oKeyPad.length, outerInput.length, innerHash);
  return digestByName(digestAlgorithm, outerInput);
}

Uint8List pbkdf2ByName({
  required String hashAlgorithm,
  required Uint8List password,
  required Uint8List salt,
  required int iterations,
  required int length,
}) {
  if (iterations <= 0) {
    throw ArgumentError.value(iterations, 'iterations', 'Deve ser > 0');
  }
  if (length < 0) {
    throw ArgumentError.value(length, 'length', 'Deve ser >= 0');
  }
  if (length == 0) return Uint8List(0);

  final digestSize = digestByName(hashAlgorithm, Uint8List(0)).length;
  final blocks = (length + digestSize - 1) ~/ digestSize;
  final out = Uint8List(blocks * digestSize);
  var outOffset = 0;

  for (var blockIndex = 1; blockIndex <= blocks; blockIndex++) {
    final saltAndBlock = Uint8List(salt.length + 4);
    saltAndBlock.setRange(0, salt.length, salt);
    saltAndBlock[salt.length] = (blockIndex >> 24) & 0xff;
    saltAndBlock[salt.length + 1] = (blockIndex >> 16) & 0xff;
    saltAndBlock[salt.length + 2] = (blockIndex >> 8) & 0xff;
    saltAndBlock[salt.length + 3] = blockIndex & 0xff;

    var u = hmacByName(hashAlgorithm, password, saltAndBlock);
    final t = Uint8List.fromList(u);

    for (var i = 1; i < iterations; i++) {
      u = hmacByName(hashAlgorithm, password, u);
      for (var j = 0; j < t.length; j++) {
        t[j] ^= u[j];
      }
    }

    out.setRange(outOffset, outOffset + t.length, t);
    outOffset += t.length;
  }

  return Uint8List.sublistView(out, 0, length);
}

Uint8List hkdfByName({
  required String hashAlgorithm,
  required Uint8List ikm,
  Uint8List? salt,
  Uint8List? info,
  required int length,
}) {
  if (length < 0) {
    throw ArgumentError.value(length, 'length', 'Deve ser >= 0');
  }
  if (length == 0) return Uint8List(0);

  final digestSize = digestByName(hashAlgorithm, Uint8List(0)).length;
  final blocks = (length + digestSize - 1) ~/ digestSize;
  if (blocks > 255) {
    throw ArgumentError.value(length, 'length', 'Excede limite HKDF (255 blocos)');
  }

  final effectiveSalt =
      salt == null || salt.isEmpty ? Uint8List(digestSize) : salt;
  final prk = hmacByName(hashAlgorithm, effectiveSalt, ikm);
  final context = info ?? Uint8List(0);

  final okm = Uint8List(blocks * digestSize);
  var previous = Uint8List(0);
  var offset = 0;

  for (var i = 1; i <= blocks; i++) {
    final input = Uint8List(previous.length + context.length + 1);
    if (previous.isNotEmpty) {
      input.setRange(0, previous.length, previous);
    }
    if (context.isNotEmpty) {
      input.setRange(previous.length, previous.length + context.length, context);
    }
    input[input.length - 1] = i;
    final block = hmacByName(hashAlgorithm, prk, input);
    okm.setRange(offset, offset + block.length, block);
    offset += block.length;
    previous = block;
  }

  return Uint8List.sublistView(okm, 0, length);
}

String _normalizeDigestAlgorithm(String algorithm) {
  switch (algorithm) {
    case 'SHA1':
      return 'SHA-1';
    case 'SHA256':
      return 'SHA-256';
    case 'SHA384':
      return 'SHA-384';
    case 'SHA512':
      return 'SHA-512';
    default:
      return algorithm;
  }
}

int _hmacBlockSize(String digestAlgorithm) {
  switch (digestAlgorithm.toUpperCase()) {
    case 'SHA-384':
    case 'SHA-512':
      return 128;
    default:
      return 64;
  }
}
