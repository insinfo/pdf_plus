import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/platform_crypto.dart';
import 'package:pdf_plus/src/crypto/rsa_keys.dart';
import 'package:pdf_plus/src/crypto/rsa_pkcs1v15.dart';

/// Adapter único para assinatura/verificação assimétrica.
///
/// - RSA PKCS#1 v1.5 via engine interno.
/// - ECDSA/Ed25519 via [PlatformCrypto] (Web Crypto no browser).
class SignatureAdapter {
  SignatureAdapter({PlatformCrypto? crypto})
      : _crypto = crypto ?? createPlatformCrypto();

  final PlatformCrypto _crypto;

  Uint8List rsaPkcs1v15SignDigest({
    required RSAPrivateKey privateKey,
    required Uint8List digest,
    String? digestOid,
  }) {
    return RsaPkcs1v15.signDigest(
      privateKey: privateKey,
      digest: digest,
      digestOid: digestOid,
    );
  }

  bool rsaPkcs1v15VerifyDigest({
    required RSAPublicKey publicKey,
    required Uint8List digest,
    required Uint8List signature,
    String? digestOid,
  }) {
    return RsaPkcs1v15.verifyDigest(
      publicKey: publicKey,
      digest: digest,
      signature: signature,
      digestOid: digestOid,
    );
  }

  Future<Uint8List> ecdsaSignDer({
    required String namedCurve,
    required String hashAlgorithm,
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) async {
    final signature = await _crypto.ecdsaSign(
      namedCurve: namedCurve,
      hashAlgorithm: hashAlgorithm,
      pkcs8PrivateKey: pkcs8PrivateKey,
      data: data,
    );
    if (_looksLikeDer(signature)) {
      return signature;
    }
    return ecdsaRawToDer(signature, namedCurve: namedCurve);
  }

  Future<bool> ecdsaVerifyDer({
    required String namedCurve,
    required String hashAlgorithm,
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List derSignature,
  }) async {
    final firstTry = await _crypto.ecdsaVerify(
      namedCurve: namedCurve,
      hashAlgorithm: hashAlgorithm,
      spkiPublicKey: spkiPublicKey,
      data: data,
      signature: derSignature,
    );
    if (firstTry) return true;
    try {
      final raw = ecdsaDerToRaw(derSignature, namedCurve: namedCurve);
      return _crypto.ecdsaVerify(
        namedCurve: namedCurve,
        hashAlgorithm: hashAlgorithm,
        spkiPublicKey: spkiPublicKey,
        data: data,
        signature: raw,
      );
    } catch (_) {
      return false;
    }
  }

  Future<Uint8List> ed25519Sign({
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) {
    return _crypto.ed25519Sign(
      pkcs8PrivateKey: pkcs8PrivateKey,
      data: data,
    );
  }

  Future<bool> ed25519Verify({
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
  }) {
    return _crypto.ed25519Verify(
      spkiPublicKey: spkiPublicKey,
      data: data,
      signature: signature,
    );
  }

  Uint8List rsaPkcs1v15SignData({
    required RSAPrivateKey privateKey,
    required Uint8List data,
    String? digestOid,
  }) {
    return RsaPkcs1v15.signData(
      privateKey: privateKey,
      data: data,
      digestOid: digestOid,
    );
  }

  bool rsaPkcs1v15VerifyData({
    required RSAPublicKey publicKey,
    required Uint8List data,
    required Uint8List signature,
    String? digestOid,
  }) {
    return RsaPkcs1v15.verifyData(
      publicKey: publicKey,
      data: data,
      signature: signature,
      digestOid: digestOid,
    );
  }

  Future<Uint8List> rsaPkcs1v15SignPkcs8({
    required String hashAlgorithm,
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) {
    return _crypto.rsaPkcs1v15Sign(
      hashAlgorithm: hashAlgorithm,
      pkcs8PrivateKey: pkcs8PrivateKey,
      data: data,
    );
  }

  Future<bool> rsaPkcs1v15VerifySpki({
    required String hashAlgorithm,
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
  }) {
    return _crypto.rsaPkcs1v15Verify(
      hashAlgorithm: hashAlgorithm,
      spkiPublicKey: spkiPublicKey,
      data: data,
      signature: signature,
    );
  }

  Future<Uint8List> rsaPssSignPkcs8({
    required String hashAlgorithm,
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
    int saltLength = 32,
  }) {
    return _crypto.rsaPssSign(
      hashAlgorithm: hashAlgorithm,
      pkcs8PrivateKey: pkcs8PrivateKey,
      data: data,
      saltLength: saltLength,
    );
  }

  Future<bool> rsaPssVerifySpki({
    required String hashAlgorithm,
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
    int saltLength = 32,
  }) {
    return _crypto.rsaPssVerify(
      hashAlgorithm: hashAlgorithm,
      spkiPublicKey: spkiPublicKey,
      data: data,
      signature: signature,
      saltLength: saltLength,
    );
  }

  static Uint8List ecdsaDerToRaw(
    Uint8List derSignature, {
    required String namedCurve,
  }) {
    final coordinateLength = curveCoordinateLength(namedCurve);
    if (derSignature.isEmpty || derSignature[0] != 0x30) {
      throw ArgumentError('ECDSA DER inválida');
    }
    final (seqLen, seqLenBytes) = _readDerLength(derSignature, 1);
    final seqStart = 1 + seqLenBytes;
    if (seqStart + seqLen > derSignature.length) {
      throw ArgumentError('ECDSA DER truncada');
    }
    var offset = seqStart;
    if (derSignature[offset] != 0x02) {
      throw ArgumentError('ECDSA DER inválida (R)');
    }
    final (rLen, rLenBytes) = _readDerLength(derSignature, offset + 1);
    final rStart = offset + 1 + rLenBytes;
    final r = derSignature.sublist(rStart, rStart + rLen);
    offset = rStart + rLen;
    if (derSignature[offset] != 0x02) {
      throw ArgumentError('ECDSA DER inválida (S)');
    }
    final (sLen, sLenBytes) = _readDerLength(derSignature, offset + 1);
    final sStart = offset + 1 + sLenBytes;
    final s = derSignature.sublist(sStart, sStart + sLen);

    final raw = Uint8List(coordinateLength * 2);
    _copyBigIntBytesToFixed(r, raw, 0, coordinateLength);
    _copyBigIntBytesToFixed(s, raw, coordinateLength, coordinateLength);
    return raw;
  }

  static Uint8List ecdsaRawToDer(
    Uint8List rawSignature, {
    required String namedCurve,
  }) {
    final coordinateLength = curveCoordinateLength(namedCurve);
    final expectedLength = coordinateLength * 2;
    if (rawSignature.length != expectedLength) {
      throw ArgumentError(
        'Assinatura raw ECDSA deve ter $expectedLength bytes para $namedCurve',
      );
    }
    final r = rawSignature.sublist(0, coordinateLength);
    final s = rawSignature.sublist(coordinateLength, expectedLength);
    final derR = _encodeDerInteger(r);
    final derS = _encodeDerInteger(s);
    final content = Uint8List(derR.length + derS.length);
    content.setRange(0, derR.length, derR);
    content.setRange(derR.length, content.length, derS);

    final lenBytes = _encodeDerLength(content.length);
    final out = Uint8List(1 + lenBytes.length + content.length);
    out[0] = 0x30;
    out.setRange(1, 1 + lenBytes.length, lenBytes);
    out.setRange(1 + lenBytes.length, out.length, content);
    return out;
  }

  static int curveCoordinateLength(String namedCurve) {
    switch (namedCurve.toUpperCase()) {
      case 'P-256':
      case 'SECP256R1':
      case 'BRAINPOOLP256R1':
        return 32;
      case 'P-384':
      case 'SECP384R1':
        return 48;
      case 'P-521':
      case 'SECP521R1':
      case 'BRAINPOOLP512R1':
        return 66;
      default:
        throw UnsupportedError('Curva ECDSA não suportada: $namedCurve');
    }
  }

  static bool _looksLikeDer(Uint8List signature) {
    return signature.length >= 8 && signature.first == 0x30;
  }

  static (int, int) _readDerLength(Uint8List bytes, int offset) {
    if (offset >= bytes.length) {
      throw ArgumentError('DER length fora do range');
    }
    final first = bytes[offset];
    if ((first & 0x80) == 0) {
      return (first, 1);
    }
    final count = first & 0x7F;
    if (count <= 0 || count > 4 || offset + 1 + count > bytes.length) {
      throw ArgumentError('DER length inválido');
    }
    var length = 0;
    for (var i = 0; i < count; i++) {
      length = (length << 8) | bytes[offset + 1 + i];
    }
    return (length, 1 + count);
  }

  static Uint8List _encodeDerLength(int value) {
    if (value < 128) {
      return Uint8List.fromList(<int>[value]);
    }
    final bytes = <int>[];
    var n = value;
    while (n > 0) {
      bytes.insert(0, n & 0xff);
      n >>= 8;
    }
    return Uint8List.fromList(<int>[0x80 | bytes.length, ...bytes]);
  }

  static Uint8List _encodeDerInteger(Uint8List value) {
    var start = 0;
    while (start < value.length - 1 && value[start] == 0) {
      start++;
    }
    var normalized = value.sublist(start);
    if (normalized.isEmpty) {
      normalized = Uint8List.fromList(<int>[0]);
    }
    final needsSignPad = (normalized.first & 0x80) != 0;
    final content = needsSignPad
        ? Uint8List.fromList(<int>[0, ...normalized])
        : Uint8List.fromList(normalized);
    final lenBytes = _encodeDerLength(content.length);
    final out = Uint8List(1 + lenBytes.length + content.length);
    out[0] = 0x02;
    out.setRange(1, 1 + lenBytes.length, lenBytes);
    out.setRange(1 + lenBytes.length, out.length, content);
    return out;
  }

  static void _copyBigIntBytesToFixed(
    Uint8List value,
    Uint8List out,
    int outOffset,
    int width,
  ) {
    var start = 0;
    while (start < value.length - 1 && value[start] == 0) {
      start++;
    }
    final normalized = value.sublist(start);
    if (normalized.length > width) {
      throw ArgumentError('Inteiro ECDSA maior que tamanho esperado');
    }
    final pad = width - normalized.length;
    for (var i = 0; i < pad; i++) {
      out[outOffset + i] = 0;
    }
    out.setRange(outOffset + pad, outOffset + width, normalized);
  }
}
