import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/asn1/asn1.dart';
import 'package:pdf_plus/src/crypto/base.dart';
import 'package:pdf_plus/src/crypto/pkcs1.dart';
import 'package:pdf_plus/src/crypto/platform_crypto.dart';
import 'package:pdf_plus/src/crypto/rsa_engine.dart';
import 'package:pdf_plus/src/crypto/rsa_keys.dart';

/// Utility for RSA PKCS#1 v1.5 sign/verify using platform hashing.
class RsaPkcs1v15 {
  static final PlatformCrypto _crypto = createPlatformCrypto();

  static const String sha1Oid = '1.3.14.3.2.26';
  static const String sha256Oid = '2.16.840.1.101.3.4.2.1';
  static const String sha384Oid = '2.16.840.1.101.3.4.2.2';
  static const String sha512Oid = '2.16.840.1.101.3.4.2.3';

  static String normalizeDigestOid(String? digestOid) {
    switch (digestOid) {
      case sha1Oid:
      case sha256Oid:
      case sha384Oid:
      case sha512Oid:
        return digestOid!;
      default:
        return sha256Oid;
    }
  }

  static Uint8List digestForOid(Uint8List data, String? digestOid) {
    switch (normalizeDigestOid(digestOid)) {
      case sha1Oid:
        return _crypto.sha1Sync(data);
      case sha384Oid:
        return _crypto.sha384Sync(data);
      case sha512Oid:
        return _crypto.sha512Sync(data);
      case sha256Oid:
      default:
        return _crypto.sha256Sync(data);
    }
  }

  static Uint8List buildDigestInfo(Uint8List digest, {String? digestOid}) {
    final oid = normalizeDigestOid(digestOid);
    final algId = ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromComponentString(oid))
      ..add(ASN1Null());
    final digestInfo = ASN1Sequence()
      ..add(algId)
      ..add(ASN1OctetString(digest));
    return digestInfo.encodedBytes;
  }

  static Uint8List buildDigestInfoFromData(
    Uint8List data, {
    String? digestOid,
  }) {
    final digest = digestForOid(data, digestOid);
    return buildDigestInfo(digest, digestOid: digestOid);
  }

  static Uint8List signDigest({
    required RSAPrivateKey privateKey,
    required Uint8List digest,
    String? digestOid,
  }) {
    final digestInfo = buildDigestInfo(digest, digestOid: digestOid);
    final engine = PKCS1Encoding(RSAEngine())
      ..init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final signature = engine.process(digestInfo);
    return Uint8List.fromList(signature);
  }

  static Uint8List signData({
    required RSAPrivateKey privateKey,
    required Uint8List data,
    String? digestOid,
  }) {
    final digest = digestForOid(data, digestOid);
    return signDigest(
      privateKey: privateKey,
      digest: digest,
      digestOid: digestOid,
    );
  }

  static bool verifyData({
    required RSAPublicKey publicKey,
    required Uint8List data,
    required Uint8List signature,
    String? digestOid,
  }) {
    final digest = digestForOid(data, digestOid);
    return verifyDigest(
      publicKey: publicKey,
      digest: digest,
      signature: signature,
      digestOid: digestOid,
    );
  }

  static bool verifyDigest({
    required RSAPublicKey publicKey,
    required Uint8List digest,
    required Uint8List signature,
    String? digestOid,
  }) {
    try {
      final expected = buildDigestInfo(digest, digestOid: digestOid);
      final engine = PKCS1Encoding(RSAEngine())
        ..init(false, PublicKeyParameter<RSAPublicKey>(publicKey));
      final decrypted = engine.process(signature);
      return _fixedTimeEquals(decrypted, expected);
    } catch (_) {
      return false;
    }
  }

  static bool _fixedTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
