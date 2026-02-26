import 'dart:typed_data';

class PdfSignatureAlgorithms {
  static const String sha256 = '2.16.840.1.101.3.4.2.1';
  static const String rsaEncryption = '1.2.840.113549.1.1.1';
  static const String ecdsaWithSha256 = '1.2.840.10045.4.3.2';
  static const String ed25519 = '1.3.101.112';
}

/// Interface for external signing (A3/HSM/services).
abstract class PdfExternalSigner {
  /// Signs the SHA-256 digest of `signedAttrs` and returns a raw signature
  /// (PKCS#1 v1.5 or ECDSA) to be embedded in the CMS.
  Future<Uint8List> signDigest(Uint8List digest);

  /// Optional hook for algorithms that sign signedAttrs bytes directly
  /// (ex.: ECDSA/EdDSA em APIs que fazem hashing internamente).
  Future<Uint8List> signSignedAttributes(
    Uint8List signedAttrsDer,
    Uint8List signedAttrsDigest,
  ) {
    return signDigest(signedAttrsDigest);
  }

  /// SignerInfo.digestAlgorithm OID.
  String get digestAlgorithmOid => PdfSignatureAlgorithms.sha256;

  /// SignerInfo.signatureAlgorithm OID.
  String get signatureAlgorithmOid => PdfSignatureAlgorithms.rsaEncryption;

  /// Public certificate chain of the signer.
  List<Uint8List> get certificates;
}
