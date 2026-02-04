import 'dart:typed_data';

/// Interface for external signing (A3/HSM/services).
abstract class PdfExternalSigner {
  /// Signs the SHA-256 digest of `signedAttrs` and returns a raw signature
  /// (PKCS#1 v1.5 or ECDSA) to be embedded in the CMS.
  Future<Uint8List> signDigest(Uint8List digest);

  /// Public certificate chain of the signer.
  List<Uint8List> get certificates;
}
