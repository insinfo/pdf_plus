import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/signature_adapter.dart';

import 'pdf_external_signer.dart';

/// ECDSA signer backed by PKCS#8 private key (Web Crypto friendly).
class PdfEcdsaPkcs8Signer extends PdfExternalSigner {
  PdfEcdsaPkcs8Signer({
    required this.pkcs8PrivateKey,
    required this.namedCurve,
    required List<Uint8List> certificates,
    this.hashAlgorithm = 'SHA-256',
    SignatureAdapter? signatureAdapter,
  })  : _certificates = List<Uint8List>.unmodifiable(certificates),
        _signatureAdapter = signatureAdapter ?? SignatureAdapter();

  final Uint8List pkcs8PrivateKey;
  final String namedCurve;
  final String hashAlgorithm;
  final List<Uint8List> _certificates;
  final SignatureAdapter _signatureAdapter;

  @override
  List<Uint8List> get certificates => _certificates;

  @override
  String get digestAlgorithmOid => _digestOidFromHash(hashAlgorithm);

  @override
  String get signatureAlgorithmOid => _ecdsaSignatureOid(hashAlgorithm);

  @override
  Future<Uint8List> signDigest(Uint8List digest) {
    throw UnsupportedError(
      'ECDSA signer requer signSignedAttributes() para evitar double-hash.',
    );
  }

  @override
  Future<Uint8List> signSignedAttributes(
    Uint8List signedAttrsDer,
    Uint8List signedAttrsDigest,
  ) {
    return _signatureAdapter.ecdsaSignDer(
      namedCurve: namedCurve,
      hashAlgorithm: hashAlgorithm,
      pkcs8PrivateKey: pkcs8PrivateKey,
      data: signedAttrsDer,
    );
  }
}

/// Ed25519 signer backed by PKCS#8 private key (Web Crypto friendly).
class PdfEd25519Pkcs8Signer extends PdfExternalSigner {
  PdfEd25519Pkcs8Signer({
    required this.pkcs8PrivateKey,
    required List<Uint8List> certificates,
    SignatureAdapter? signatureAdapter,
  })  : _certificates = List<Uint8List>.unmodifiable(certificates),
        _signatureAdapter = signatureAdapter ?? SignatureAdapter();

  final Uint8List pkcs8PrivateKey;
  final List<Uint8List> _certificates;
  final SignatureAdapter _signatureAdapter;

  @override
  List<Uint8List> get certificates => _certificates;

  // Para Ed25519 o algoritmo de assinatura já embute o hash.
  @override
  String get digestAlgorithmOid => PdfSignatureAlgorithms.sha256;

  @override
  String get signatureAlgorithmOid => PdfSignatureAlgorithms.ed25519;

  @override
  Future<Uint8List> signDigest(Uint8List digest) {
    throw UnsupportedError(
      'Ed25519 signer requer signSignedAttributes() para assinar os bytes DER.',
    );
  }

  @override
  Future<Uint8List> signSignedAttributes(
    Uint8List signedAttrsDer,
    Uint8List signedAttrsDigest,
  ) {
    return _signatureAdapter.ed25519Sign(
      pkcs8PrivateKey: pkcs8PrivateKey,
      data: signedAttrsDer,
    );
  }
}

String _digestOidFromHash(String hashAlgorithm) {
  switch (hashAlgorithm.toUpperCase()) {
    case 'SHA-384':
      return '2.16.840.1.101.3.4.2.2';
    case 'SHA-512':
      return '2.16.840.1.101.3.4.2.3';
    case 'SHA-256':
    default:
      return PdfSignatureAlgorithms.sha256;
  }
}

String _ecdsaSignatureOid(String hashAlgorithm) {
  switch (hashAlgorithm.toUpperCase()) {
    case 'SHA-384':
      return '1.2.840.10045.4.3.3';
    case 'SHA-512':
      return '1.2.840.10045.4.3.4';
    case 'SHA-256':
    default:
      return PdfSignatureAlgorithms.ecdsaWithSha256;
  }
}
