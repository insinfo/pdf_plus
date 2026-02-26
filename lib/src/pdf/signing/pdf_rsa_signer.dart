import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/signature_adapter.dart';
import 'package:pdf_plus/src/crypto/rsa_keys.dart';

import 'pem_utils.dart';
import 'pdf_external_signer.dart';

/// RSA private key signer for external signing APIs.
class PdfRsaPrivateKeySigner extends PdfExternalSigner {
  static final SignatureAdapter _signatureAdapter = SignatureAdapter();

  /// Creates a signer from an RSA private key and certificate chain.
  PdfRsaPrivateKeySigner({
    required RSAPrivateKey privateKey,
    required List<Uint8List> certificates,
  })  : _privateKey = privateKey,
        _certificates = List<Uint8List>.unmodifiable(certificates);

  /// Creates a signer from PEM-encoded key and certificates.
  factory PdfRsaPrivateKeySigner.fromPem({
    required String privateKeyPem,
    required String certificatePem,
    List<String> chainPem = const <String>[],
  }) {
    final privateKey = PdfPemUtils.rsaPrivateKeyFromPem(privateKeyPem);
    final signerCert =
        PdfPemUtils.decodeFirstPem(certificatePem, 'CERTIFICATE');
    final chain = <Uint8List>[
      signerCert,
      ...chainPem
          .expand((pem) => PdfPemUtils.decodePemBlocks(pem, 'CERTIFICATE')),
    ];
    return PdfRsaPrivateKeySigner(privateKey: privateKey, certificates: chain);
  }

  final RSAPrivateKey _privateKey;
  final List<Uint8List> _certificates;

  @override
  /// Returns the certificate chain as DER bytes.
  List<Uint8List> get certificates => _certificates;

  @override
  /// Signs a digest using RSA/SHA-256.
  Future<Uint8List> signDigest(Uint8List digest) async {
    return _rsaSignDigest(digest, _privateKey);
  }

  Uint8List _rsaSignDigest(Uint8List digest, RSAPrivateKey key) {
    return _signatureAdapter.rsaPkcs1v15SignDigest(
      privateKey: key,
      digest: digest,
      digestOid: PdfSignatureAlgorithms.sha256,
    );
  }
}
