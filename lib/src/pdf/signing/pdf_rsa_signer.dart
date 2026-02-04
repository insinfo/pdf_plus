import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/asn1/asn1.dart';
import 'package:pdf_plus/src/crypto/base.dart';
import 'package:pdf_plus/src/crypto/pkcs1.dart';
import 'package:pdf_plus/src/crypto/rsa_engine.dart';
import 'package:pdf_plus/src/crypto/rsa_keys.dart';

import 'pem_utils.dart';
import 'pdf_external_signer.dart';

/// RSA private key signer for external signing APIs.
class PdfRsaPrivateKeySigner implements PdfExternalSigner {
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
    final digestInfo = _buildDigestInfoSha256(digest);
    final signer = PKCS1Encoding(RSAEngine())
      ..init(true, PrivateKeyParameter<RSAPrivateKey>(key));
    final sig = signer.process(digestInfo);
    return Uint8List.fromList(sig);
  }

  Uint8List _buildDigestInfoSha256(Uint8List digest) {
    final algId = ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromComponentString('2.16.840.1.101.3.4.2.1'))
      ..add(ASN1Null());
    final di = ASN1Sequence()
      ..add(algId)
      ..add(ASN1OctetString(digest));
    return di.encodedBytes;
  }
}
