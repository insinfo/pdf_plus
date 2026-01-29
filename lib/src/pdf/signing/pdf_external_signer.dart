import 'dart:typed_data';

/// Interface para assinatura externa (A3/HSM/serviços).
abstract class PdfExternalSigner {
  /// Assina o digest (SHA-256) dos `signedAttrs` e retorna a assinatura crua
  /// (PKCS#1 v1.5 ou ECDSA), que será embutida no CMS.
  Future<Uint8List> signDigest(Uint8List digest);

  /// Cadeia de certificados públicos do signatário.
  List<Uint8List> get certificates;
}
