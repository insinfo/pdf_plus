import '../document.dart';

/// Configurações/metadata para assinatura externa.
class PdfSignatureConfig {
  PdfSignatureConfig({
    this.contactInfo,
    this.reason,
    this.location,
    this.name,
    this.signingTime,
  });

  String? contactInfo;
  String? reason;
  String? location;
  String? name;
  DateTime? signingTime;

  int? docMdpPermissionP;

  bool get hasDocMdp => docMdpPermissionP != null;

  void configureDocMdpForFirstSignature(
    PdfDocument document, {
    required int permissionP,
  }) {
    docMdpPermissionP = permissionP;
  }
}