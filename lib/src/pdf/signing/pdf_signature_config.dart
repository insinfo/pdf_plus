import '../document.dart';

/// Metadata and configuration for external signatures.
class PdfSignatureConfig {
  /// Creates a signature configuration.
  PdfSignatureConfig({
    this.contactInfo,
    this.reason,
    this.location,
    this.name,
    this.signingTime,
    this.subFilter,
    this.isDocTimeStamp = false,
  });

  /// Contact information.
  String? contactInfo;
  /// Reason for signing.
  String? reason;
  /// Location of signing.
  String? location;
  /// Signer name.
  String? name;
  /// Signing time to embed.
  DateTime? signingTime;
  /// SubFilter name (e.g. /adbe.pkcs7.detached).
  String? subFilter;
  /// Whether this signature is a DocTimeStamp.
  bool isDocTimeStamp;

  /// DocMDP permission value (1, 2, or 3).
  int? docMdpPermissionP;

  /// Whether DocMDP permissions are configured.
  bool get hasDocMdp => docMdpPermissionP != null;

  /// Configures DocMDP for the first signature in a document.
  void configureDocMdpForFirstSignature(
    PdfDocument document, {
    required int permissionP,
  }) {
    docMdpPermissionP = permissionP;
  }
}
