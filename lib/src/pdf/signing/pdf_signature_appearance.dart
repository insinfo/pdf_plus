/// Appearance data for visible signatures.
class PdfSignatureAppearance {
  /// Creates a visible signature appearance description.
  const PdfSignatureAppearance({
    this.title,
    this.reason,
    this.location,
    this.contactInfo,
    this.signedAt,
  });

  /// Title shown in the appearance.
  final String? title;
  /// Reason shown in the appearance.
  final String? reason;
  /// Location shown in the appearance.
  final String? location;
  /// Contact information shown in the appearance.
  final String? contactInfo;
  /// Signing time to display.
  final DateTime? signedAt;
}
