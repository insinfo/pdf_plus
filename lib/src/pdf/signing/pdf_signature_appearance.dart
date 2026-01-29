/// Dados de aparência para assinatura visível.
class PdfSignatureAppearance {
  const PdfSignatureAppearance({
    this.title,
    this.reason,
    this.location,
    this.contactInfo,
    this.signedAt,
  });

  final String? title;
  final String? reason;
  final String? location;
  final String? contactInfo;
  final DateTime? signedAt;
}
