import 'dart:typed_data';

import '../crypto/pdf_crypto.dart';
import 'pdf_validation_format_utils.dart';

String validationSha256Hex(Uint8List bytes) {
  return bytesToHexLower(PdfCrypto.sha256(bytes));
}

String? normalizeValidationName(String? value) {
  if (value == null) return null;
  final normalized = value.toLowerCase().replaceAll(RegExp(r'[^a-z0-9]'), '');
  return normalized.isEmpty ? null : normalized;
}

bool subjectMatchesValidationIssuer(String issuer, Set<String> subjects) {
  for (final subject in subjects) {
    if (subject == issuer ||
        subject.contains(issuer) ||
        issuer.contains(subject)) {
      return true;
    }
  }
  return false;
}
