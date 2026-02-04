import 'dart:typed_data';

import 'pdf_signature_validator.dart';
import 'package:pdf_plus/src/pdf/io/pdf_http_fetcher_base.dart';

class PdfSignatureInspectionReport {
  const PdfSignatureInspectionReport({required this.signatures});

  final List<PdfSignatureSummary> signatures;

  bool get allDocumentsIntact =>
      signatures.every((s) => s.documentIntact == true);
}

class PdfSignatureSummary {
  const PdfSignatureSummary({
    required this.signatureIndex,
    required this.fieldName,
    required this.signer,
    required this.signingTime,
    required this.policyPresent,
    required this.policyDigestOk,
    required this.cmsSignatureValid,
    required this.byteRangeDigestOk,
    required this.documentIntact,
    required this.chainTrusted,
    required this.docMdp,
  });

  final int signatureIndex;
  final String fieldName;
  final PdfSignatureSignerInfo? signer;
  final DateTime? signingTime;
  final bool policyPresent;
  final bool? policyDigestOk;
  final bool cmsSignatureValid;
  final bool byteRangeDigestOk;
  final bool documentIntact;
  final bool? chainTrusted;
  final PdfSignatureDocMdpInfo? docMdp;
}

class PdfSignatureSignerInfo {
  const PdfSignatureSignerInfo({
    this.subject,
    this.issuer,
    this.serialNumberHex,
    this.serialNumberDecimal,
    this.certNotBefore,
    this.certNotAfter,
    this.commonName,
    this.cpf,
    this.dateOfBirth,
  });

  final String? subject;
  final String? issuer;
  final String? serialNumberHex;
  final String? serialNumberDecimal;
  final DateTime? certNotBefore;
  final DateTime? certNotAfter;
  final String? commonName;
  final String? cpf;
  final DateTime? dateOfBirth;
}

class PdfSignatureInspector {
  Future<PdfSignatureInspectionReport> inspect(
    Uint8List pdfBytes, {
    List<String>? trustedRootsPem,
    TrustedRootsProvider? trustedRootsProvider,
    List<TrustedRootsProvider>? trustedRootsProviders,
    bool strictRevocation = false,
    bool fetchCrls = false,
    bool fetchOcsp = false,
    PdfRevocationDataProvider? revocationDataProvider,
    PdfHttpFetcherBase? certificateFetcher,
    bool includeCertificates = true,
    bool includeSignatureFields = true,
  }) async {
    final report = await PdfSignatureValidator().validateAllSignatures(
      pdfBytes,
      trustedRootsPem: trustedRootsPem,
      trustedRootsProvider: trustedRootsProvider,
      trustedRootsProviders: trustedRootsProviders,
      strictRevocation: strictRevocation,
      fetchCrls: fetchCrls,
      fetchOcsp: fetchOcsp,
      revocationDataProvider: revocationDataProvider,
      certificateFetcher: certificateFetcher,
      includeCertificates: includeCertificates,
      includeSignatureFields: includeSignatureFields,
    );

    final summaries = report.signatures.map((sig) {
      final fieldName = sig.signatureField?.fieldName ?? 'Signature';
      final signer = _buildSignerInfo(sig.signerCertificate);
      final policyPresent = sig.signaturePolicyOid != null;
      final rawSigningTime = sig.signatureField?.signingTimeRaw;
      final signingTime = policyPresent && rawSigningTime != null
          ? _parsePdfDate(rawSigningTime)
          : sig.signingTime ?? _parsePdfDate(rawSigningTime);

      return PdfSignatureSummary(
        signatureIndex: sig.signatureIndex,
        fieldName: fieldName,
        signer: signer,
        signingTime: signingTime,
        policyPresent: policyPresent,
        policyDigestOk: null,
        cmsSignatureValid: sig.cmsValid,
        byteRangeDigestOk: sig.digestValid,
        documentIntact: sig.intact,
        chainTrusted: sig.chainTrusted,
        docMdp: sig.docMdp,
      );
    }).toList(growable: false);

    return PdfSignatureInspectionReport(signatures: summaries);
  }
}

PdfSignatureSignerInfo? _buildSignerInfo(PdfSignatureCertificateInfo? cert) {
  if (cert == null) return null;
  final serial = cert.serial;
  final serialHex =
      serial != null ? serial.toRadixString(16).toUpperCase() : null;
  final serialDec = serial?.toString();
  final subject = cert.subject;
  return PdfSignatureSignerInfo(
    subject: subject,
    issuer: cert.issuer,
    serialNumberHex: serialHex,
    serialNumberDecimal: serialDec,
    certNotBefore: cert.notBefore,
    certNotAfter: cert.notAfter,
    commonName: _extractCommonName(subject),
    cpf: cert.icpBrasilIds?.cpf,
    dateOfBirth: cert.icpBrasilIds?.dateOfBirth,
  );
}

String? _extractCommonName(String? subject) {
  if (subject == null) return null;
  final parts = subject.split(',');
  for (final part in parts) {
    final trimmed = part.trim();
    if (trimmed.toUpperCase().startsWith('CN=')) {
      return trimmed.substring(3).trim();
    }
  }
  return null;
}

DateTime? _parsePdfDate(String? raw) {
  if (raw == null || raw.isEmpty) return null;
  var value = raw.trim();
  if (value.startsWith('D:')) {
    value = value.substring(2);
  }
  if (value.length < 8) return null;
  int parseInt(String s, int start, int len, int fallback) {
    if (start + len > s.length) return fallback;
    final chunk = s.substring(start, start + len);
    return int.tryParse(chunk) ?? fallback;
  }

  final year = parseInt(value, 0, 4, 0);
  final month = parseInt(value, 4, 2, 1);
  final day = parseInt(value, 6, 2, 1);
  final hour = parseInt(value, 8, 2, 0);
  final minute = parseInt(value, 10, 2, 0);
  final second = parseInt(value, 12, 2, 0);
  if (year <= 0) return null;
  return DateTime(year, month, day, hour, minute, second);
}
