import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/asn1/asn1.dart';
import 'package:pdf_plus/src/pki/x509_certificate.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_document_info.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_document_parser.dart';

import 'pdf_iti_report.dart';
import 'pdf_lpa.dart';
import 'pdf_signature_validator.dart';
import 'pdf_validation_format_utils.dart';
import 'pdf_smart_trusted_roots.dart';
import 'pdf_validation_common.dart';

enum PdfComplianceReportFormat {
  itiText,
  json,
}

enum PdfDocMdpDecisionCode {
  noCertification,
  p1Blocked,
  p2Allowed,
  p3Allowed,
  unknown,
}

class PdfValidationCacheHooks {
  const PdfValidationCacheHooks({
    this.get,
    this.put,
    this.getJson,
    this.putJson,
  });

  final Future<Object?> Function(String key)? get;
  final Future<void> Function(String key, Object value, Duration ttl)? put;
  final Future<String?> Function(String key)? getJson;
  final Future<void> Function(String key, String value, Duration ttl)? putJson;
}

class PdfTrustProfile {
  const PdfTrustProfile({
    required this.id,
    required this.provider,
    this.displayName,
  });

  final String id;
  final TrustedRootsProvider provider;
  final String? displayName;
}

class PdfBatchValidationInput {
  const PdfBatchValidationInput({
    required this.id,
    required this.pdfBytes,
    this.fileName,
  });

  final String id;
  final Uint8List pdfBytes;
  final String? fileName;
}

class PdfBatchValidationItemResult {
  const PdfBatchValidationItemResult({
    required this.id,
    required this.result,
    this.fileName,
  });

  final String id;
  final String? fileName;
  final PdfValidationWithProfilesResult result;
}

class PdfBatchValidationResult {
  const PdfBatchValidationResult({
    required this.items,
  });

  final List<PdfBatchValidationItemResult> items;
}

class PdfPreflightSignaturesFastReport {
  const PdfPreflightSignaturesFastReport({
    required this.signatures,
  });

  final List<PdfPreflightSignatureFastInfo> signatures;

  Map<String, dynamic> toJson() {
    return {
      'signatures': signatures.map((e) => e.toJson()).toList(growable: false),
    };
  }

  factory PdfPreflightSignaturesFastReport.fromJson(Map<String, dynamic> json) {
    final list = (json['signatures'] as List<dynamic>? ?? const <dynamic>[])
        .whereType<Map>()
        .map((e) => PdfPreflightSignatureFastInfo.fromJson(
            e.map((k, v) => MapEntry(k.toString(), v))))
        .toList(growable: false);
    return PdfPreflightSignaturesFastReport(signatures: list);
  }
}

class PdfPreflightSignatureFastInfo {
  const PdfPreflightSignatureFastInfo({
    required this.signatureIndex,
    required this.fieldName,
    this.serialDecimal,
    this.serialHex,
    this.issuerDn,
    this.policyOid,
    this.signingTime,
    this.authorityKeyIdentifierHex,
    this.notes,
  });

  final int signatureIndex;
  final String fieldName;
  final String? serialDecimal;
  final String? serialHex;
  final String? issuerDn;
  final String? policyOid;
  final DateTime? signingTime;
  final String? authorityKeyIdentifierHex;
  final String? notes;

  Map<String, dynamic> toJson() {
    return {
      'signatureIndex': signatureIndex,
      'fieldName': fieldName,
      'serialDecimal': serialDecimal,
      'serialHex': serialHex,
      'issuerDn': issuerDn,
      'policyOid': policyOid,
      'signingTime': signingTime?.toUtc().toIso8601String(),
      'authorityKeyIdentifierHex': authorityKeyIdentifierHex,
      'notes': notes,
    };
  }

  factory PdfPreflightSignatureFastInfo.fromJson(Map<String, dynamic> json) {
    return PdfPreflightSignatureFastInfo(
      signatureIndex: (json['signatureIndex'] as num?)?.toInt() ?? 0,
      fieldName: (json['fieldName'] ?? 'Signature').toString(),
      serialDecimal: json['serialDecimal']?.toString(),
      serialHex: json['serialHex']?.toString(),
      issuerDn: json['issuerDn']?.toString(),
      policyOid: json['policyOid']?.toString(),
      signingTime: json['signingTime'] == null
          ? null
          : DateTime.tryParse(json['signingTime'].toString())?.toUtc(),
      authorityKeyIdentifierHex: json['authorityKeyIdentifierHex']?.toString(),
      notes: json['notes']?.toString(),
    );
  }
}

class PdfRevocationEvidence {
  const PdfRevocationEvidence({
    required this.signatureIndex,
    required this.status,
    required this.source,
    this.checkedAt,
    this.ocspResponder,
    this.crlIssuer,
    this.nextUpdate,
    this.softFailReason,
  });

  final int signatureIndex;
  final String status;
  final String source;
  final DateTime? checkedAt;
  final String? ocspResponder;
  final String? crlIssuer;
  final DateTime? nextUpdate;
  final String? softFailReason;

  Map<String, dynamic> toJson() {
    return {
      'signatureIndex': signatureIndex,
      'status': status,
      'source': source,
      'checkedAt': checkedAt?.toUtc().toIso8601String(),
      'ocspResponder': ocspResponder,
      'crlIssuer': crlIssuer,
      'nextUpdate': nextUpdate?.toUtc().toIso8601String(),
      'softFailReason': softFailReason,
    };
  }

  factory PdfRevocationEvidence.fromJson(Map<String, dynamic> json) {
    return PdfRevocationEvidence(
      signatureIndex: (json['signatureIndex'] as num?)?.toInt() ?? 0,
      status: (json['status'] ?? 'unknown').toString(),
      source: (json['source'] ?? 'none').toString(),
      checkedAt: json['checkedAt'] == null
          ? null
          : DateTime.tryParse(json['checkedAt'].toString())?.toUtc(),
      ocspResponder: json['ocspResponder']?.toString(),
      crlIssuer: json['crlIssuer']?.toString(),
      nextUpdate: json['nextUpdate'] == null
          ? null
          : DateTime.tryParse(json['nextUpdate'].toString())?.toUtc(),
      softFailReason: json['softFailReason']?.toString(),
    );
  }
}

class PdfPolicyResolution {
  const PdfPolicyResolution({
    required this.signatureIndex,
    this.policyOid,
    this.displayName,
    this.lpaMatch,
    this.validAtSigningTime,
    this.validNow,
    this.digestMatch,
  });

  final int signatureIndex;
  final String? policyOid;
  final String? displayName;
  final bool? lpaMatch;
  final bool? validAtSigningTime;
  final bool? validNow;
  final bool? digestMatch;

  Map<String, dynamic> toJson() {
    return {
      'signatureIndex': signatureIndex,
      'policyOid': policyOid,
      'displayName': displayName,
      'lpaMatch': lpaMatch,
      'validAtSigningTime': validAtSigningTime,
      'validNow': validNow,
      'digestMatch': digestMatch,
    };
  }

  factory PdfPolicyResolution.fromJson(Map<String, dynamic> json) {
    return PdfPolicyResolution(
      signatureIndex: (json['signatureIndex'] as num?)?.toInt() ?? 0,
      policyOid: json['policyOid']?.toString(),
      displayName: json['displayName']?.toString(),
      lpaMatch: json['lpaMatch'] as bool?,
      validAtSigningTime: json['validAtSigningTime'] as bool?,
      validNow: json['validNow'] as bool?,
      digestMatch: json['digestMatch'] as bool?,
    );
  }
}

class PdfDocMdpEvaluation {
  const PdfDocMdpEvaluation({
    required this.canAppendSignature,
    required this.code,
    required this.reason,
    this.permissionP,
  });

  final bool canAppendSignature;
  final PdfDocMdpDecisionCode code;
  final String reason;
  final int? permissionP;

  Map<String, dynamic> toJson() {
    return {
      'canAppendSignature': canAppendSignature,
      'code': _docMdpDecisionCodeWire(code),
      'reason': reason,
      'permissionP': permissionP,
    };
  }

  factory PdfDocMdpEvaluation.fromJson(Map<String, dynamic> json) {
    final code = _docMdpDecisionCodeFromWire(json['code']?.toString());
    return PdfDocMdpEvaluation(
      canAppendSignature: json['canAppendSignature'] == true,
      code: code,
      reason: (json['reason'] ?? '').toString(),
      permissionP: (json['permissionP'] as num?)?.toInt(),
    );
  }
}

class PdfTrustResolutionBySignature {
  const PdfTrustResolutionBySignature({
    required this.signatureIndex,
    required this.fieldName,
    required this.trustedByProfile,
    required this.winningProfile,
    required this.reasons,
  });

  final int signatureIndex;
  final String fieldName;
  final Map<String, bool> trustedByProfile;
  final String? winningProfile;
  final List<String> reasons;

  Map<String, dynamic> toJson() {
    return {
      'signatureIndex': signatureIndex,
      'fieldName': fieldName,
      'trustedByProfile': trustedByProfile,
      'winningProfile': winningProfile,
      'reasons': reasons,
    };
  }

  factory PdfTrustResolutionBySignature.fromJson(Map<String, dynamic> json) {
    final trustedMap = <String, bool>{};
    final rawMap = json['trustedByProfile'];
    if (rawMap is Map) {
      rawMap.forEach((key, value) {
        trustedMap[key.toString()] = value == true;
      });
    }
    final reasons = (json['reasons'] as List<dynamic>? ?? const <dynamic>[])
        .map((e) => e.toString())
        .toList(growable: false);
    return PdfTrustResolutionBySignature(
      signatureIndex: (json['signatureIndex'] as num?)?.toInt() ?? 0,
      fieldName: (json['fieldName'] ?? 'Signature').toString(),
      trustedByProfile: trustedMap,
      winningProfile: json['winningProfile']?.toString(),
      reasons: reasons,
    );
  }
}

class PdfValidationWithProfilesResult {
  const PdfValidationWithProfilesResult({
    required this.report,
    required this.trustResolutionBySignature,
    required this.revocationEvidence,
    required this.policyResolver,
    required this.docMdpEvaluation,
  });

  final PdfSignatureValidationReport report;
  final List<PdfTrustResolutionBySignature> trustResolutionBySignature;
  final List<PdfRevocationEvidence> revocationEvidence;
  final List<PdfPolicyResolution> policyResolver;
  final PdfDocMdpEvaluation docMdpEvaluation;

  Map<String, dynamic> toJson() {
    return {
      'report': _encodeValidationReport(report),
      'trustResolutionBySignature': trustResolutionBySignature
          .map((e) => e.toJson())
          .toList(growable: false),
      'revocationEvidence':
          revocationEvidence.map((e) => e.toJson()).toList(growable: false),
      'policyResolver':
          policyResolver.map((e) => e.toJson()).toList(growable: false),
      'docMdpEvaluation': docMdpEvaluation.toJson(),
    };
  }

  factory PdfValidationWithProfilesResult.fromJson(Map<String, dynamic> json) {
    final trust = (json['trustResolutionBySignature'] as List<dynamic>? ??
            const <dynamic>[])
        .whereType<Map>()
        .map((e) => PdfTrustResolutionBySignature.fromJson(
            e.map((k, v) => MapEntry(k.toString(), v))))
        .toList(growable: false);

    final rev =
        (json['revocationEvidence'] as List<dynamic>? ?? const <dynamic>[])
            .whereType<Map>()
            .map((e) => PdfRevocationEvidence.fromJson(
                e.map((k, v) => MapEntry(k.toString(), v))))
            .toList(growable: false);

    final policy =
        (json['policyResolver'] as List<dynamic>? ?? const <dynamic>[])
            .whereType<Map>()
            .map((e) => PdfPolicyResolution.fromJson(
                e.map((k, v) => MapEntry(k.toString(), v))))
            .toList(growable: false);

    final docMdpRaw = json['docMdpEvaluation'];
    final docMdp = docMdpRaw is Map
        ? PdfDocMdpEvaluation.fromJson(
            docMdpRaw.map((k, v) => MapEntry(k.toString(), v)),
          )
        : const PdfDocMdpEvaluation(
            canAppendSignature: false,
            code: PdfDocMdpDecisionCode.unknown,
            reason: 'DocMDP ausente no cache.',
          );

    return PdfValidationWithProfilesResult(
      report: _decodeValidationReport(json['report']),
      trustResolutionBySignature: trust,
      revocationEvidence: rev,
      policyResolver: policy,
      docMdpEvaluation: docMdp,
    );
  }
}

class PdfComplianceReportOutput {
  const PdfComplianceReportOutput({
    required this.format,
    this.text,
    this.json,
  });

  final PdfComplianceReportFormat format;
  final String? text;
  final Map<String, dynamic>? json;
}

class PdfUiSignatureSummary {
  const PdfUiSignatureSummary({
    required this.signatureIndex,
    required this.nome,
    required this.cpfMasked,
    required this.cadeia,
    required this.integridade,
    required this.alertas,
  });

  final int signatureIndex;
  final String nome;
  final String cpfMasked;
  final String cadeia;
  final bool integridade;
  final List<String> alertas;
}

class PdfUiSummary {
  const PdfUiSummary({
    required this.locale,
    required this.signatures,
  });

  final String locale;
  final List<PdfUiSignatureSummary> signatures;
}

class PdfValidationApi {
  PdfValidationApi({
    PdfSignatureValidator? validator,
    PdfSignatureExtractor? extractor,
  })  : _validator = validator ?? PdfSignatureValidator(),
        _extractor = extractor ?? PdfSignatureExtractor();

  final PdfSignatureValidator _validator;
  final PdfSignatureExtractor _extractor;

  Future<PdfPreflightSignaturesFastReport> preflightSignaturesFast(
    Uint8List pdfBytes, {
    PdfValidationCacheHooks? cacheHooks,
    Duration cacheTtl = const Duration(minutes: 2),
    bool incremental = true,
  }) async {
    final cacheKey = 'preflight-fast:${_sha256Hex(pdfBytes)}';
    final cached = await _cacheGet<PdfPreflightSignaturesFastReport>(
      cacheHooks,
      cacheKey,
      fromJson: (raw) => PdfPreflightSignaturesFastReport.fromJson(raw),
    );
    if (cached != null) {
      return cached;
    }

    if (incremental) {
      final quick = _preflightIncremental(pdfBytes);
      await _cachePut(
        cacheHooks,
        cacheKey,
        quick,
        cacheTtl,
        toJson: (value) => value.toJson(),
      );
      return quick;
    }

    final extraction = await _extractor.extractSignatures(
      pdfBytes,
      includeCertificates: true,
      includeSignatureFields: true,
    );
    final akiBySignature = _extractAuthorityKeyIdentifiersFromCms(pdfBytes);

    final signatures = extraction.signatures.map((sig) {
      final signer = sig.signerCertificate;
      final signerSerial = signer?.serial;
      final aki = akiBySignature[sig.signatureIndex];
      return PdfPreflightSignatureFastInfo(
        signatureIndex: sig.signatureIndex,
        fieldName: sig.signatureField?.fieldName ?? 'Signature',
        serialDecimal: signerSerial?.toString(),
        serialHex: signerSerial == null ? null : bigIntToHexUpper(signerSerial),
        issuerDn: signer?.issuer,
        policyOid: sig.signaturePolicyOid,
        signingTime: sig.signingTime,
        authorityKeyIdentifierHex: aki,
        notes: aki == null || aki.isEmpty
            ? 'AKI indisponível no certificado extraído.'
            : null,
      );
    }).toList(growable: false);

    final result = PdfPreflightSignaturesFastReport(signatures: signatures);
    await _cachePut(
      cacheHooks,
      cacheKey,
      result,
      cacheTtl,
      toJson: (value) => value.toJson(),
    );
    return result;
  }

  Future<PdfValidationWithProfilesResult> validateWithTrustProfiles(
    Uint8List pdfBytes, {
    required List<PdfTrustProfile> trustProfiles,
    bool strictRevocation = false,
    bool fetchCrls = false,
    bool fetchOcsp = false,
    bool validateTemporal = false,
    bool temporalUseSigningTime = false,
    DateTime? validationTime,
    bool temporalExpiredNeedsLtv = true,
    PdfRevocationDataProvider? revocationDataProvider,
    bool includeCertificates = true,
    bool includeSignatureFields = true,
    PdfLpa? lpa,
    Map<String, String>? policyDisplayMap,
    PdfValidationCacheHooks? cacheHooks,
    Duration cacheTtl = const Duration(minutes: 2),
  }) async {
    final index = await PdfTrustedRootsIndex.build(
      trustProfiles
          .map((p) => PdfTrustedRootsSource(id: p.id, provider: p.provider))
          .toList(growable: false),
    );

    return _validateWithPreparedTrustIndex(
      pdfBytes,
      trustProfiles: trustProfiles,
      trustIndex: index,
      strictRevocation: strictRevocation,
      fetchCrls: fetchCrls,
      fetchOcsp: fetchOcsp,
      validateTemporal: validateTemporal,
      temporalUseSigningTime: temporalUseSigningTime,
      validationTime: validationTime,
      temporalExpiredNeedsLtv: temporalExpiredNeedsLtv,
      revocationDataProvider: revocationDataProvider,
      includeCertificates: includeCertificates,
      includeSignatureFields: includeSignatureFields,
      lpa: lpa,
      policyDisplayMap: policyDisplayMap,
      cacheHooks: cacheHooks,
      cacheTtl: cacheTtl,
    );
  }

  Future<PdfBatchValidationResult> validateBatch(
    List<PdfBatchValidationInput> batch, {
    required List<PdfTrustProfile> trustProfiles,
    bool strictRevocation = false,
    bool fetchCrls = false,
    bool fetchOcsp = false,
    bool validateTemporal = false,
    bool temporalUseSigningTime = false,
    DateTime? validationTime,
    bool temporalExpiredNeedsLtv = true,
    PdfRevocationDataProvider? revocationDataProvider,
    bool includeCertificates = true,
    bool includeSignatureFields = true,
    PdfLpa? lpa,
    Map<String, String>? policyDisplayMap,
    PdfValidationCacheHooks? cacheHooks,
    Duration cacheTtl = const Duration(minutes: 2),
  }) async {
    final index = await PdfTrustedRootsIndex.build(
      trustProfiles
          .map((p) => PdfTrustedRootsSource(id: p.id, provider: p.provider))
          .toList(growable: false),
    );
    final sharedRevocationProvider =
        revocationDataProvider == null || (!fetchCrls && !fetchOcsp)
            ? null
            : _MemoizingRevocationDataProvider(revocationDataProvider);

    final items = <PdfBatchValidationItemResult>[];
    for (final input in batch) {
      final result = await _validateWithPreparedTrustIndex(
        input.pdfBytes,
        trustProfiles: trustProfiles,
        trustIndex: index,
        strictRevocation: strictRevocation,
        fetchCrls: fetchCrls,
        fetchOcsp: fetchOcsp,
        validateTemporal: validateTemporal,
        temporalUseSigningTime: temporalUseSigningTime,
        validationTime: validationTime,
        temporalExpiredNeedsLtv: temporalExpiredNeedsLtv,
        revocationDataProvider: sharedRevocationProvider,
        includeCertificates: includeCertificates,
        includeSignatureFields: includeSignatureFields,
        lpa: lpa,
        policyDisplayMap: policyDisplayMap,
        cacheHooks: cacheHooks,
        cacheTtl: cacheTtl,
      );
      items.add(PdfBatchValidationItemResult(
        id: input.id,
        fileName: input.fileName,
        result: result,
      ));
    }
    return PdfBatchValidationResult(items: items);
  }

  Future<PdfValidationWithProfilesResult> _validateWithPreparedTrustIndex(
    Uint8List pdfBytes, {
    required List<PdfTrustProfile> trustProfiles,
    required PdfTrustedRootsIndex trustIndex,
    required bool strictRevocation,
    required bool fetchCrls,
    required bool fetchOcsp,
    required bool validateTemporal,
    required bool temporalUseSigningTime,
    required DateTime? validationTime,
    required bool temporalExpiredNeedsLtv,
    required PdfRevocationDataProvider? revocationDataProvider,
    required bool includeCertificates,
    required bool includeSignatureFields,
    required PdfLpa? lpa,
    required Map<String, String>? policyDisplayMap,
    required PdfValidationCacheHooks? cacheHooks,
    required Duration cacheTtl,
  }) async {
    final profileKey = trustProfiles.map((e) => e.id).toList()..sort();
    final cacheKey =
        'validate-with-profiles:${profileKey.join(',')}:${_sha256Hex(pdfBytes)}';
    final cached = await _cacheGet<PdfValidationWithProfilesResult>(
      cacheHooks,
      cacheKey,
      fromJson: (raw) => PdfValidationWithProfilesResult.fromJson(raw),
    );
    if (cached != null) {
      return cached;
    }

    final checkedAt = DateTime.now().toUtc();
    final cmsDerived = _extractCmsDerivedDataBySignature(pdfBytes);
    final signedAttrsBySignature = cmsDerived.signedAttrsBySignature;
    final revocationHints = cmsDerived.revocationHintsBySignature;

    final report = await _validator.validateAllSignatures(
      pdfBytes,
      trustedRootsProvider:
          PdfInMemoryTrustedRootsProvider(trustIndex.allRoots()),
      strictRevocation: strictRevocation,
      fetchCrls: fetchCrls,
      fetchOcsp: fetchOcsp,
      validateTemporal: validateTemporal,
      temporalUseSigningTime: temporalUseSigningTime,
      validationTime: validationTime,
      temporalExpiredNeedsLtv: temporalExpiredNeedsLtv,
      revocationDataProvider: revocationDataProvider,
      includeCertificates: includeCertificates,
      includeSignatureFields: includeSignatureFields,
    );

    final trustResolution = _resolveTrustBySignature(
      report,
      trustProfiles,
      trustIndex,
    );
    final revocationEvidence = _buildRevocationEvidence(
      report,
      checkedAt: checkedAt,
      hintsBySignature: revocationHints,
    );
    final policyResolver = _buildPolicyResolver(
      report,
      lpa: lpa,
      policyDisplayMap: policyDisplayMap,
      now: validationTime ?? checkedAt,
      signedAttrsBySignature: signedAttrsBySignature,
    );
    final docMdp = evaluateDocMdp(report);

    final result = PdfValidationWithProfilesResult(
      report: report,
      trustResolutionBySignature: trustResolution,
      revocationEvidence: revocationEvidence,
      policyResolver: policyResolver,
      docMdpEvaluation: docMdp,
    );
    await _cachePut(
      cacheHooks,
      cacheKey,
      result,
      cacheTtl,
      toJson: (value) => value.toJson(),
    );
    return result;
  }

  PdfComplianceReportOutput toComplianceReport({
    required Uint8List pdfBytes,
    required PdfValidationWithProfilesResult result,
    required PdfComplianceReportFormat format,
    String fileName = 'Arquivo PDF',
    PdfLpa? lpa,
    String? lpaName,
    bool? lpaOnline,
    bool? paOnline,
    PdfItiComplianceMetadata? metadata,
  }) {
    final report = PdfItiComplianceReport.fromValidation(
      pdfBytes: pdfBytes,
      validationReport: result.report,
      metadata: metadata ?? PdfItiComplianceMetadata(),
      fileName: fileName,
      lpa: lpa,
      lpaName: lpaName,
      lpaOnline: lpaOnline,
      paOnline: paOnline,
    );

    if (format == PdfComplianceReportFormat.itiText) {
      return PdfComplianceReportOutput(
        format: format,
        text: report.toText(),
      );
    }

    final json = _itiReportToJson(report);
    return PdfComplianceReportOutput(
      format: format,
      json: json,
    );
  }

  PdfUiSummary toUiSummary(
    PdfValidationWithProfilesResult result, {
    String locale = 'pt_BR',
  }) {
    final signatures = result.report.signatures.map((sig) {
      final signer = sig.signerCertificate;
      final trust = result.trustResolutionBySignature.firstWhere(
        (e) => e.signatureIndex == sig.signatureIndex,
        orElse: () => PdfTrustResolutionBySignature(
          signatureIndex: sig.signatureIndex,
          fieldName: sig.signatureField?.fieldName ?? 'Signature',
          trustedByProfile: const <String, bool>{},
          winningProfile: null,
          reasons: const <String>[],
        ),
      );

      final alerts = <String>[];
      if (!sig.intact) {
        alerts.add('Documento modificado após assinatura.');
      }
      if (!sig.cmsValid || !sig.digestValid) {
        alerts.add('Falha criptográfica de assinatura.');
      }
      final rev = _revocationStatus(sig.revocation);
      if (rev == 'revoked') {
        alerts.add('Certificado revogado.');
      } else if (rev == 'unknown') {
        alerts.add('Revogação não comprovada.');
      }
      if (trust.winningProfile == null) {
        alerts.add('Cadeia não resolvida por perfil de confiança.');
      }

      final nome = _nameFromSubject(signer?.subject) ??
          sig.signatureField?.fieldName ??
          'Assinante';

      return PdfUiSignatureSummary(
        signatureIndex: sig.signatureIndex,
        nome: nome,
        cpfMasked: _maskCpf(signer?.icpBrasilIds?.cpf),
        cadeia: trust.winningProfile ?? 'Desconhecida',
        integridade: sig.intact && sig.cmsValid && sig.digestValid,
        alertas: alerts,
      );
    }).toList(growable: false);

    return PdfUiSummary(
      locale: locale,
      signatures: signatures,
    );
  }

  PdfDocMdpEvaluation evaluateDocMdp(PdfSignatureValidationReport report) {
    final cert = report.signatures.where(
      (s) => s.docMdp.isCertificationSignature == true,
    );
    if (cert.isEmpty) {
      return const PdfDocMdpEvaluation(
        canAppendSignature: true,
        code: PdfDocMdpDecisionCode.noCertification,
        reason: 'Sem assinatura de certificação (DocMDP).',
      );
    }

    final perms =
        cert.map((e) => e.docMdp.permissionP).whereType<int>().toSet();

    if (perms.contains(2)) {
      return const PdfDocMdpEvaluation(
        canAppendSignature: true,
        code: PdfDocMdpDecisionCode.p2Allowed,
        reason: 'DocMDP P=2 permite formulários e novas assinaturas.',
        permissionP: 2,
      );
    }
    if (perms.contains(3)) {
      return const PdfDocMdpEvaluation(
        canAppendSignature: true,
        code: PdfDocMdpDecisionCode.p3Allowed,
        reason: 'DocMDP P=3 permite anotações, formulários e assinaturas.',
        permissionP: 3,
      );
    }
    if (perms.contains(1)) {
      return const PdfDocMdpEvaluation(
        canAppendSignature: false,
        code: PdfDocMdpDecisionCode.p1Blocked,
        reason: 'DocMDP P=1 bloqueia alterações e novas assinaturas.',
        permissionP: 1,
      );
    }

    return const PdfDocMdpEvaluation(
      canAppendSignature: false,
      code: PdfDocMdpDecisionCode.unknown,
      reason: 'DocMDP presente com permissão indefinida.',
    );
  }

  Future<T?> _cacheGet<T>(
    PdfValidationCacheHooks? hooks,
    String key, {
    required T Function(Map<String, dynamic> raw) fromJson,
  }) async {
    final getter = hooks?.get;
    if (getter != null) {
      final value = await getter(key);
      if (value is T) return value;
      if (value is Map) {
        return fromJson(value.map((k, v) => MapEntry(k.toString(), v)));
      }
    }

    final getJson = hooks?.getJson;
    if (getJson != null) {
      final raw = await getJson(key);
      if (raw != null && raw.isNotEmpty) {
        final decoded = jsonDecode(raw);
        if (decoded is Map) {
          return fromJson(decoded.map((k, v) => MapEntry(k.toString(), v)));
        }
      }
    }

    return null;
  }

  Future<void> _cachePut(
    PdfValidationCacheHooks? hooks,
    String key,
    Object value,
    Duration ttl, {
    required Map<String, dynamic> Function(dynamic value) toJson,
  }) async {
    final putter = hooks?.put;
    if (putter != null) {
      await putter(key, value, ttl);
    }

    final putJson = hooks?.putJson;
    if (putJson != null) {
      final map = toJson(value);
      await putJson(key, jsonEncode(map), ttl);
    }
  }

  PdfPreflightSignaturesFastReport _preflightIncremental(Uint8List pdfBytes) {
    final fieldByRange = _signatureFieldNamesByRange(pdfBytes);
    final ranges = findAllSignatureByteRanges(pdfBytes);
    final contents = extractAllSignatureContents(pdfBytes);
    final signatures = <PdfPreflightSignatureFastInfo>[];

    for (var i = 0; i < contents.length; i++) {
      final cms = contents[i];
      final sid = _extractSignerIssuerAndSerialFromCms(cms);
      final signedAttrs = _extractSignedAttrsFromCms(cms);
      final aki = _extractAkiHexFromCms(cms);
      final key = _byteRangeKeyFromRanges(ranges, i);

      signatures.add(PdfPreflightSignatureFastInfo(
        signatureIndex: i,
        fieldName: fieldByRange[key] ?? 'Signature',
        serialDecimal: sid.serialDecimal,
        serialHex: sid.serialHex,
        issuerDn: sid.issuerDn,
        policyOid: signedAttrs.policyOid,
        signingTime: signedAttrs.signingTime,
        authorityKeyIdentifierHex: aki,
        notes: aki == null ? 'AKI indisponível no certificado extraído.' : null,
      ));
    }

    return PdfPreflightSignaturesFastReport(signatures: signatures);
  }

  List<PdfTrustResolutionBySignature> _resolveTrustBySignature(
    PdfSignatureValidationReport report,
    List<PdfTrustProfile> profiles,
    PdfTrustedRootsIndex index,
  ) {
    return report.signatures.map((sig) {
      final signerIssuer = _normalizeName(sig.signerCertificate?.issuer);
      final fieldName = sig.signatureField?.fieldName ?? 'Signature';
      final trustedByProfile = <String, bool>{};
      final reasons = <String>[];

      for (final profile in profiles) {
        final subjects = index.subjectsForSource(profile.id);
        final trusted = sig.chainTrusted == true &&
            signerIssuer != null &&
            _subjectMatchesIssuer(signerIssuer, subjects);
        trustedByProfile[profile.id] = trusted;
      }

      String? winner;
      for (final profile in profiles) {
        if (trustedByProfile[profile.id] == true) {
          winner = profile.id;
          break;
        }
      }

      if (sig.chainTrusted == true && winner == null) {
        reasons.add(
          'Cadeia válida no conjunto unido, sem correspondência inequívoca em perfil.',
        );
      }
      if (sig.chainTrusted != true) {
        reasons.add('Cadeia não confiável no conjunto unido de raízes.');
      }

      return PdfTrustResolutionBySignature(
        signatureIndex: sig.signatureIndex,
        fieldName: fieldName,
        trustedByProfile: trustedByProfile,
        winningProfile: winner,
        reasons: reasons,
      );
    }).toList(growable: false);
  }

  List<PdfRevocationEvidence> _buildRevocationEvidence(
    PdfSignatureValidationReport report, {
    required DateTime checkedAt,
    required Map<int, _RevocationCmsHints> hintsBySignature,
  }) {
    return report.signatures.map((sig) {
      final rev = sig.revocation;
      final status = _revocationStatus(rev);
      final source = _revocationSource(rev);
      final hints = hintsBySignature[sig.signatureIndex];
      final softFail = _revocationSoftFailReason(rev, source);
      final nextUpdate = hints?.nextUpdate;

      return PdfRevocationEvidence(
        signatureIndex: sig.signatureIndex,
        status: status,
        source: source,
        checkedAt: checkedAt,
        ocspResponder: hints?.ocspResponder,
        crlIssuer: hints?.crlIssuer,
        nextUpdate: nextUpdate,
        softFailReason: softFail,
      );
    }).toList(growable: false);
  }

  List<PdfPolicyResolution> _buildPolicyResolver(
    PdfSignatureValidationReport report, {
    required DateTime now,
    PdfLpa? lpa,
    Map<String, String>? policyDisplayMap,
    Map<int, _SignedAttrsData>? signedAttrsBySignature,
  }) {
    return report.signatures.map((sig) {
      final oid = sig.signaturePolicyOid;
      final policy = oid == null || lpa == null ? null : lpa.findPolicy(oid);
      final displayFromMap = oid == null ? null : policyDisplayMap?[oid];
      final display = displayFromMap ??
          (policy == null ? oid : _policyLabelFromLpa(policy));

      bool? validAtSigning;
      bool? validNow;
      if (policy != null) {
        final signAt = sig.signingTime?.toUtc();
        if (signAt != null) {
          validAtSigning = _isPolicyValidAt(policy, signAt);
        }
        validNow = _isPolicyValidAt(policy, now.toUtc());
      }
      final digestMatch = _matchPolicyDigest(
        policy,
        signedAttrsBySignature?[sig.signatureIndex],
      );

      return PdfPolicyResolution(
        signatureIndex: sig.signatureIndex,
        policyOid: oid,
        displayName: display,
        lpaMatch: policy != null,
        validAtSigningTime: validAtSigning,
        validNow: validNow,
        digestMatch: digestMatch,
      );
    }).toList(growable: false);
  }

  _CmsDerivedDataBySignature _extractCmsDerivedDataBySignature(
    Uint8List pdfBytes,
  ) {
    final signedAttrs = <int, _SignedAttrsData>{};
    final revocationHints = <int, _RevocationCmsHints>{};
    final contents = extractAllSignatureContents(pdfBytes);
    for (var i = 0; i < contents.length; i++) {
      final cms = contents[i];
      signedAttrs[i] = _extractSignedAttrsFromCms(cms);
      revocationHints[i] = _extractRevocationHintsFromCms(cms);
    }
    return _CmsDerivedDataBySignature(
      signedAttrsBySignature: signedAttrs,
      revocationHintsBySignature: revocationHints,
    );
  }

  _RevocationCmsHints _extractRevocationHintsFromCms(Uint8List cmsBytes) {
    final signerCert = _extractSignerCertificateFromCms(cmsBytes);
    if (signerCert == null) return const _RevocationCmsHints();
    return _RevocationCmsHints(
      ocspResponder: _extractOcspResponderFromDerCert(signerCert),
      crlIssuer: _extractCrlIssuerFromDerCert(signerCert),
      nextUpdate: _extractCrlNextUpdateFromDerCert(signerCert),
    );
  }

  X509Certificate? _extractSignerCertificateFromCms(Uint8List cmsBytes) {
    try {
      final root = ASN1Parser(cmsBytes).nextObject();
      if (root is! ASN1Sequence || root.elements.length < 2) return null;

      final signedData = _unwrapTaggedObject(root.elements[1]);
      if (signedData is! ASN1Sequence || signedData.elements.length < 4) {
        return null;
      }

      ASN1Object? certsObj;
      ASN1Set? signerInfos;
      for (final el in signedData.elements) {
        if (_isContextSpecificTag(el, 0)) {
          certsObj ??= _unwrapTaggedObject(el);
        }
        if (el is ASN1Set) {
          signerInfos = el;
        }
      }
      if (certsObj == null ||
          signerInfos == null ||
          signerInfos.elements.isEmpty) {
        return null;
      }

      final certs = _extractCertificateCandidates(certsObj);
      if (certs.isEmpty) return null;

      final signerInfo = signerInfos.elements.first;
      if (signerInfo is! ASN1Sequence || signerInfo.elements.length < 2) {
        return null;
      }
      final sid = signerInfo.elements[1];
      return _findSignerCertificateBySid(certs, sid);
    } catch (_) {
      return null;
    }
  }

  String? _extractOcspResponderFromDerCert(X509Certificate cert) {
    final ext = cert.extensions.firstWhere(
      (e) => e.oid == '1.3.6.1.5.5.7.1.1',
      orElse: () => X509Extension(
        oid: '',
        value: Uint8List(0),
        critical: false,
      ),
    );
    if (ext.oid.isEmpty || ext.value.isEmpty) return null;

    try {
      final obj = ASN1Parser(ext.value).nextObject();
      if (obj is! ASN1Sequence) return null;
      for (final ad in obj.elements) {
        if (ad is! ASN1Sequence || ad.elements.length < 2) continue;
        final method = ad.elements[0];
        if (method is! ASN1ObjectIdentifier ||
            method.identifier != '1.3.6.1.5.5.7.48.1') {
          continue;
        }
        final location = ad.elements[1];
        final uri = _decodeGeneralNameUri(location);
        if (uri != null && uri.isNotEmpty) return uri;
      }
    } catch (_) {
      return null;
    }
    return null;
  }

  String? _extractCrlIssuerFromDerCert(X509Certificate cert) {
    final issuer = cert.issuer.toString().trim();
    return issuer.isEmpty ? null : issuer;
  }

  DateTime? _extractCrlNextUpdateFromDerCert(X509Certificate cert) {
    final ext = cert.extensions.firstWhere(
      (e) => e.oid == '2.5.29.31',
      orElse: () => X509Extension(
        oid: '',
        value: Uint8List(0),
        critical: false,
      ),
    );
    if (ext.oid.isEmpty || ext.value.isEmpty) return null;
    return cert.notAfter.toUtc();
  }
}

class _SignerIdentifierData {
  const _SignerIdentifierData({
    this.serialDecimal,
    this.serialHex,
    this.issuerDn,
  });

  final String? serialDecimal;
  final String? serialHex;
  final String? issuerDn;
}

class _SignedAttrsData {
  const _SignedAttrsData({
    this.policyOid,
    this.signingTime,
    this.policyHashAlgorithmOid,
    this.policyHashValue,
  });

  final String? policyOid;
  final DateTime? signingTime;
  final String? policyHashAlgorithmOid;
  final Uint8List? policyHashValue;
}

class _CmsDerivedDataBySignature {
  const _CmsDerivedDataBySignature({
    required this.signedAttrsBySignature,
    required this.revocationHintsBySignature,
  });

  final Map<int, _SignedAttrsData> signedAttrsBySignature;
  final Map<int, _RevocationCmsHints> revocationHintsBySignature;
}

class _PolicyIdentifierData {
  const _PolicyIdentifierData({
    this.policyOid,
    this.hashAlgorithmOid,
    this.hashValue,
  });

  final String? policyOid;
  final String? hashAlgorithmOid;
  final Uint8List? hashValue;
}

class _PolicyHashInfo {
  const _PolicyHashInfo({
    this.hashAlgorithmOid,
    this.hashValue,
  });

  final String? hashAlgorithmOid;
  final Uint8List? hashValue;
}

class _RevocationCmsHints {
  const _RevocationCmsHints({
    this.ocspResponder,
    this.crlIssuer,
    this.nextUpdate,
  });

  final String? ocspResponder;
  final String? crlIssuer;
  final DateTime? nextUpdate;
}

class _MemoizingRevocationDataProvider implements PdfRevocationDataProvider {
  _MemoizingRevocationDataProvider(this._delegate);

  final PdfRevocationDataProvider _delegate;
  final Map<String, Future<Uint8List?>> _crlByUrl =
      <String, Future<Uint8List?>>{};
  final Map<String, Future<Uint8List?>> _ocspByRequest =
      <String, Future<Uint8List?>>{};

  @override
  Future<Uint8List?> fetchCrl(Uri url) {
    final key = url.toString();
    return _crlByUrl.putIfAbsent(key, () => _delegate.fetchCrl(url));
  }

  @override
  Future<Uint8List?> fetchOcsp(Uri url, Uint8List requestDer) {
    final key = '${url.toString()}#${_sha256Hex(requestDer)}';
    return _ocspByRequest.putIfAbsent(
      key,
      () => _delegate.fetchOcsp(url, requestDer),
    );
  }
}

Map<String, dynamic> _itiReportToJson(PdfItiComplianceReport report) {
  return {
    'metadata': {
      'name': report.metadata.name,
      'validationDate':
          report.metadata.validationDate.toUtc().toIso8601String(),
      'verifierVersion': report.metadata.verifierVersion,
      'validatorVersion': report.metadata.validatorVersion,
      'verificationSource': report.metadata.verificationSource,
    },
    'file': {
      'name': report.fileName,
      'sha256': report.fileHashSha256,
      'type': report.fileType,
      'signatureCount': report.signatureCount,
      'anchoredSignatureCount': report.anchoredSignatureCount,
    },
    'policyInfo': {
      'paValid': report.policyInfo?.paValid,
      'paValidFrom': report.policyInfo?.paValidFrom?.toUtc().toIso8601String(),
      'paValidTo': report.policyInfo?.paValidTo?.toUtc().toIso8601String(),
      'paExpired': report.policyInfo?.paExpired,
      'paValidInLpa': report.policyInfo?.paValidInLpa,
      'paOnline': report.policyInfo?.paOnline,
      'paOidLabel': report.policyInfo?.paOidLabel,
    },
    'lpaInfo': {
      'lpaValid': report.lpaInfo?.lpaValid,
      'nextIssue': report.lpaInfo?.nextIssue?.toUtc().toIso8601String(),
      'lpaExpired': report.lpaInfo?.lpaExpired,
      'lpaName': report.lpaInfo?.lpaName,
      'lpaOnline': report.lpaInfo?.lpaOnline,
      'lpaVersion': report.lpaInfo?.lpaVersion,
    },
    'signatures': report.signatures
        .map((sig) => {
              'title': sig.title,
              'signerName': sig.signerName,
              'cpfMasked': sig.cpfMasked,
              'signatureType': sig.signatureType,
              'signatureStatus': sig.signatureStatus,
              'certPathStatus': sig.certPathStatus,
              'structureStatus': sig.structureStatus,
              'asymmetricCipherStatus': sig.asymmetricCipherStatus,
              'digestOk': sig.digestOk,
              'signingTime': sig.signingTime,
              'signaturePolicy': sig.signaturePolicy,
              'requiredAttrsStatus': sig.requiredAttrsStatus,
              'incrementalCheck': sig.incrementalCheck,
              'message': sig.message,
              'chainTrusted': sig.chainTrusted,
            })
        .toList(growable: false),
  };
}

String _sha256Hex(Uint8List bytes) {
  return validationSha256Hex(bytes);
}

String _revocationStatus(PdfSignatureRevocationInfo rev) {
  if (rev.ocspRevoked || rev.crlRevoked) return 'revoked';
  if (rev.revocationUnknown) return 'unknown';
  return 'good';
}

String _revocationSource(PdfSignatureRevocationInfo rev) {
  if (rev.ocspChecked && rev.crlChecked) return 'mixed';
  if (rev.ocspChecked) return 'ocsp';
  if (rev.crlChecked) return 'crl';
  return 'none';
}

String? _revocationSoftFailReason(
  PdfSignatureRevocationInfo rev,
  String source,
) {
  if (!rev.revocationUnknown) return null;
  if (source == 'none') {
    return 'Sem consulta OCSP/CRL para comprovar revogação.';
  }
  return 'Consulta de revogação inconclusiva.';
}

String? _decodeGeneralNameUri(ASN1Object obj) {
  if (!_isContextSpecificTag(obj, 6)) return null;
  final bytes = _readValueBytes(obj);
  if (bytes == null || bytes.isEmpty) return null;
  try {
    final decoded = ascii.decode(bytes, allowInvalid: true).trim();
    return decoded.isEmpty ? null : decoded;
  } catch (_) {
    return null;
  }
}

bool? _matchPolicyDigest(PdfLpaPolicyInfo? policy, _SignedAttrsData? attrs) {
  if (policy == null || attrs == null) return null;
  final lpaHash = policy.hashValue;
  final cmsHash = attrs.policyHashValue;
  if (lpaHash == null ||
      lpaHash.isEmpty ||
      cmsHash == null ||
      cmsHash.isEmpty) {
    return null;
  }

  final lpaAlg = policy.hashAlgorithmOid?.trim();
  final cmsAlg = attrs.policyHashAlgorithmOid?.trim();
  if (lpaAlg != null &&
      lpaAlg.isNotEmpty &&
      cmsAlg != null &&
      cmsAlg.isNotEmpty &&
      lpaAlg != cmsAlg) {
    return false;
  }

  if (lpaHash.length != cmsHash.length) return false;
  for (var i = 0; i < lpaHash.length; i++) {
    if (lpaHash[i] != cmsHash[i]) return false;
  }
  return true;
}

String _docMdpDecisionCodeWire(PdfDocMdpDecisionCode code) {
  switch (code) {
    case PdfDocMdpDecisionCode.noCertification:
      return 'NO_CERTIFICATION';
    case PdfDocMdpDecisionCode.p1Blocked:
      return 'P1_BLOCKED';
    case PdfDocMdpDecisionCode.p2Allowed:
      return 'P2_ALLOWED';
    case PdfDocMdpDecisionCode.p3Allowed:
      return 'P3_ALLOWED';
    case PdfDocMdpDecisionCode.unknown:
      return 'UNKNOWN';
  }
}

PdfDocMdpDecisionCode _docMdpDecisionCodeFromWire(String? raw) {
  switch (raw) {
    case 'NO_CERTIFICATION':
    case 'noCertification':
      return PdfDocMdpDecisionCode.noCertification;
    case 'P1_BLOCKED':
    case 'p1Blocked':
      return PdfDocMdpDecisionCode.p1Blocked;
    case 'P2_ALLOWED':
    case 'p2Allowed':
      return PdfDocMdpDecisionCode.p2Allowed;
    case 'P3_ALLOWED':
    case 'p3Allowed':
      return PdfDocMdpDecisionCode.p3Allowed;
    case 'UNKNOWN':
    case 'unknown':
    case null:
      return PdfDocMdpDecisionCode.unknown;
  }
  return PdfDocMdpDecisionCode.unknown;
}

String? _nameFromSubject(String? subject) {
  if (subject == null || subject.trim().isEmpty) return null;
  final match = RegExp(r'(?:^|,\s*)CN\s*=\s*([^,]+)', caseSensitive: false)
      .firstMatch(subject);
  return (match?.group(1) ?? subject).trim();
}

String _maskCpf(String? cpfDigits) {
  return maskCpfForUi(cpfDigits);
}

String? _normalizeName(String? value) {
  return normalizeValidationName(value);
}

bool _subjectMatchesIssuer(String issuer, Set<String> subjects) {
  return subjectMatchesValidationIssuer(issuer, subjects);
}

String _policyLabelFromLpa(PdfLpaPolicyInfo policy) {
  final uri = policy.policyUri.trim();
  if (uri.isEmpty) return policy.policyOid;
  final name = uri.split('/').last;
  return name.isEmpty ? policy.policyOid : '$name (${policy.policyOid})';
}

bool _isPolicyValidAt(PdfLpaPolicyInfo policy, DateTime instantUtc) {
  final notBefore = policy.notBefore?.toUtc();
  final notAfter = policy.notAfter?.toUtc();
  final revoked = policy.revocationDate?.toUtc();
  if (revoked != null && !instantUtc.isBefore(revoked)) {
    return false;
  }
  if (notBefore != null && instantUtc.isBefore(notBefore)) {
    return false;
  }
  if (notAfter != null && instantUtc.isAfter(notAfter)) {
    return false;
  }
  return true;
}

Map<String, dynamic> _encodeValidationReport(
    PdfSignatureValidationReport report) {
  return {
    'signatures':
        report.signatures.map(_encodeSignatureInfo).toList(growable: false),
  };
}

PdfSignatureValidationReport _decodeValidationReport(dynamic raw) {
  if (raw is! Map) {
    return const PdfSignatureValidationReport(
        signatures: <PdfSignatureInfoReport>[]);
  }
  final signatures = (raw['signatures'] as List<dynamic>? ?? const <dynamic>[])
      .whereType<Map>()
      .map((e) =>
          _decodeSignatureInfo(e.map((k, v) => MapEntry(k.toString(), v))))
      .toList(growable: false);
  return PdfSignatureValidationReport(signatures: signatures);
}

Map<String, dynamic> _encodeSignatureInfo(PdfSignatureInfoReport sig) {
  return {
    'signatureIndex': sig.signatureIndex,
    'cmsValid': sig.cmsValid,
    'digestValid': sig.digestValid,
    'intact': sig.intact,
    'docMdp': {
      'isCertificationSignature': sig.docMdp.isCertificationSignature,
      'permissionP': sig.docMdp.permissionP,
    },
    'revocation': {
      'crlChecked': sig.revocation.crlChecked,
      'crlRevoked': sig.revocation.crlRevoked,
      'ocspChecked': sig.revocation.ocspChecked,
      'ocspRevoked': sig.revocation.ocspRevoked,
      'revocationUnknown': sig.revocation.revocationUnknown,
    },
    'signatureField': {
      'fieldName': sig.signatureField?.fieldName,
      'name': sig.signatureField?.name,
      'signingTimeRaw': sig.signatureField?.signingTimeRaw,
      'signatureDictionaryPresent':
          sig.signatureField?.signatureDictionaryPresent,
      'byteRange': sig.signatureField?.byteRange,
    },
    'signatureDictionaryPresent': sig.signatureDictionaryPresent,
    'signingTime': sig.signingTime?.toUtc().toIso8601String(),
    'signaturePolicyOid': sig.signaturePolicyOid,
    'signedAttrsOids': sig.signedAttrsOids,
    'signedAttrsReport': sig.signedAttrsReport == null
        ? null
        : {
            'requiredOids': sig.signedAttrsReport!.requiredOids,
            'optionalOids': sig.signedAttrsReport!.optionalOids,
            'missingRequiredOids': sig.signedAttrsReport!.missingRequiredOids,
            'presentOids': sig.signedAttrsReport!.presentOids,
          },
    'certificates': (sig.certificates ?? const <PdfSignatureCertificateInfo>[])
        .map(_encodeCertificateInfo)
        .toList(growable: false),
    'signerCertificate': sig.signerCertificate == null
        ? null
        : _encodeCertificateInfo(sig.signerCertificate!),
    'chainTrusted': sig.chainTrusted,
    'chainErrors': sig.chainErrors,
    'certValid': sig.certValid,
    'validationStatus': sig.validationStatus.name,
    'message': sig.message,
  };
}

PdfSignatureInfoReport _decodeSignatureInfo(Map<String, dynamic> raw) {
  final docMdpRaw = raw['docMdp'];
  final revRaw = raw['revocation'];
  final fieldRaw = raw['signatureField'];
  final attrsRaw = raw['signedAttrsReport'];
  final certificatesRaw = raw['certificates'];
  final signerRaw = raw['signerCertificate'];

  PdfSignatureValidationStatus status;
  final statusName = raw['validationStatus']?.toString();
  status = PdfSignatureValidationStatus.values.firstWhere(
    (e) => e.name == statusName,
    orElse: () => PdfSignatureValidationStatus.indeterminate,
  );

  return PdfSignatureInfoReport(
    signatureIndex: (raw['signatureIndex'] as num?)?.toInt() ?? 0,
    cmsValid: raw['cmsValid'] == true,
    digestValid: raw['digestValid'] == true,
    intact: raw['intact'] == true,
    docMdp: PdfSignatureDocMdpInfo(
      isCertificationSignature: docMdpRaw is Map
          ? docMdpRaw['isCertificationSignature'] as bool?
          : null,
      permissionP:
          docMdpRaw is Map ? (docMdpRaw['permissionP'] as num?)?.toInt() : null,
    ),
    revocation: PdfSignatureRevocationInfo(
      crlChecked: revRaw is Map && revRaw['crlChecked'] == true,
      crlRevoked: revRaw is Map && revRaw['crlRevoked'] == true,
      ocspChecked: revRaw is Map && revRaw['ocspChecked'] == true,
      ocspRevoked: revRaw is Map && revRaw['ocspRevoked'] == true,
      revocationUnknown:
          revRaw is Map ? revRaw['revocationUnknown'] != false : true,
    ),
    signatureField: fieldRaw is Map
        ? PdfSignatureFieldInfo(
            name: fieldRaw['name']?.toString(),
            fieldName: fieldRaw['fieldName']?.toString(),
            signingTimeRaw: fieldRaw['signingTimeRaw']?.toString(),
            signatureDictionaryPresent:
                fieldRaw['signatureDictionaryPresent'] as bool?,
            byteRange: (fieldRaw['byteRange'] as List<dynamic>?)
                ?.map((e) => (e as num).toInt())
                .toList(growable: false),
          )
        : null,
    signatureDictionaryPresent: raw['signatureDictionaryPresent'] as bool?,
    signingTime: raw['signingTime'] == null
        ? null
        : DateTime.tryParse(raw['signingTime'].toString())?.toUtc(),
    signaturePolicyOid: raw['signaturePolicyOid']?.toString(),
    signedAttrsOids: (raw['signedAttrsOids'] as List<dynamic>?)
        ?.map((e) => e.toString())
        .toList(growable: false),
    signedAttrsReport: attrsRaw is Map
        ? PdfSignatureSignedAttrsReport(
            requiredOids: (attrsRaw['requiredOids'] as List<dynamic>? ??
                    const <dynamic>[])
                .map((e) => e.toString())
                .toList(growable: false),
            optionalOids: (attrsRaw['optionalOids'] as List<dynamic>? ??
                    const <dynamic>[])
                .map((e) => e.toString())
                .toList(growable: false),
            missingRequiredOids:
                (attrsRaw['missingRequiredOids'] as List<dynamic>? ??
                        const <dynamic>[])
                    .map((e) => e.toString())
                    .toList(growable: false),
            presentOids:
                (attrsRaw['presentOids'] as List<dynamic>? ?? const <dynamic>[])
                    .map((e) => e.toString())
                    .toList(growable: false),
          )
        : null,
    certificates: certificatesRaw is List
        ? certificatesRaw
            .whereType<Map>()
            .map((e) => _decodeCertificateInfo(
                e.map((k, v) => MapEntry(k.toString(), v))))
            .toList(growable: false)
        : null,
    signerCertificate: signerRaw is Map
        ? _decodeCertificateInfo(
            signerRaw.map((k, v) => MapEntry(k.toString(), v)))
        : null,
    chainTrusted: raw['chainTrusted'] as bool?,
    chainErrors: (raw['chainErrors'] as List<dynamic>?)
        ?.map((e) => e.toString())
        .toList(growable: false),
    certValid: raw['certValid'] as bool?,
    validationStatus: status,
    message: raw['message']?.toString(),
  );
}

Map<String, dynamic> _encodeCertificateInfo(PdfSignatureCertificateInfo cert) {
  return {
    'subject': cert.subject,
    'issuer': cert.issuer,
    'serial': cert.serial?.toString(),
    'notBefore': cert.notBefore?.toUtc().toIso8601String(),
    'notAfter': cert.notAfter?.toUtc().toIso8601String(),
    'otherNames': cert.otherNames
        .map((e) => {'oid': e.oid, 'value': e.value})
        .toList(growable: false),
    'icpBrasilIds': cert.icpBrasilIds == null
        ? null
        : {
            'cpf': cert.icpBrasilIds!.cpf,
            'cnpj': cert.icpBrasilIds!.cnpj,
            'nis': cert.icpBrasilIds!.nis,
            'responsavelCpf': cert.icpBrasilIds!.responsavelCpf,
            'responsavelNome': cert.icpBrasilIds!.responsavelNome,
            'tituloEleitor': cert.icpBrasilIds!.tituloEleitor,
            'cei': cert.icpBrasilIds!.cei,
            'dateOfBirth':
                cert.icpBrasilIds!.dateOfBirth?.toUtc().toIso8601String(),
            'raw': cert.icpBrasilIds!.raw,
          },
  };
}

PdfSignatureCertificateInfo _decodeCertificateInfo(Map<String, dynamic> raw) {
  final otherNamesRaw = raw['otherNames'];
  final idsRaw = raw['icpBrasilIds'];

  return PdfSignatureCertificateInfo(
    subject: raw['subject']?.toString(),
    issuer: raw['issuer']?.toString(),
    serial: raw['serial'] == null
        ? null
        : BigInt.tryParse(raw['serial'].toString()),
    notBefore: raw['notBefore'] == null
        ? null
        : DateTime.tryParse(raw['notBefore'].toString())?.toUtc(),
    notAfter: raw['notAfter'] == null
        ? null
        : DateTime.tryParse(raw['notAfter'].toString())?.toUtc(),
    otherNames: otherNamesRaw is List
        ? otherNamesRaw
            .whereType<Map>()
            .map((e) => PdfSignatureOtherName(
                  e['oid']?.toString() ?? '',
                  e['value']?.toString() ?? '',
                ))
            .toList(growable: false)
        : const <PdfSignatureOtherName>[],
    icpBrasilIds: idsRaw is Map
        ? PdfSignatureIcpBrasilIds(
            cpf: idsRaw['cpf']?.toString(),
            cnpj: idsRaw['cnpj']?.toString(),
            nis: idsRaw['nis']?.toString(),
            responsavelCpf: idsRaw['responsavelCpf']?.toString(),
            responsavelNome: idsRaw['responsavelNome']?.toString(),
            tituloEleitor: idsRaw['tituloEleitor']?.toString(),
            cei: idsRaw['cei']?.toString(),
            dateOfBirth: idsRaw['dateOfBirth'] == null
                ? null
                : DateTime.tryParse(idsRaw['dateOfBirth'].toString())?.toUtc(),
            raw: idsRaw['raw'] is Map
                ? (idsRaw['raw'] as Map)
                    .map((k, v) => MapEntry(k.toString(), v.toString()))
                : null,
          )
        : null,
  );
}

Map<String, String> _signatureFieldNamesByRange(Uint8List pdfBytes) {
  final out = <String, String>{};
  final fields = PdfDocumentParser(pdfBytes).extractSignatureFields();
  for (final f in fields) {
    final r = f.byteRange;
    if (r == null || r.length != 4) continue;
    out['${r[0]}:${r[1]}:${r[2]}:${r[3]}'] =
        f.fieldName ?? f.name ?? 'Signature';
  }
  return out;
}

String _byteRangeKeyFromRanges(List<List<int>> ranges, int index) {
  if (index < 0 || index >= ranges.length) return '';
  final r = ranges[index];
  if (r.length != 4) return '';
  return '${r[0]}:${r[1]}:${r[2]}:${r[3]}';
}

_SignerIdentifierData _extractSignerIssuerAndSerialFromCms(Uint8List cmsBytes) {
  try {
    final root = ASN1Parser(cmsBytes).nextObject();
    if (root is! ASN1Sequence || root.elements.length < 2) {
      return const _SignerIdentifierData();
    }
    final signedData = _unwrapTaggedObject(root.elements[1]);
    if (signedData is! ASN1Sequence) return const _SignerIdentifierData();

    ASN1Set? signerInfos;
    for (final el in signedData.elements) {
      if (el is ASN1Set) signerInfos = el;
    }
    if (signerInfos == null || signerInfos.elements.isEmpty) {
      return const _SignerIdentifierData();
    }

    final signerInfo = signerInfos.elements.first;
    if (signerInfo is! ASN1Sequence || signerInfo.elements.length < 2) {
      return const _SignerIdentifierData();
    }

    final sid = signerInfo.elements[1];
    if (sid is ASN1Sequence && sid.elements.length >= 2) {
      final issuer = sid.elements[0];
      final serial = sid.elements[1];
      if (issuer is ASN1Sequence && serial is ASN1Integer) {
        final issuerDn = X509Name.fromAsn1(issuer).toString();
        final serialBig = serial.valueAsBigInteger;
        return _SignerIdentifierData(
          serialDecimal: serialBig.toString(),
          serialHex: bigIntToHexUpper(serialBig),
          issuerDn: issuerDn,
        );
      }
    }

    return const _SignerIdentifierData();
  } catch (_) {
    return const _SignerIdentifierData();
  }
}

_SignedAttrsData _extractSignedAttrsFromCms(Uint8List cmsBytes) {
  try {
    final root = ASN1Parser(cmsBytes).nextObject();
    if (root is! ASN1Sequence || root.elements.length < 2) {
      return const _SignedAttrsData();
    }
    final signedData = _unwrapTaggedObject(root.elements[1]);
    if (signedData is! ASN1Sequence) return const _SignedAttrsData();

    ASN1Set? signerInfos;
    for (final el in signedData.elements) {
      if (el is ASN1Set) signerInfos = el;
    }
    if (signerInfos == null || signerInfos.elements.isEmpty) {
      return const _SignedAttrsData();
    }

    final signerInfo = signerInfos.elements.first;
    if (signerInfo is! ASN1Sequence) return const _SignedAttrsData();

    ASN1Object? signedAttrsTagged;
    for (final el in signerInfo.elements) {
      if (_isContextSpecificTag(el, 0)) {
        signedAttrsTagged = el;
        break;
      }
    }
    if (signedAttrsTagged == null) return const _SignedAttrsData();

    final attrs = _unwrapTaggedObject(signedAttrsTagged);
    Iterable<ASN1Object> list;
    if (attrs is ASN1Set) {
      list = attrs.elements.cast<ASN1Object>();
    } else if (attrs is ASN1Sequence) {
      list = attrs.elements.cast<ASN1Object>();
    } else {
      return const _SignedAttrsData();
    }

    String? policyOid;
    DateTime? signingTime;
    String? policyHashAlgorithmOid;
    Uint8List? policyHashValue;

    for (final attr in list) {
      if (attr is! ASN1Sequence || attr.elements.length < 2) continue;
      final oidObj = attr.elements[0];
      final setObj = attr.elements[1];
      if (oidObj is! ASN1ObjectIdentifier) continue;
      final oid = oidObj.identifier ?? '';
      final values = <ASN1Object>[];
      if (setObj is ASN1Set || setObj is ASN1Sequence) {
        final dynamic typed = setObj;
        values
            .addAll((typed.elements as List<dynamic>).whereType<ASN1Object>());
      } else {
        values.add(setObj);
      }
      if (values.isEmpty) continue;

      if (oid == '1.2.840.113549.1.9.5') {
        final v = values.first;
        if (v is ASN1UtcTime || v is ASN1GeneralizedTime) {
          signingTime = _parseAsn1Date(v);
        }
      }

      if (oid == '1.2.840.113549.1.9.16.2.15') {
        final policyData = _extractPolicyIdentifierData(values.first);
        if (policyData != null) {
          policyOid = policyData.policyOid ?? policyOid;
          policyHashAlgorithmOid =
              policyData.hashAlgorithmOid ?? policyHashAlgorithmOid;
          policyHashValue = policyData.hashValue ?? policyHashValue;
        }
      }
    }

    return _SignedAttrsData(
      policyOid: policyOid,
      signingTime: signingTime,
      policyHashAlgorithmOid: policyHashAlgorithmOid,
      policyHashValue: policyHashValue,
    );
  } catch (_) {
    return const _SignedAttrsData();
  }
}

DateTime? _parseAsn1Date(ASN1Object obj) {
  if (obj is ASN1UtcTime) return obj.dateTimeValue.toUtc();
  if (obj is ASN1GeneralizedTime) return obj.dateTimeValue.toUtc();
  return null;
}

_PolicyIdentifierData? _extractPolicyIdentifierData(ASN1Object value) {
  final seq = _asAsn1SequenceLoose(value);
  if (seq == null || seq.elements.isEmpty) return null;

  String? policyOid;
  if (seq.elements.first is ASN1ObjectIdentifier) {
    policyOid = (seq.elements.first as ASN1ObjectIdentifier).identifier;
  }

  String? hashAlgorithmOid;
  Uint8List? hashValue;
  if (seq.elements.length > 1) {
    final hash = _extractPolicyHashInfo(seq.elements[1]);
    if (hash != null) {
      hashAlgorithmOid = hash.hashAlgorithmOid;
      hashValue = hash.hashValue;
    }
  }

  if (policyOid == null && hashAlgorithmOid == null && hashValue == null) {
    return null;
  }
  return _PolicyIdentifierData(
    policyOid: policyOid,
    hashAlgorithmOid: hashAlgorithmOid,
    hashValue: hashValue,
  );
}

_PolicyHashInfo? _extractPolicyHashInfo(ASN1Object obj) {
  final seq = _asAsn1SequenceLoose(obj);
  if (seq == null || seq.elements.length < 2) return null;

  String? hashAlgorithmOid;
  final algSeq = _asAsn1SequenceLoose(seq.elements[0]);
  if (algSeq != null && algSeq.elements.isNotEmpty) {
    final oidObj = algSeq.elements.first;
    if (oidObj is ASN1ObjectIdentifier) {
      hashAlgorithmOid = oidObj.identifier;
    }
  }

  Uint8List? hashValue;
  final hashObj = seq.elements[1];
  if (hashObj is ASN1OctetString) {
    hashValue = hashObj.valueBytes();
  } else {
    hashValue = _readValueBytes(hashObj);
  }

  if (hashAlgorithmOid == null && (hashValue == null || hashValue.isEmpty)) {
    return null;
  }
  return _PolicyHashInfo(
    hashAlgorithmOid: hashAlgorithmOid,
    hashValue: hashValue,
  );
}

ASN1Sequence? _asAsn1SequenceLoose(ASN1Object obj) {
  if (obj is ASN1Sequence) return obj;
  final unwrapped = _unwrapTaggedObject(obj);
  if (unwrapped is ASN1Sequence) return unwrapped;
  try {
    final parsed = ASN1Parser(obj.encodedBytes).nextObject();
    if (parsed is ASN1Sequence) return parsed;
  } catch (_) {
    return null;
  }
  return null;
}

Map<int, String?> _extractAuthorityKeyIdentifiersFromCms(Uint8List pdfBytes) {
  final out = <int, String?>{};
  final contents = extractAllSignatureContents(pdfBytes);
  for (var i = 0; i < contents.length; i++) {
    out[i] = _extractAkiHexFromCms(contents[i]);
  }
  return out;
}

String? _extractAkiHexFromCms(Uint8List cmsBytes) {
  try {
    final root = ASN1Parser(cmsBytes).nextObject();
    if (root is! ASN1Sequence || root.elements.length < 2) return null;

    final signedData = _unwrapTaggedObject(root.elements[1]);
    if (signedData is! ASN1Sequence || signedData.elements.length < 4) {
      return null;
    }

    ASN1Object? certsObj;
    ASN1Set? signerInfos;
    for (final el in signedData.elements) {
      if (_isContextSpecificTag(el, 0)) {
        certsObj ??= _unwrapTaggedObject(el);
      }
      if (el is ASN1Set) {
        signerInfos = el;
      }
    }

    if (certsObj == null ||
        signerInfos == null ||
        signerInfos.elements.isEmpty) {
      return null;
    }

    final certs = _extractCertificateCandidates(certsObj);
    if (certs.isEmpty) return null;

    final signerInfo = signerInfos.elements.first;
    if (signerInfo is! ASN1Sequence || signerInfo.elements.length < 2) {
      return null;
    }

    final sid = signerInfo.elements[1];
    final matched = _findSignerCertificateBySid(certs, sid);
    if (matched == null) return null;

    return _extractAuthorityKeyIdentifierHexFromDerCert(matched);
  } catch (_) {
    return null;
  }
}

X509Certificate? _findSignerCertificateBySid(
  List<X509Certificate> certs,
  ASN1Object sid,
) {
  if (_isContextSpecificTag(sid, 0)) {
    final keyId = _decodeTaggedOctetString(sid);
    if (keyId != null && keyId.isNotEmpty) {
      final keyIdHex = _bytesToHex(keyId);
      for (final cert in certs) {
        final skiHex = _extractSubjectKeyIdentifierHexFromDerCert(cert);
        if (skiHex != null && skiHex.toLowerCase() == keyIdHex.toLowerCase()) {
          return cert;
        }
      }
    }
    return certs.isNotEmpty ? certs.first : null;
  }

  if (sid is ASN1Sequence && sid.elements.length >= 2) {
    final issuerObj = sid.elements[0];
    final serialObj = sid.elements[1];
    if (issuerObj is ASN1Sequence && serialObj is ASN1Integer) {
      final issuerName = X509Name.fromAsn1(issuerObj).toString();
      final serial = serialObj.valueAsBigInteger;
      final normalizedIssuer = _normalizeName(issuerName);
      for (final cert in certs) {
        final certIssuer = _normalizeName(cert.issuer.toString());
        if (cert.serialNumber == serial && certIssuer == normalizedIssuer) {
          return cert;
        }
      }
    }
  }

  return certs.isNotEmpty ? certs.first : null;
}

List<X509Certificate> _extractCertificateCandidates(ASN1Object certsObj) {
  final out = <X509Certificate>[];

  Iterable<ASN1Object> iterateElements(ASN1Object obj) {
    if (obj is ASN1Set) return obj.elements.cast<ASN1Object>();
    if (obj is ASN1Sequence) return obj.elements.cast<ASN1Object>();
    return const <ASN1Object>[];
  }

  for (final el in iterateElements(certsObj)) {
    if (el is! ASN1Sequence || el.elements.length < 3) continue;
    try {
      out.add(X509Certificate.fromDer(el.encodedBytes));
    } catch (_) {
      continue;
    }
  }

  return out;
}

String? _extractAuthorityKeyIdentifierHexFromDerCert(X509Certificate cert) {
  final ext = cert.extensions.firstWhere(
    (e) => e.oid == '2.5.29.35',
    orElse: () => X509Extension(
      oid: '',
      value: Uint8List(0),
      critical: false,
    ),
  );
  if (ext.oid.isEmpty || ext.value.isEmpty) return null;

  try {
    final obj = ASN1Parser(ext.value).nextObject();
    if (obj is! ASN1Sequence) return null;
    for (final el in obj.elements) {
      if (!_isContextSpecificTag(el, 0)) continue;
      final decoded = _decodeTaggedOctetString(el);
      if (decoded == null || decoded.isEmpty) continue;
      return _bytesToHex(decoded);
    }
    return null;
  } catch (_) {
    return null;
  }
}

String? _extractSubjectKeyIdentifierHexFromDerCert(X509Certificate cert) {
  final ext = cert.extensions.firstWhere(
    (e) => e.oid == '2.5.29.14',
    orElse: () => X509Extension(
      oid: '',
      value: Uint8List(0),
      critical: false,
    ),
  );
  if (ext.oid.isEmpty || ext.value.isEmpty) return null;

  try {
    final obj = ASN1Parser(ext.value).nextObject();
    if (obj is ASN1OctetString) {
      return _bytesToHex(obj.valueBytes());
    }
    final bytes = _readValueBytes(obj);
    if (bytes == null || bytes.isEmpty) return null;
    return _bytesToHex(bytes);
  } catch (_) {
    return null;
  }
}

ASN1Object _unwrapTaggedObject(ASN1Object obj) {
  final bytes = _readValueBytes(obj);
  if (bytes == null || bytes.isEmpty) return obj;
  try {
    return ASN1Parser(bytes).nextObject();
  } catch (_) {
    return obj;
  }
}

bool _isContextSpecificTag(ASN1Object obj, int tagNo) {
  return isContextSpecific(obj.tag) && (obj.tag & 0x1f) == tagNo;
}

Uint8List? _decodeTaggedOctetString(ASN1Object obj) {
  final bytes = _readValueBytes(obj);
  if (bytes == null || bytes.isEmpty) return null;

  try {
    final inner = ASN1Parser(bytes).nextObject();
    if (inner is ASN1OctetString) {
      return inner.valueBytes();
    }
    final nested = _readValueBytes(inner);
    return nested == null || nested.isEmpty ? bytes : nested;
  } catch (_) {
    return bytes;
  }
}

Uint8List? _readValueBytes(ASN1Object obj) {
  try {
    final bytes = obj.valueBytes();
    return bytes;
  } catch (_) {
    return null;
  }
}

String _bytesToHex(List<int> bytes) {
  return bytesToHexLower(bytes);
}
