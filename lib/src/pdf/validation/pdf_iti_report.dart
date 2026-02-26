import 'dart:typed_data';
import '../crypto/pdf_crypto.dart';
import 'pdf_signature_validator.dart';
import 'pdf_lpa.dart';

class PdfItiComplianceMetadata {
  PdfItiComplianceMetadata({
    this.name = 'Validar',
    DateTime? validationDate,
    this.verifierVersion = 'Não informado',
    this.validatorVersion = 'Não informado',
    this.verificationSource = 'Offline',
  }) : validationDate = validationDate ?? DateTime.now();

  final String name;
  final DateTime validationDate;
  final String verifierVersion;
  final String validatorVersion;
  final String verificationSource;
}

class PdfItiPolicyInfo {
  const PdfItiPolicyInfo({
    this.paValid,
    this.paValidFrom,
    this.paValidTo,
    this.paExpired,
    this.paValidInLpa,
    this.paOnline,
    this.paOidLabel,
  });

  final bool? paValid;
  final DateTime? paValidFrom;
  final DateTime? paValidTo;
  final bool? paExpired;
  final bool? paValidInLpa;
  final bool? paOnline;
  final String? paOidLabel;
}

class PdfItiLpaInfo {
  const PdfItiLpaInfo({
    this.lpaValid,
    this.nextIssue,
    this.lpaExpired,
    this.lpaName,
    this.lpaOnline,
    this.lpaVersion,
  });

  final bool? lpaValid;
  final DateTime? nextIssue;
  final bool? lpaExpired;
  final String? lpaName;
  final bool? lpaOnline;
  final String? lpaVersion;
}

class PdfItiComplianceReport {
  PdfItiComplianceReport({
    required this.metadata,
    required this.fileName,
    required this.fileHashSha256,
    required this.fileType,
    required this.signatureCount,
    required this.anchoredSignatureCount,
    required this.signatures,
    this.policyInfo,
    this.lpaInfo,
  });

  final PdfItiComplianceMetadata metadata;
  final String fileName;
  final String fileHashSha256;
  final String fileType;
  final int signatureCount;
  final int anchoredSignatureCount;
  final List<PdfItiSignatureReport> signatures;
  final PdfItiPolicyInfo? policyInfo;
  final PdfItiLpaInfo? lpaInfo;

  static List<PdfItiSignatureReport> _buildSignatureReports(
    List<PdfSignatureInfoReport> infos,
    PdfLpa? lpa,
  ) {
    return infos.map((sig) {
      final oid = sig.signaturePolicyOid;
      final policy = oid != null && lpa != null ? lpa.findPolicy(oid) : null;
      final label = policy != null ? _policyFileName(policy) : null;
      return PdfItiSignatureReport.fromInfo(sig, policyLabel: label);
    }).toList();
  }

  factory PdfItiComplianceReport.fromValidation({
    required Uint8List pdfBytes,
    required PdfSignatureValidationReport validationReport,
    required PdfItiComplianceMetadata metadata,
    String? fileName,
    String fileType = 'PDF',
    PdfItiPolicyInfo? policyInfo,
    PdfItiLpaInfo? lpaInfo,
    PdfLpa? lpa,
    String? lpaName,
    bool? lpaOnline,
    bool? paOnline,
  }) {
    final hash = _bytesToHex(PdfCrypto.sha256(pdfBytes));
    final signatures = _buildSignatureReports(validationReport.signatures, lpa);
    final anchored = signatures.where((s) => s.chainTrusted == true).length;

    PdfItiPolicyInfo? computedPolicy = policyInfo;
    PdfItiLpaInfo? computedLpa = lpaInfo;
    if (computedPolicy == null || computedLpa == null) {
      final policyOid = validationReport.signatures
          .map((s) => s.signaturePolicyOid)
          .firstWhere((oid) => oid != null && oid.isNotEmpty,
              orElse: () => null);
      final policy =
          policyOid != null && lpa != null ? lpa.findPolicy(policyOid) : null;
      final now = DateTime.now();
      if (computedPolicy == null) {
        final validInLpa = policy != null;
        final revoked = policy?.revocationDate != null;
        final notBefore = policy?.notBefore;
        final notAfter = policy?.notAfter;
        final inPeriod = notBefore != null && notAfter != null
            ? (now.isAfter(notBefore) || now.isAtSameMomentAs(notBefore)) &&
                (now.isBefore(notAfter) || now.isAtSameMomentAs(notAfter))
            : null;
        final paValid = validInLpa && revoked == false && (inPeriod ?? true);
        final paExpired = notAfter != null ? now.isAfter(notAfter) : null;
        computedPolicy = PdfItiPolicyInfo(
          paValid: validInLpa ? paValid : null,
          paValidFrom: notBefore,
          paValidTo: notAfter,
          paExpired: validInLpa ? paExpired : null,
          paValidInLpa: validInLpa ? true : null,
          paOnline: paOnline,
          paOidLabel: policy != null ? _policyLabel(policy) : null,
        );
      }
      if (computedLpa == null) {
        final nextUpdate = lpa?.nextUpdate;
        final valid = nextUpdate != null ? !now.isAfter(nextUpdate) : null;
        computedLpa = PdfItiLpaInfo(
          lpaValid: valid,
          nextIssue: nextUpdate,
          lpaExpired: nextUpdate != null ? now.isAfter(nextUpdate) : null,
          lpaName: lpaName,
          lpaOnline: lpaOnline,
          lpaVersion: lpa?.version?.toString(),
        );
      }
    }

    return PdfItiComplianceReport(
      metadata: metadata,
      fileName: fileName ?? 'Arquivo PDF',
      fileHashSha256: hash,
      fileType: fileType,
      signatureCount: signatures.length,
      anchoredSignatureCount: anchored,
      signatures: signatures,
      policyInfo: computedPolicy,
      lpaInfo: computedLpa,
    );
  }

  String toText() {
    final buffer = StringBuffer();
    buffer.writeln('Relatório de Conformidade');
    buffer.writeln('Nome: ${metadata.name}');
    buffer.writeln('');
    buffer.writeln(
      'Data de validação: ${_formatDateTimeBrt(metadata.validationDate)}',
    );
    buffer.writeln('');
    buffer.writeln(
      'Versão do software(Verificador de Conformidade): ${metadata.verifierVersion}',
    );
    buffer.writeln('');
    buffer.writeln(
      'Versão do software(Validador de Documentos): ${metadata.validatorVersion}',
    );
    buffer.writeln('');
    buffer.writeln('Fonte de verificação: ${metadata.verificationSource}');
    buffer.writeln('');
    buffer.writeln('');
    buffer.writeln('Informações do arquivo');
    buffer.writeln('Nome do arquivo: $fileName');
    buffer.writeln('');
    buffer.writeln('Resumo da SHA256 do arquivo: $fileHashSha256');
    buffer.writeln('');
    buffer.writeln('Tipo do arquivo: $fileType');
    buffer.writeln('');
    buffer.writeln('Quantidade de assinaturas: $signatureCount');
    buffer.writeln('');
    buffer.writeln(
        'Quantidade de assinaturas ancoradas: $anchoredSignatureCount');
    buffer.writeln('');
    buffer.writeln('');
    buffer.writeln('Informações da Política de Assinatura');

    final pa = policyInfo;
    buffer.writeln('PA válida: ${_formatBool(pa?.paValid)}');
    buffer.writeln('');
    buffer.writeln(
      'Período de validade da PA: ${_formatPeriod(pa?.paValidFrom, pa?.paValidTo)}',
    );
    buffer.writeln('');
    buffer.writeln('PA expirada: ${_formatBool(pa?.paExpired)}');
    buffer.writeln('');
    buffer.writeln('PA válida na LPA: ${_formatBool(pa?.paValidInLpa)}');
    buffer.writeln('');
    buffer.writeln('PA online: ${_formatBool(pa?.paOnline)}');
    buffer.writeln('');
    buffer.writeln('OID da PA: ${pa?.paOidLabel ?? 'Não informado'}');
    buffer.writeln('');
    buffer.writeln('');
    buffer.writeln('Informações da Lista de Políticas de Assinatura');

    final lpa = lpaInfo;
    buffer.writeln('LPA válida: ${_formatBool(lpa?.lpaValid)}');
    buffer.writeln('');
    buffer.writeln(
      'Próxima emissão da LPA: ${_formatDateTimeBrt(lpa?.nextIssue)}',
    );
    buffer.writeln('');
    buffer.writeln('LPA expirada: ${_formatBool(lpa?.lpaExpired)}');
    buffer.writeln('');
    buffer.writeln('Nome da LPA: ${lpa?.lpaName ?? 'Não informado'}');
    buffer.writeln('');
    buffer.writeln('LPA online: ${_formatBool(lpa?.lpaOnline)}');
    buffer.writeln('');
    buffer.writeln('Versão da LPA: ${lpa?.lpaVersion ?? 'Não informado'}');
    buffer.writeln('');

    for (final sig in signatures) {
      buffer.writeln('');
      buffer.writeln(sig.title);
      buffer.writeln('');
      buffer.writeln('Informações da assinatura');
      buffer.writeln('Assinante: ${sig.signerName}');
      buffer.writeln('');
      buffer.writeln('CPF: ${sig.cpfMasked}');
      buffer.writeln('');
      buffer.writeln('Tipo de assinatura: ${sig.signatureType}');
      buffer.writeln('');
      buffer.writeln('Status de assinatura: ${sig.signatureStatus}');
      buffer.writeln('');
      buffer.writeln('Caminho de certificação: ${sig.certPathStatus}');
      buffer.writeln('');
      buffer.writeln('Estrutura: ${sig.structureStatus}');
      buffer.writeln('');
      buffer.writeln('Cifra assimétrica: ${sig.asymmetricCipherStatus}');
      buffer.writeln('');
      buffer.writeln('Resumo criptográfico: ${sig.digestOk}');
      buffer.writeln('');
      buffer.writeln('Data assinatura: ${sig.signingTime}');
      buffer.writeln('');
      buffer.writeln('Política de assinatura: ${sig.signaturePolicy}');
      buffer.writeln('');
      buffer.writeln('Atributos obrigatórios: ${sig.requiredAttrsStatus}');
      buffer.writeln('');
      buffer.writeln('Verificação incremental: ${sig.incrementalCheck}');
      buffer.writeln('');
      buffer.writeln('Mensagem de erro: ${sig.message}');
      buffer.writeln('');
      buffer.writeln('');
      buffer.writeln('Certificados utilizados');
      buffer.writeln('');

      for (final cert in sig.certificates) {
        buffer.writeln(cert.subject);
        buffer.writeln('Buscado: ${cert.fetchSource}');
        buffer.writeln('');
        buffer.writeln('Assinatura: ${cert.isSignature}');
        buffer.writeln('');
        buffer.writeln('Emissor: ${cert.issuer}');
        buffer.writeln('');
        buffer.writeln('Data de emissão: ${cert.notBefore}');
        buffer.writeln('');
        buffer.writeln('Aprovado até: ${cert.notAfter}');
        buffer.writeln('');
        buffer.writeln('Expirado (LCR): ${cert.revoked}');
        buffer.writeln('');
        buffer.writeln('');
      }

      buffer.writeln('Atributos usados');
      buffer.writeln('ATRIBUTOS OBRIGATÓRIOS:');
      buffer.writeln('');
      for (final attr in sig.requiredAttributes) {
        buffer.writeln('Nome do atributo:${attr.name}');
        buffer.writeln('');
        buffer.writeln('Corretude: ${attr.status}');
        buffer.writeln('');
        buffer.writeln('');
      }

      if (sig.optionalAttributes.isEmpty) {
        buffer.writeln('ATRIBUTOS OPCIONAIS:Não possui.');
      } else {
        buffer.writeln('ATRIBUTOS OPCIONAIS:');
        buffer.writeln('');
        for (final attr in sig.optionalAttributes) {
          buffer.writeln('Nome do atributo:${attr.name}');
          buffer.writeln('');
          buffer.writeln('Corretude: ${attr.status}');
          buffer.writeln('');
          buffer.writeln('');
        }
      }
    }

    return buffer.toString();
  }
}

class PdfItiSignatureReport {
  PdfItiSignatureReport({
    required this.title,
    required this.signerName,
    required this.cpfMasked,
    required this.signatureType,
    required this.signatureStatus,
    required this.certPathStatus,
    required this.structureStatus,
    required this.asymmetricCipherStatus,
    required this.digestOk,
    required this.signingTime,
    required this.signaturePolicy,
    required this.requiredAttrsStatus,
    required this.incrementalCheck,
    required this.message,
    required this.certificates,
    required this.requiredAttributes,
    required this.optionalAttributes,
    required this.chainTrusted,
  });

  final String title;
  final String signerName;
  final String cpfMasked;
  final String signatureType;
  final String signatureStatus;
  final String certPathStatus;
  final String structureStatus;
  final String asymmetricCipherStatus;
  final String digestOk;
  final String signingTime;
  final String signaturePolicy;
  final String requiredAttrsStatus;
  final String incrementalCheck;
  final String message;
  final List<PdfItiCertificateReport> certificates;
  final List<PdfItiAttributeReport> requiredAttributes;
  final List<PdfItiAttributeReport> optionalAttributes;
  final bool? chainTrusted;

  factory PdfItiSignatureReport.fromInfo(
    PdfSignatureInfoReport info, {
    String? policyLabel,
  }) {
    final signerCert = info.signerCertificate;
    final signerName =
        signerCert?.subject ?? info.signatureField?.name ?? 'Não informado';
    final title = signerName.isNotEmpty ? signerName : 'Assinatura';

    final cpf = signerCert?.icpBrasilIds?.cpf;
    final cpfMasked = _maskCpf(cpf) ?? 'Não informado';

    final signatureType = 'Destacada';

    final revoked = info.revocation.crlRevoked || info.revocation.ocspRevoked;
    final signatureStatus = (info.cmsValid &&
            info.digestValid &&
            info.intact &&
            info.certValid != false &&
            !revoked)
        ? 'Aprovado'
        : 'Reprovado';

    final certPathStatus = info.chainTrusted == true
        ? 'Valid'
        : (info.chainTrusted == false ? 'Invalid' : 'Unknown');

    final structureStatus =
        info.intact ? 'Em conformidade com o padrão' : 'Não conforme';

    final asymmetricCipherStatus = info.cmsValid ? 'Aprovada' : 'Reprovada';
    final digestOk = info.digestValid ? 'true' : 'false';

    final signingTime = _formatDateTimeBrt(info.signingTime) ??
        (info.signatureField?.signingTimeRaw ?? 'Não informado');

    final signaturePolicy =
        policyLabel ?? info.signaturePolicyOid ?? 'Não informado';

    final requiredAttrsOk =
        info.signedAttrsReport?.missingRequiredOids.isEmpty == true &&
            info.signatureDictionaryPresent == true;
    final requiredAttrsStatus = requiredAttrsOk ? 'Aprovados' : 'Reprovados';

    final incrementalCheck = info.docMdp.isCertificationSignature == true &&
            info.docMdp.permissionP != null
        ? 'DocMDP - Com permissão ${info.docMdp.permissionP}, DocMDP'
        : 'Não possui';

    final message = info.message ?? 'Nenhuma mensagem de alerta';

    final certificates = _buildCertificatesReport(info);
    final attributes = _buildAttributesReport(info);

    return PdfItiSignatureReport(
      title: title,
      signerName: signerName,
      cpfMasked: cpfMasked,
      signatureType: signatureType,
      signatureStatus: signatureStatus,
      certPathStatus: certPathStatus,
      structureStatus: structureStatus,
      asymmetricCipherStatus: asymmetricCipherStatus,
      digestOk: digestOk,
      signingTime: signingTime,
      signaturePolicy: signaturePolicy,
      requiredAttrsStatus: requiredAttrsStatus,
      incrementalCheck: incrementalCheck,
      message: message,
      certificates: certificates,
      requiredAttributes: attributes.required,
      optionalAttributes: attributes.optional,
      chainTrusted: info.chainTrusted,
    );
  }
}

class PdfItiCertificateReport {
  PdfItiCertificateReport({
    required this.subject,
    required this.issuer,
    required this.notBefore,
    required this.notAfter,
    required this.fetchSource,
    required this.isSignature,
    required this.revoked,
  });

  final String subject;
  final String issuer;
  final String notBefore;
  final String notAfter;
  final String fetchSource;
  final String isSignature;
  final String revoked;
}

class PdfItiAttributeReport {
  PdfItiAttributeReport({required this.name, required this.status});

  final String name;
  final String status;
}

({List<PdfItiAttributeReport> required, List<PdfItiAttributeReport> optional})
    _buildAttributesReport(PdfSignatureInfoReport info) {
  final required = <PdfItiAttributeReport>[];
  final optional = <PdfItiAttributeReport>[];

  final present = info.signedAttrsReport?.presentOids ?? const <String>[];
  final requiredOids = info.signedAttrsReport?.requiredOids ?? const <String>[];
  final optionalOids = info.signedAttrsReport?.optionalOids ?? const <String>[];

  for (final oid in requiredOids) {
    final name = _oidToAttributeName(oid);
    final status = present.contains(oid) ? 'Valid' : 'Invalid';
    required.add(PdfItiAttributeReport(name: name, status: status));
  }

  final signatureDictPresent = info.signatureDictionaryPresent == true;
  required.add(PdfItiAttributeReport(
    name: 'SignatureDictionary',
    status: signatureDictPresent ? 'Valid' : 'Invalid',
  ));

  for (final oid in optionalOids) {
    if (!present.contains(oid)) continue;
    final name = _oidToAttributeName(oid);
    optional.add(PdfItiAttributeReport(name: name, status: 'Valid'));
  }

  return (required: required, optional: optional);
}

List<PdfItiCertificateReport> _buildCertificatesReport(
  PdfSignatureInfoReport info,
) {
  final certs = info.certificates ?? const <PdfSignatureCertificateInfo>[];
  return certs
      .map((cert) => PdfItiCertificateReport(
            subject: cert.subject ?? 'Não informado',
            issuer: cert.issuer ?? 'Não informado',
            notBefore: _formatDateTimeBrt(cert.notBefore) ?? 'Não informado',
            notAfter: _formatDateTimeBrt(cert.notAfter) ?? 'Não informado',
            fetchSource: 'Offline',
            isSignature: 'true',
            revoked: 'false',
          ))
      .toList();
}

String _oidToAttributeName(String oid) {
  const names = <String, String>{
    '1.2.840.113549.1.9.3': 'IdContentType',
    '1.2.840.113549.1.9.4': 'IdMessageDigest',
    '1.2.840.113549.1.9.5': 'IdSigningTime',
    '1.2.840.113549.1.9.16.2.15': 'IdAaEtsSigPolicyId',
    '1.2.840.113549.1.9.16.2.47': 'IdAaSigningCertificateV2',
  };
  return names[oid] ?? oid;
}

String _policyLabel(PdfLpaPolicyInfo policy) {
  final uri = policy.policyUri.trim();
  if (uri.isEmpty) return policy.policyOid;
  final name = uri.split('/').last;
  if (name.isEmpty) return policy.policyOid;
  return '$name (${policy.policyOid})';
}

String _policyFileName(PdfLpaPolicyInfo policy) {
  final uri = policy.policyUri.trim();
  if (uri.isEmpty) return policy.policyOid;
  final name = uri.split('/').last;
  return name.isEmpty ? policy.policyOid : name;
}

String _formatBool(bool? value) {
  if (value == null) return 'Não informado';
  return value ? 'Sim' : 'Não';
}

String _formatPeriod(DateTime? from, DateTime? to) {
  if (from == null || to == null) return 'Não informado';
  return 'de ${_formatDateTimeBrt(from)} até ${_formatDateTimeBrt(to)}';
}

String? _formatDateTimeBrt(DateTime? dt) {
  if (dt == null) return null;
  final local = dt.toLocal();
  final d = _twoDigits(local.day);
  final m = _twoDigits(local.month);
  final y = local.year.toString();
  final h = _twoDigits(local.hour);
  final min = _twoDigits(local.minute);
  final s = _twoDigits(local.second);
  return '$d/$m/$y $h:$min:$s BRT';
}

String _twoDigits(int value) => value < 10 ? '0$value' : value.toString();

String? _maskCpf(String? cpf) {
  if (cpf == null) return null;
  final digits = cpf.replaceAll(RegExp(r'\D'), '');
  if (digits.length != 11) return cpf;
  final middle = digits.substring(3, 9);
  final part1 = middle.substring(0, 3);
  final part2 = middle.substring(3, 6);
  return '***.$part1.$part2-**';
}

String _bytesToHex(Uint8List bytes) {
  final b = StringBuffer();
  for (final v in bytes) {
    b.write(v.toRadixString(16).padLeft(2, '0'));
  }
  return b.toString();
}
