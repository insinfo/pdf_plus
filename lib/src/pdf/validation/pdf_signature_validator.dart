import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:pointycastle/export.dart';

import '../parsing/pdf_document_parser.dart';
import '../parsing/pdf_document_info.dart';

class PdfSignatureValidationResult {
  const PdfSignatureValidationResult({
    required this.signatureIndex,
    required this.cmsValid,
    required this.digestValid,
    required this.intact,
    this.message,
  });

  final int signatureIndex;
  final bool cmsValid;
  final bool digestValid;
  final bool intact;
  final String? message;
}

class PdfSignatureDocMdpInfo {
  const PdfSignatureDocMdpInfo({
    this.isCertificationSignature,
    this.permissionP,
  });

  final bool? isCertificationSignature;
  final int? permissionP;
}

class PdfSignatureRevocationInfo {
  const PdfSignatureRevocationInfo({
    this.crlChecked = false,
    this.crlRevoked = false,
    this.ocspChecked = false,
    this.ocspRevoked = false,
    this.revocationUnknown = true,
  });

  final bool crlChecked;
  final bool crlRevoked;
  final bool ocspChecked;
  final bool ocspRevoked;
  final bool revocationUnknown;
}

class PdfSignatureInfoReport {
  const PdfSignatureInfoReport({
    required this.signatureIndex,
    required this.cmsValid,
    required this.digestValid,
    required this.intact,
    required this.docMdp,
    required this.revocation,
    this.signatureField,
    this.signatureDictionaryPresent,
    this.signingTime,
    this.signaturePolicyOid,
    this.signedAttrsOids,
    this.signedAttrsReport,
    this.certificates,
    this.signerCertificate,
    this.chainTrusted,
    this.chainErrors,
    this.certValid,
    this.message,
  });

  final int signatureIndex;
  final bool cmsValid;
  final bool digestValid;
  final bool intact;
  final PdfSignatureDocMdpInfo docMdp;
  final PdfSignatureRevocationInfo revocation;
  final PdfSignatureFieldInfo? signatureField;
  final bool? signatureDictionaryPresent;
  final DateTime? signingTime;
  final String? signaturePolicyOid;
  final List<String>? signedAttrsOids;
  final PdfSignatureSignedAttrsReport? signedAttrsReport;
  final List<PdfSignatureCertificateInfo>? certificates;
  final PdfSignatureCertificateInfo? signerCertificate;
  final bool? chainTrusted;
  final List<String>? chainErrors;
  final bool? certValid;
  final String? message;
}

class PdfSignatureSignedAttrsReport {
  const PdfSignatureSignedAttrsReport({
    required this.requiredOids,
    required this.optionalOids,
    required this.missingRequiredOids,
    required this.presentOids,
  });

  final List<String> requiredOids;
  final List<String> optionalOids;
  final List<String> missingRequiredOids;
  final List<String> presentOids;
}

class PdfSignatureValidationReport {
  const PdfSignatureValidationReport({required this.signatures});

  final List<PdfSignatureInfoReport> signatures;
}

class PdfSignatureOtherName {
  const PdfSignatureOtherName(this.oid, this.value);

  final String oid;
  final String value;
}

class PdfSignatureCertificateInfo {
  const PdfSignatureCertificateInfo({
    required this.subject,
    required this.issuer,
    required this.serial,
    required this.notBefore,
    required this.notAfter,
    required this.otherNames,
    required this.icpBrasilIds,
  });

  final String? subject;
  final String? issuer;
  final BigInt? serial;
  final DateTime? notBefore;
  final DateTime? notAfter;
  final List<PdfSignatureOtherName> otherNames;
  final PdfSignatureIcpBrasilIds? icpBrasilIds;
}

class PdfSignatureIcpBrasilIds {
  const PdfSignatureIcpBrasilIds({
    this.cpf,
    this.cnpj,
    this.nis,
    this.responsavelCpf,
    this.responsavelNome,
    this.tituloEleitor,
    this.cei,
    this.dateOfBirth,
    this.raw,
  });

  final String? cpf;
  final String? cnpj;
  final String? nis;
  final String? responsavelCpf;
  final String? responsavelNome;
  final String? tituloEleitor;
  final String? cei;
  final DateTime? dateOfBirth;
  final Map<String, String>? raw;

  static PdfSignatureIcpBrasilIds? fromOtherNames(
    List<PdfSignatureOtherName> otherNames,
  ) {
    if (otherNames.isEmpty) return null;
    String? cpf;
    String? cnpj;
    String? nis;
    String? responsavelCpf;
    String? responsavelNome;
    String? tituloEleitor;
    String? cei;
    DateTime? dateOfBirth;
    final raw = <String, String>{};

    for (final entry in otherNames) {
      final oid = entry.oid;
      final value = entry.value;
      raw[oid] = value;
      final digits = _onlyDigits(value);
      switch (oid) {
        case '2.16.76.1.3.1': // CPF
          final parsed = _parseDobCpfFromIcpOtherName(value);
          if (parsed != null) {
            dateOfBirth ??= parsed.dob;
            cpf ??= parsed.cpf;
          } else {
            cpf ??= _extractCpfFromDigits(digits);
          }
          break;
        case '2.16.76.1.3.2': // Nome do responsável (PJ)
          if (value.trim().isNotEmpty) {
            responsavelNome ??= value.trim();
          }
          break;
        case '2.16.76.1.3.3': // CNPJ
          cnpj ??= _extractCnpjFromDigits(digits);
          break;
        case '2.16.76.1.3.4': // CPF responsável
          final parsedResp = _parseDobCpfFromIcpOtherName(value);
          if (parsedResp != null) {
            responsavelCpf ??= parsedResp.cpf;
            dateOfBirth ??= parsedResp.dob;
          } else {
            responsavelCpf ??= _extractCpfFromDigits(digits, allowLast11: true);
          }
          break;
        case '2.16.76.1.3.5': // Título de eleitor
          tituloEleitor ??= digits.isEmpty ? null : digits;
          break;
        case '2.16.76.1.3.6': // CEI
          cei ??= digits.isEmpty ? null : digits;
          break;
        case '2.16.76.1.3.7': // NIS/PIS/PASEP (em alguns layouts)
        case '2.16.76.1.3.8':
          nis ??= _extractNisFromDigits(digits);
          break;
      }
    }

    if (cpf == null &&
        cnpj == null &&
        nis == null &&
        responsavelCpf == null &&
        responsavelNome == null &&
        tituloEleitor == null &&
        cei == null &&
        dateOfBirth == null) {
      return null;
    }
    return PdfSignatureIcpBrasilIds(
      cpf: cpf,
      cnpj: cnpj,
      nis: nis,
      responsavelCpf: responsavelCpf,
      responsavelNome: responsavelNome,
      tituloEleitor: tituloEleitor,
      cei: cei,
      dateOfBirth: dateOfBirth,
      raw: raw.isEmpty ? null : raw,
    );
  }
}

/// Provider de certificados confiáveis.
abstract class TrustedRootsProvider {
  Future<List<Uint8List>> getTrustedRootsDer();
}

abstract class PdfRevocationDataProvider {
  Future<Uint8List?> fetchCrl(Uri url);

  Future<Uint8List?> fetchOcsp(Uri url, Uint8List requestDer);
}

/// Provider de download de certificados (AIA/caIssuers).
abstract class PdfCertificateFetcher {
  Future<Uint8List?> fetchBytes(Uri url);
}

/// Validador básico de assinaturas (PAdES).
class PdfSignatureValidator {
  /// Valida todas as assinaturas do PDF.
  Future<PdfSignatureValidationReport> validateAllSignatures(
    Uint8List pdfBytes, {
    List<String>? trustedRootsPem,
    TrustedRootsProvider? trustedRootsProvider,
    List<TrustedRootsProvider>? trustedRootsProviders,
    bool strictRevocation = false,
    bool fetchCrls = false,
    bool fetchOcsp = false,
    PdfRevocationDataProvider? revocationDataProvider,
    PdfCertificateFetcher? certificateFetcher,
    bool includeCertificates = false,
    bool includeSignatureFields = false,
  }) async {
    final roots = await _collectTrustedRoots(
      trustedRootsPem: trustedRootsPem,
      trustedRootsProvider: trustedRootsProvider,
      trustedRootsProviders: trustedRootsProviders,
    );
    strictRevocation = strictRevocation;
    fetchCrls = fetchCrls;
    fetchOcsp = fetchOcsp;

    final quickInfo = PdfQuickInfo.fromBytes(pdfBytes);
    final permissionP = quickInfo.docMdpPermissionP;

    final signatureFields = includeSignatureFields
        ? PdfDocumentParser(pdfBytes).extractSignatureFields()
        : const <PdfSignatureFieldInfo>[];
    final fieldByRange = <String, PdfSignatureFieldInfo>{};
    for (final field in signatureFields) {
      final range = field.byteRange;
      if (range != null && range.length == 4) {
        fieldByRange[_byteRangeKey(range)] = field;
      }
    }

    final ranges = _findAllByteRanges(pdfBytes);
    final results = <PdfSignatureInfoReport>[];

    for (var i = 0; i < ranges.length; i++) {
      final range = ranges[i];
      final fieldInfo = includeSignatureFields
          ? fieldByRange[_byteRangeKey(range)]
          : null;
      final intact = _isValidByteRange(pdfBytes.length, range);
      var cmsValid = false;
      var digestValid = false;
      bool? certValid;
      var revocation = const PdfSignatureRevocationInfo();
      String? message;
      DateTime? signingTime;
      String? signaturePolicyOid;
      List<String>? signedAttrsOids;
      PdfSignatureSignedAttrsReport? signedAttrsReport;

      if (!intact) {
        results.add(PdfSignatureInfoReport(
          signatureIndex: i,
          cmsValid: false,
          digestValid: false,
          intact: false,
          docMdp: _buildDocMdpInfo(i, permissionP),
          revocation: revocation,
          signatureField: fieldInfo,
          signatureDictionaryPresent: fieldInfo != null,
          signingTime: null,
          signaturePolicyOid: null,
          signedAttrsOids: null,
          signedAttrsReport: null,
          certificates: null,
          signerCertificate: null,
          chainTrusted: null,
          chainErrors: null,
          certValid: null,
          message: 'ByteRange inconsistente.',
        ));
        continue;
      }

      final contents = _extractContentsFromByteRange(pdfBytes, range);
      if (contents == null || contents.isEmpty) {
        results.add(PdfSignatureInfoReport(
          signatureIndex: i,
          cmsValid: false,
          digestValid: false,
          intact: true,
          docMdp: _buildDocMdpInfo(i, permissionP),
          revocation: revocation,
          signatureField: fieldInfo,
          signatureDictionaryPresent: fieldInfo != null,
          signingTime: null,
          signaturePolicyOid: null,
          signedAttrsOids: null,
          signedAttrsReport: null,
          certificates: null,
          signerCertificate: null,
          chainTrusted: null,
          chainErrors: null,
          certValid: null,
          message: 'Conteúdo de assinatura ausente ou inválido.',
        ));
        continue;
      }

        final certInfos =
          includeCertificates ? _extractCertificatesInfo(contents) : null;
      final signerCertInfo =
          includeCertificates ? _extractSignerCertificateInfo(contents) : null;

      cmsValid = _verifyCmsSignature(contents);
      signingTime = _extractSigningTimeFromCms(contents);
      if (signingTime == null && fieldInfo?.signingTimeRaw != null) {
        signingTime = _parsePdfDate(fieldInfo!.signingTimeRaw!);
      }
      if (signingTime == null) {
        final raw = _scanSigningTimeNearByteRange(pdfBytes, range);
        if (raw != null) {
          signingTime = _parsePdfDate(raw);
        }
      }
      signaturePolicyOid = _extractSignaturePolicyOid(contents);
      signedAttrsOids = _extractSignedAttrsOids(contents);
      signedAttrsReport = _buildSignedAttrsReport(signedAttrsOids);
      final digestOid = _extractDigestOid(contents);
      final contentDigest =
          _computeByteRangeDigestForOid(pdfBytes, range, digestOid);
      final messageDigest = _extractMessageDigest(contents);
      if (messageDigest != null) {
        digestValid = _listEquals(contentDigest, messageDigest);
      } else {
        message = 'Atributo messageDigest não encontrado no CMS.';
      }

      _ChainResult? chainResult;
      if (roots.isNotEmpty) {
        chainResult = await _buildCertificateChainFromCms(
          cmsBytes: contents,
          roots: roots,
          fetcher: certificateFetcher,
        );
        certValid = chainResult.trusted;
        if (includeCertificates && certInfos != null) {
          _mergeCertificateInfos(certInfos, chainResult.chain);
        }
      }

      final chainTrusted = certValid;
      final chainErrors = certValid == false
          ? const <String>['Signer certificate not trusted.']
          : null;

      if (revocationDataProvider != null && (fetchCrls || fetchOcsp)) {
        revocation = await _checkRevocation(
          cmsBytes: contents,
          roots: roots,
          fetchCrls: fetchCrls,
          fetchOcsp: fetchOcsp,
          provider: revocationDataProvider,
        );

        if (revocation.crlRevoked || revocation.ocspRevoked) {
          certValid = false;
          message = 'Certificado revogado.';
        } else if (strictRevocation && revocation.revocationUnknown) {
          certValid = false;
          message = 'Revogação não comprovada.';
        }
      }

      results.add(PdfSignatureInfoReport(
        signatureIndex: i,
        cmsValid: cmsValid,
        digestValid: digestValid,
        intact: true,
        docMdp: _buildDocMdpInfo(i, permissionP),
        revocation: revocation,
        signatureField: fieldInfo,
        signatureDictionaryPresent: fieldInfo != null,
        signingTime: signingTime,
        signaturePolicyOid: signaturePolicyOid,
        signedAttrsOids: signedAttrsOids,
        signedAttrsReport: signedAttrsReport,
        certificates: certInfos,
        signerCertificate: signerCertInfo,
        chainTrusted: chainTrusted,
        chainErrors: chainErrors,
        certValid: certValid,
        message: message,
      ));
    }

    return PdfSignatureValidationReport(signatures: results);
  }

  /// API legada: retorna apenas resultados básicos.
  Future<List<PdfSignatureValidationResult>> validateAllSignaturesLegacy(
    Uint8List pdfBytes,
  ) async {
    final report = await validateAllSignatures(pdfBytes);
    return report.signatures
        .map((sig) => PdfSignatureValidationResult(
              signatureIndex: sig.signatureIndex,
              cmsValid: sig.cmsValid,
              digestValid: sig.digestValid,
              intact: sig.intact,
              message: sig.message,
            ))
        .toList();
  }
}

PdfSignatureDocMdpInfo _buildDocMdpInfo(int index, int? permissionP) {
  if (index == 0 && permissionP != null) {
    return PdfSignatureDocMdpInfo(
      isCertificationSignature: true,
      permissionP: permissionP,
    );
  }
  return const PdfSignatureDocMdpInfo(
    isCertificationSignature: false,
    permissionP: null,
  );
}

Future<List<Uint8List>> _collectTrustedRoots({
  List<String>? trustedRootsPem,
  TrustedRootsProvider? trustedRootsProvider,
  List<TrustedRootsProvider>? trustedRootsProviders,
}) async {
  final roots = <Uint8List>[];

  if (trustedRootsPem != null) {
    for (final pem in trustedRootsPem) {
      roots.addAll(_pemBlocksToDer(pem, 'CERTIFICATE'));
    }
  }

  if (trustedRootsProvider != null) {
    roots.addAll(await trustedRootsProvider.getTrustedRootsDer());
  }

  if (trustedRootsProviders != null) {
    for (final provider in trustedRootsProviders) {
      roots.addAll(await provider.getTrustedRootsDer());
    }
  }

  return roots;
}

List<Uint8List> _pemBlocksToDer(String pem, String label) {
  final escaped = RegExp.escape(label);
  final re = RegExp(
    '-----BEGIN $escaped-----([\\s\\S]*?)-----END $escaped-----',
    multiLine: true,
  );
  final matches = re.allMatches(pem);
  final out = <Uint8List>[];
  for (final m in matches) {
    final body = (m.group(1) ?? '').replaceAll(RegExp(r'\s+'), '');
    if (body.isEmpty) continue;
    out.add(Uint8List.fromList(base64.decode(body)));
  }
  return out;
}

void _mergeCertificateInfos(
  List<PdfSignatureCertificateInfo> infos,
  List<Uint8List> chain,
) {
  for (final cert in chain) {
    final info = _parseCertificateInfo(cert);
    if (info == null) continue;
    final exists = infos.any((existing) {
      if (existing.serial != null && info.serial != null) {
        return existing.serial == info.serial &&
            existing.issuer == info.issuer &&
            existing.subject == info.subject;
      }
      return existing.subject == info.subject && existing.issuer == info.issuer;
    });
    if (!exists) {
      infos.add(info);
    }
  }
}

Future<_ChainResult> _buildCertificateChainFromCms({
  required Uint8List cmsBytes,
  required List<Uint8List> roots,
  PdfCertificateFetcher? fetcher,
}) async {
  final parsed = _parseCmsSignerInfoAndCert(cmsBytes);
  if (parsed == null || parsed.certs.isEmpty || parsed.signerInfo == null) {
    return _ChainResult(trusted: false, chain: const <Uint8List>[]);
  }

  final signerId = _parseSignerIdentifier(parsed.signerInfo!);
  final signerCert = _findSignerCert(parsed.certs, signerId);
  if (signerCert == null) {
    return _ChainResult(trusted: false, chain: const <Uint8List>[]);
  }

  final pool = <Uint8List>[...parsed.certs, ...roots];
  final fetched = <Uint8List>[];
  final chain = <Uint8List>[signerCert];

  Uint8List current = signerCert;
  for (int depth = 0; depth < 10; depth++) {
    final tbs = _readTbsCertificate(current);
    if (tbs == null) break;

    if (_nameEquals(tbs.issuer, tbs.subject)) {
      if (_isTrustedAnchor(current, roots)) {
        return _ChainResult(trusted: true, chain: chain);
      }
      final selfKey = _rsaPublicKeyFromCert(current);
      if (selfKey != null && _verifyX509Signature(current, selfKey)) {
        if (_isTrustedAnchor(current, roots)) {
          return _ChainResult(trusted: true, chain: chain);
        }
      }
    }

    for (final root in roots) {
      final rootTbs = _readTbsCertificate(root);
      if (rootTbs == null) continue;
      if (!_nameEquals(tbs.issuer, rootTbs.subject)) continue;
      final rootKey = _rsaPublicKeyFromCert(root);
      if (rootKey == null) continue;
      if (_verifyX509Signature(current, rootKey)) {
        if (!_containsCert(chain, root)) {
          chain.add(root);
        }
        return _ChainResult(trusted: true, chain: chain);
      }
    }

    final authorityKeyId = _readAuthorityKeyIdentifier(current);
    final issuer = _findIssuerInPool(
      pool,
      tbs.issuer,
      exclude: current,
      authorityKeyId: authorityKeyId,
    );
    if (issuer != null) {
      final issuerKey = _rsaPublicKeyFromCert(issuer);
      if (issuerKey != null && _verifyX509Signature(current, issuerKey)) {
        if (!_containsCert(chain, issuer)) {
          chain.add(issuer);
        }
        current = issuer;
        continue;
      }
      if (_isTrustedAnchor(issuer, roots)) {
        if (!_containsCert(chain, issuer)) {
          chain.add(issuer);
        }
        return _ChainResult(trusted: true, chain: chain);
      }
    }

    if (fetcher != null) {
      final aiaUrls = _extractAiaCaIssuersUrls(current);
      var added = false;
      for (final url in aiaUrls) {
        try {
          final bytes = await fetcher.fetchBytes(url);
          if (bytes == null || bytes.isEmpty) continue;
          for (final cert in _extractCertificatesFromBytes(bytes)) {
            if (_containsCert(pool, cert)) continue;
            pool.add(cert);
            fetched.add(cert);
            added = true;
          }
        } catch (_) {}
      }
      if (added) continue;
    }

    break;
  }

  final trusted =
      chain.any((cert) => _isTrustedAnchor(cert, roots)) || _chainHasSelfSigned(chain);
  return _ChainResult(trusted: trusted, chain: chain);
}

bool _chainHasSelfSigned(List<Uint8List> chain) {
  for (final cert in chain) {
    final tbs = _readTbsCertificate(cert);
    if (tbs == null) continue;
    if (_nameEquals(tbs.subject, tbs.issuer)) return true;
  }
  return false;
}

bool _containsCert(List<Uint8List> list, Uint8List cert) {
  for (final existing in list) {
    if (_listEquals(existing, cert)) return true;
  }
  return false;
}

bool _isTrustedAnchor(Uint8List cert, List<Uint8List> roots) {
  if (_containsCert(roots, cert)) return true;
  final tbs = _readTbsCertificate(cert);
  final certSubjectText = _parseCertificateInfo(cert)?.subject;
  for (final root in roots) {
    final rootTbs = _readTbsCertificate(root);
    if (tbs != null && rootTbs != null) {
      if (_nameEquals(tbs.subject, rootTbs.subject)) return true;
    }
    if (certSubjectText != null) {
      final rootSubjectText = _parseCertificateInfo(root)?.subject;
      if (rootSubjectText != null && rootSubjectText == certSubjectText) {
        return true;
      }
    }
  }
  return false;
}

Uint8List? _findIssuerInPool(
  List<Uint8List> pool,
  Uint8List issuerName, {
  Uint8List? exclude,
  Uint8List? authorityKeyId,
}) {
  final issuerNameText = _formatX509NameFromDer(issuerName);
  final issuerNameNormalized = _normalizeX509NameFromDer(issuerName);
  for (final cert in pool) {
    if (exclude != null && _listEquals(cert, exclude)) continue;
    final tbs = _readTbsCertificate(cert);
    if (tbs != null) {
      if (_nameEquals(tbs.subject, issuerName)) return cert;
      if (issuerNameNormalized != null) {
        final subjectNormalized = _normalizeX509NameFromDer(tbs.subject);
        if (subjectNormalized != null && subjectNormalized == issuerNameNormalized) {
          return cert;
        }
      }
      if (authorityKeyId != null) {
        final subjectKeyId = _readSubjectKeyIdentifier(cert);
        if (subjectKeyId != null && _listEquals(subjectKeyId, authorityKeyId)) {
          return cert;
        }
      }
      continue;
    }
    if (issuerNameText != null) {
      final info = _parseCertificateInfo(cert);
      if (info?.subject == issuerNameText) return cert;
    }
  }
  return null;
}

bool _nameEquals(Uint8List a, Uint8List b) {
  if (_listEquals(a, b)) return true;
  final aName = _formatX509NameFromDer(a);
  final bName = _formatX509NameFromDer(b);
  if (aName == null || bName == null) return false;
  if (aName == bName) return true;
  final aNorm = _normalizeX509NameFromDer(a);
  final bNorm = _normalizeX509NameFromDer(b);
  if (aNorm == null || bNorm == null) return false;
  if (aNorm == bNorm) return true;
  return _nameIsSubset(a, b) || _nameIsSubset(b, a);
}

String? _formatX509NameFromDer(Uint8List nameDer) {
  try {
    final obj = ASN1Parser(nameDer).nextObject();
    final seq = obj is ASN1Sequence ? obj : _asAsn1Sequence(obj);
    if (seq == null) return null;
    return _formatX509Name(seq);
  } catch (_) {
    return null;
  }
}

String? _normalizeX509NameFromDer(Uint8List nameDer) {
  try {
    final obj = ASN1Parser(nameDer).nextObject();
    final seq = obj is ASN1Sequence ? obj : _asAsn1Sequence(obj);
    if (seq == null) return null;
    return _normalizeX509Name(seq);
  } catch (_) {
    return null;
  }
}

class _ChainResult {
  const _ChainResult({required this.trusted, required this.chain});

  final bool trusted;
  final List<Uint8List> chain;
}

Uint8List? _extractSignerCertDer(Uint8List cmsBytes) {
  final parsed = _parseCmsSignerInfoAndCert(cmsBytes);
  if (parsed == null || parsed.certs.isEmpty || parsed.signerInfo == null) {
    return null;
  }
  final signerId = _parseSignerIdentifier(parsed.signerInfo!);
  return _findSignerCert(parsed.certs, signerId);
}

List<PdfSignatureCertificateInfo> _extractCertificatesInfo(Uint8List cmsBytes) {
  final parsed = _parseCmsSignerInfoAndCert(cmsBytes);
  if (parsed == null || parsed.certs.isEmpty)
    return const <PdfSignatureCertificateInfo>[];
  final out = <PdfSignatureCertificateInfo>[];
  for (final certDer in parsed.certs) {
    final info = _parseCertificateInfo(certDer);
    if (info != null) out.add(info);
  }
  return out;
}

PdfSignatureCertificateInfo? _extractSignerCertificateInfo(Uint8List cmsBytes) {
  final signerDer = _extractSignerCertDer(cmsBytes);
  if (signerDer == null) return null;
  return _parseCertificateInfo(signerDer);
}

class _TbsInfo {
  _TbsInfo({
    required this.tbsDer,
    required this.issuer,
    required this.subject,
    required this.serial,
  });

  final Uint8List tbsDer;
  final Uint8List issuer;
  final Uint8List subject;
  final BigInt serial;
}

ASN1Sequence? _asAsn1Sequence(ASN1Object obj) {
  if (obj is ASN1Sequence) return obj;
  try {
    final parsed = ASN1Parser(obj.encodedBytes).nextObject();
    if (parsed is ASN1Sequence) return parsed;
  } catch (_) {}
  return null;
}

_TbsInfo? _readTbsCertificate(Uint8List certDer) {
  try {
    final certSeqObj = ASN1Parser(certDer).nextObject();
    final certSeq = certSeqObj is ASN1Sequence ? certSeqObj : null;
    if (certSeq == null || certSeq.elements.isEmpty) return null;
    final tbs = _asAsn1Sequence(certSeq.elements.first);
    if (tbs == null) return null;
    final tbsDer = tbs.encodedBytes;

    int idx = 0;
    if (_readTagNumber(tbs.elements.first) == 0) {
      idx = 1;
    }
    final serial = (tbs.elements[idx] as ASN1Integer).valueAsBigInteger;
    final issuerSeq = _asAsn1Sequence(tbs.elements[idx + 2]);
    final subjectSeq = _asAsn1Sequence(tbs.elements[idx + 4]);
    if (issuerSeq == null || subjectSeq == null) return null;
    final issuer = issuerSeq.encodedBytes;
    final subject = subjectSeq.encodedBytes;
    return _TbsInfo(
      tbsDer: tbsDer,
      issuer: issuer,
      subject: subject,
      serial: serial,
    );
  } catch (_) {
    return null;
  }
}

bool _verifyX509Signature(Uint8List certDer, RSAPublicKey key) {
  try {
    final certSeqObj = ASN1Parser(certDer).nextObject();
    final certSeq = certSeqObj is ASN1Sequence ? certSeqObj : null;
    if (certSeq == null || certSeq.elements.length < 3) return false;
    final tbs = _asAsn1Sequence(certSeq.elements[0]);
    if (tbs == null) return false;
    final sigAlgOid = _readCertSignatureAlgorithmOid(certSeq.elements[1]);
    final digestOid = _signatureOidToDigestOid(sigAlgOid);
    final sigBitString = certSeq.elements[2] as ASN1BitString;

    var sigBytes = sigBitString.valueBytes();
    if (sigBytes.isNotEmpty && sigBytes.first == 0x00) {
      sigBytes = sigBytes.sublist(1);
    }

    final digest = _digestForOid(tbs.encodedBytes, digestOid);
    if (digest == null) return false;
    final digestInfo = _buildDigestInfoForDigest(digest, digestOid);
    if (digestInfo == null) return false;

    final engine = PKCS1Encoding(RSAEngine())
      ..init(false, PublicKeyParameter<RSAPublicKey>(key));
    final decrypted = engine.process(sigBytes);
    return _listEquals(decrypted, digestInfo);
  } catch (_) {
    return false;
  }
}

String? _readCertSignatureAlgorithmOid(ASN1Object obj) {
  final seq = obj is ASN1Sequence ? obj : _asAsn1Sequence(obj);
  if (seq == null || seq.elements.isEmpty) return null;
  final first = seq.elements.first;
  if (first is ASN1ObjectIdentifier) return _oidToString(first);
  return null;
}

String? _signatureOidToDigestOid(String? signatureOid) {
  switch (signatureOid) {
    case '1.2.840.113549.1.1.5':
      return '1.3.14.3.2.26'; // sha1
    case '1.2.840.113549.1.1.11':
      return '2.16.840.1.101.3.4.2.1'; // sha256
    case '1.2.840.113549.1.1.12':
      return '2.16.840.1.101.3.4.2.2'; // sha384
    case '1.2.840.113549.1.1.13':
      return '2.16.840.1.101.3.4.2.3'; // sha512
    default:
      return '2.16.840.1.101.3.4.2.1';
  }
}

Future<PdfSignatureRevocationInfo> _checkRevocation({
  required Uint8List cmsBytes,
  required List<Uint8List> roots,
  required bool fetchCrls,
  required bool fetchOcsp,
  required PdfRevocationDataProvider provider,
}) async {
  final signerCertDer = _extractSignerCertDer(cmsBytes);
  if (signerCertDer == null) {
    return const PdfSignatureRevocationInfo();
  }

  final tbs = _readTbsCertificate(signerCertDer);
  if (tbs == null) {
    return const PdfSignatureRevocationInfo();
  }

  final issuerCert = _findIssuerCert(roots, tbs.issuer);
  final issuerKey =
      issuerCert != null ? _rsaPublicKeyFromCert(issuerCert) : null;

  var crlChecked = false;
  var crlRevoked = false;
  var ocspChecked = false;
  var ocspRevoked = false;
  var ocspUnknown = false;

  if (fetchCrls) {
    final crlUrls = _extractCrlUrls(signerCertDer);
    for (final url in crlUrls) {
      final bytes = await provider.fetchCrl(url);
      if (bytes == null || bytes.isEmpty) continue;
      crlChecked = true;
      if (_isSerialRevokedInCrl(bytes, tbs.serial)) {
        crlRevoked = true;
        break;
      }
    }
  }

  if (fetchOcsp && issuerCert != null && issuerKey != null) {
    final ocspUrls = _extractOcspUrls(signerCertDer);
    final requestDer = _buildOcspRequest(
      signerSerial: tbs.serial,
      issuerCertDer: issuerCert,
    );
    for (final url in ocspUrls) {
      final response = await provider.fetchOcsp(url, requestDer);
      if (response == null || response.isEmpty) continue;
      final status = _parseOcspResponseStatus(response);
      if (status == _OcspCertStatus.unknown) {
        ocspChecked = true;
        ocspUnknown = true;
        continue;
      }
      ocspChecked = true;
      ocspRevoked = status == _OcspCertStatus.revoked;
      if (ocspRevoked || status == _OcspCertStatus.good) break;
    }
  }

  final unknown = !(crlChecked || ocspChecked) || ocspUnknown;

  return PdfSignatureRevocationInfo(
    crlChecked: crlChecked,
    crlRevoked: crlRevoked,
    ocspChecked: ocspChecked,
    ocspRevoked: ocspRevoked,
    revocationUnknown: unknown,
  );
}

Uint8List? _findIssuerCert(List<Uint8List> roots, Uint8List issuerName) {
  for (final root in roots) {
    final tbs = _readTbsCertificate(root);
    if (tbs == null) continue;
    if (_listEquals(tbs.subject, issuerName)) {
      return root;
    }
  }
  return null;
}

List<Uri> _extractCrlUrls(Uint8List certDer) {
  const oidCrlDp = '2.5.29.31';
  final extBytes = _findExtensionValue(certDer, oidCrlDp);
  if (extBytes == null) return <Uri>[];
  try {
    final obj = ASN1Parser(extBytes).nextObject();
    return _extractUrisFromGeneralNames(obj);
  } catch (_) {
    return <Uri>[];
  }
}

List<Uri> _extractOcspUrls(Uint8List certDer) {
  const oidAia = '1.3.6.1.5.5.7.1.1';
  const oidOcsp = '1.3.6.1.5.5.7.48.1';
  final extBytes = _findExtensionValue(certDer, oidAia);
  if (extBytes == null) return <Uri>[];
  try {
    final seq = ASN1Parser(extBytes).nextObject();
    if (seq is! ASN1Sequence) return <Uri>[];
    final urls = <Uri>[];
    for (final el in seq.elements) {
      if (el is! ASN1Sequence || el.elements.length < 2) continue;
      final method = el.elements.first;
      if (method is! ASN1ObjectIdentifier) continue;
      if (_oidToString(method) != oidOcsp) continue;
      final location = el.elements[1];
      urls.addAll(_extractUrisFromGeneralNames(location));
    }
    return urls;
  } catch (_) {
    return <Uri>[];
  }
}

List<Uri> _extractAiaCaIssuersUrls(Uint8List certDer) {
  const oidAia = '1.3.6.1.5.5.7.1.1';
  const oidCaIssuers = '1.3.6.1.5.5.7.48.2';
  final extBytes = _findExtensionValue(certDer, oidAia);
  if (extBytes == null) return <Uri>[];
  try {
    final seq = ASN1Parser(extBytes).nextObject();
    if (seq is! ASN1Sequence) return <Uri>[];
    final urls = <Uri>[];
    for (final el in seq.elements) {
      if (el is! ASN1Sequence || el.elements.length < 2) continue;
      final method = el.elements.first;
      if (method is! ASN1ObjectIdentifier) continue;
      if (_oidToString(method) != oidCaIssuers) continue;
      final location = el.elements[1];
      urls.addAll(_extractUrisFromGeneralNames(location));
    }
    return urls;
  } catch (_) {
    return <Uri>[];
  }
}

Uint8List? _findExtensionValue(Uint8List certDer, String oid) {
  try {
    final certSeqObj = ASN1Parser(certDer).nextObject();
    final certSeq = certSeqObj is ASN1Sequence ? certSeqObj : null;
    if (certSeq == null || certSeq.elements.isEmpty) return null;
    final tbs = _asAsn1Sequence(certSeq.elements.first);
    if (tbs == null) return null;
    for (final el in tbs.elements) {
      if (!_isTagged(el, 3)) continue;
      final extSeqObj = _unwrapTagged(el);
      if (extSeqObj is! ASN1Sequence) continue;
      for (final ext in extSeqObj.elements) {
        if (ext is! ASN1Sequence || ext.elements.isEmpty) continue;
        final oidObj = ext.elements.first;
        if (oidObj is! ASN1ObjectIdentifier) continue;
        if (_oidToString(oidObj) != oid) continue;
        final extValue = ext.elements.last;
        if (extValue is! ASN1OctetString) continue;
        return extValue.valueBytes();
      }
    }
  } catch (_) {
    return null;
  }
  return null;
}

List<Uint8List> _extractCertificatesFromBytes(Uint8List bytes) {
  final out = <Uint8List>[];
  try {
    final text = utf8.decode(bytes, allowMalformed: true);
    if (text.contains('-----BEGIN CERTIFICATE-----')) {
      out.addAll(_pemBlocksToDer(text, 'CERTIFICATE'));
      return out;
    }
  } catch (_) {}

  // PKCS7 / CMS
  try {
    final contentInfo = ASN1Parser(bytes).nextObject();
    if (contentInfo is ASN1Sequence && contentInfo.elements.length >= 2) {
      final signedDataObj = _unwrapTagged(contentInfo.elements[1]);
      if (signedDataObj is ASN1Sequence) {
        ASN1Object? certsTag;
        for (final element in signedDataObj.elements) {
          if (_isTagged(element, 0)) {
            certsTag = element;
            break;
          }
        }
        if (certsTag != null) {
          out.addAll(_parseCmsCertificates(certsTag));
          if (out.isNotEmpty) return out;
        }
      }
    }
  } catch (_) {}

  // Assume raw DER certificate
  out.add(bytes);
  return out;
}

List<Uri> _extractUrisFromGeneralNames(ASN1Object obj) {
  final urls = <Uri>[];
  void walk(ASN1Object node) {
    final tag = _readTagNumber(node);
    if (tag == 6) {
      final bytes = _readTaggedValueBytes(node);
      if (bytes != null) {
        final url = Uri.tryParse(String.fromCharCodes(bytes));
        if (url != null) urls.add(url);
      }
      return;
    }
    if (node is ASN1Sequence || node is ASN1Set) {
      final elements =
          node is ASN1Sequence ? node.elements : (node as ASN1Set).elements;
      for (final el in elements) {
        walk(el);
      }
    }
  }

  walk(obj);
  return urls;
}

bool _isSerialRevokedInCrl(Uint8List crlBytes, BigInt serial) {
  try {
    final seq = ASN1Parser(crlBytes).nextObject();
    if (seq is! ASN1Sequence || seq.elements.isEmpty) return false;
    final tbs = seq.elements.first as ASN1Sequence;

    ASN1Sequence? revoked;
    for (final el in tbs.elements) {
      if (el is ASN1Sequence && el.elements.isNotEmpty) {
        final first = el.elements.first;
        if (first is ASN1Sequence || first is ASN1Integer) {
          if (el.elements.first is ASN1Integer) {
            revoked = el;
            break;
          }
          if (el.elements.first is ASN1Sequence &&
              (el.elements.first as ASN1Sequence).elements.first
                  is ASN1Integer) {
            revoked = el;
            break;
          }
        }
      }
    }
    if (revoked == null) return false;

    for (final entry in revoked.elements) {
      if (entry is! ASN1Sequence || entry.elements.isEmpty) continue;
      final serialObj = entry.elements.first;
      if (serialObj is ASN1Integer) {
        if (serialObj.valueAsBigInteger == serial) return true;
      }
    }
    return false;
  } catch (_) {
    return false;
  }
}

Uint8List _buildOcspRequest({
  required BigInt signerSerial,
  required Uint8List issuerCertDer,
}) {
  final issuerTbs = _readTbsCertificate(issuerCertDer);
  if (issuerTbs == null) {
    return Uint8List(0);
  }

  final issuerNameHash = crypto.sha1.convert(issuerTbs.subject).bytes;
  final issuerKeyHash = _computeIssuerKeyHash(issuerCertDer);

  final certId = ASN1Sequence()
    ..add(ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromComponentString('1.3.14.3.2.26'))
      ..add(ASN1Null()))
    ..add(ASN1OctetString(Uint8List.fromList(issuerNameHash)))
    ..add(ASN1OctetString(issuerKeyHash))
    ..add(ASN1Integer(signerSerial));

  final request = ASN1Sequence()..add(certId);
  final requestList = ASN1Sequence()..add(request);
  final tbsRequest = ASN1Sequence()..add(requestList);
  final ocspRequest = ASN1Sequence()..add(tbsRequest);
  return ocspRequest.encodedBytes;
}

Uint8List _computeIssuerKeyHash(Uint8List issuerCertDer) {
  final key = _rsaPublicKeyFromCert(issuerCertDer);
  if (key == null) return Uint8List(0);
  final rsaSeq = ASN1Sequence()
    ..add(ASN1Integer(key.modulus!))
    ..add(ASN1Integer(key.exponent!));
  return Uint8List.fromList(crypto.sha1.convert(rsaSeq.encodedBytes).bytes);
}

enum _OcspCertStatus { good, revoked, unknown }

_OcspCertStatus _parseOcspResponseStatus(Uint8List ocspBytes) {
  try {
    final resp = ASN1Parser(ocspBytes).nextObject();
    if (resp is! ASN1Sequence || resp.elements.length < 2) {
      return _OcspCertStatus.unknown;
    }
    final responseBytesObj = resp.elements[1];
    final responseBytes = _unwrapTagged(responseBytesObj);
    if (responseBytes is! ASN1Sequence || responseBytes.elements.length < 2) {
      return _OcspCertStatus.unknown;
    }

    final basic = _unwrapTagged(responseBytes.elements[1]);
    if (basic is! ASN1Sequence || basic.elements.isEmpty) {
      return _OcspCertStatus.unknown;
    }
    final tbs = basic.elements.first as ASN1Sequence;
    if (tbs.elements.isEmpty) return _OcspCertStatus.unknown;

    ASN1Sequence? responses;
    for (final el in tbs.elements) {
      if (el is ASN1Sequence && el.elements.isNotEmpty) {
        final first = el.elements.first;
        if (first is ASN1Sequence) {
          responses = el;
        }
      }
    }
    if (responses == null || responses.elements.isEmpty) {
      return _OcspCertStatus.unknown;
    }

    final single = responses.elements.first as ASN1Sequence;
    if (single.elements.length < 2) return _OcspCertStatus.unknown;
    final statusObj = single.elements[1];
    final tag = _readTagNumber(statusObj);
    if (tag == 0) return _OcspCertStatus.good;
    if (tag == 1) return _OcspCertStatus.revoked;
    return _OcspCertStatus.unknown;
  } catch (_) {
    return _OcspCertStatus.unknown;
  }
}

List<List<int>> _findAllByteRanges(Uint8List bytes) {
  const token = <int>[
    0x2F, // /
    0x42, 0x79, 0x74, 0x65, 0x52, 0x61, 0x6E, 0x67, 0x65, // ByteRange
  ];

  final ranges = <List<int>>[];
  var offset = 0;
  while (true) {
    final pos = _indexOfSequence(bytes, token, offset, bytes.length);
    if (pos == -1) break;
    final parsed = _parseByteRangeAt(bytes, pos + token.length);
    if (parsed != null) {
      ranges.add(parsed.range);
      offset = parsed.nextIndex;
    } else {
      offset = pos + token.length;
    }
  }
  return ranges;
}

({List<int> range, int nextIndex})? _parseByteRangeAt(
  Uint8List bytes,
  int start,
) {
  int i = _skipPdfWsAndComments(bytes, start, bytes.length);
  // buscar '['
  while (i < bytes.length && bytes[i] != 0x5B /* [ */) {
    i++;
  }
  if (i >= bytes.length) return null;
  i++;

  final values = <int>[];
  for (int k = 0; k < 4; k++) {
    i = _skipPdfWsAndComments(bytes, i, bytes.length);
    final parsed = _readInt(bytes, i, bytes.length);
    values.add(parsed.value);
    i = parsed.nextIndex;
  }

  return (range: values, nextIndex: i);
}

bool _isValidByteRange(int fileLength, List<int> range) {
  if (range.length != 4) return false;
  final start1 = range[0];
  final len1 = range[1];
  final start2 = range[2];
  final len2 = range[3];
  if (start1 < 0 || len1 < 0 || start2 < 0 || len2 < 0) return false;
  if (start1 + len1 > fileLength) return false;
  if (start2 + len2 > fileLength) return false;
  if (start2 < start1 + len1) return false;
  return true;
}

Uint8List _computeByteRangeDigestForOid(
  Uint8List bytes,
  List<int> range,
  String? digestOid,
) {
  final start1 = range[0];
  final len1 = range[1];
  final start2 = range[2];
  final len2 = range[3];
  final part1 = bytes.sublist(start1, start1 + len1);
  final part2 = bytes.sublist(start2, start2 + len2);
  final data = <int>[...part1, ...part2];
  if (digestOid == '1.3.14.3.2.26') {
    return Uint8List.fromList(crypto.sha1.convert(data).bytes);
  }
  if (digestOid == '2.16.840.1.101.3.4.2.3') {
    return Uint8List.fromList(crypto.sha512.convert(data).bytes);
  }
  return Uint8List.fromList(crypto.sha256.convert(data).bytes);
}

Uint8List? _extractContentsFromByteRange(
  Uint8List bytes,
  List<int> range,
) {
  final gapStart = range[0] + range[1];
  final gapEnd = range[2];
  if (gapStart < 0 || gapEnd <= gapStart || gapEnd > bytes.length) {
    return null;
  }

  int lt = -1;
  for (int i = gapStart; i < gapEnd; i++) {
    if (bytes[i] == 0x3C /* < */) {
      lt = i;
      break;
    }
  }
  if (lt == -1) return null;
  int gt = -1;
  for (int i = lt + 1; i < gapEnd; i++) {
    if (bytes[i] == 0x3E /* > */) {
      gt = i;
      break;
    }
  }
  if (gt == -1 || gt <= lt) return null;

  final hex = bytes.sublist(lt + 1, gt);
  final cleaned = <int>[];
  for (final b in hex) {
    if (b == 0x20 || b == 0x0A || b == 0x0D || b == 0x09) continue;
    cleaned.add(b);
  }
  if (cleaned.length.isOdd) return null;
  final decoded = _hexToBytes(cleaned);
  final trimmed = _trimCmsPadding(decoded);
  return _normalizeBerToDer(trimmed);
}

Uint8List _trimCmsPadding(Uint8List bytes) {
  var start = 0;
  var end = bytes.length;
  while (start < end && bytes[start] == 0x00) {
    start++;
  }
  while (end > start && bytes[end - 1] == 0x00) {
    end--;
  }
  if (start == 0 && end == bytes.length) return bytes;
  return bytes.sublist(start, end);
}

class _NormalizeResult {
  _NormalizeResult(this.bytes, this.nextIndex);
  final Uint8List bytes;
  final int nextIndex;
}

Uint8List _normalizeBerToDer(Uint8List input) {
  try {
    final res = _normalizeElement(input, 0);
    if (res != null && res.nextIndex == input.length) {
      return res.bytes;
    }
  } catch (_) {}
  return input;
}

_NormalizeResult? _normalizeElement(Uint8List input, int offset) {
  if (offset >= input.length) return null;
  if (input[offset] == 0x00 &&
      offset + 1 < input.length &&
      input[offset + 1] == 0x00) {
    return _NormalizeResult(Uint8List(0), offset + 2);
  }

  final tagStart = offset;
  var tagEnd = offset + 1;
  if ((input[offset] & 0x1F) == 0x1F) {
    while (tagEnd < input.length) {
      final b = input[tagEnd];
      tagEnd++;
      if ((b & 0x80) == 0) break;
    }
  }
  if (tagEnd >= input.length) return null;

  final lenStart = tagEnd;
  if (lenStart >= input.length) return null;
  final lenByte = input[lenStart];
  var contentStart = lenStart + 1;
  int length;
  bool indefinite = false;

  if (lenByte == 0x80) {
    indefinite = true;
    length = -1;
  } else if ((lenByte & 0x80) == 0) {
    length = lenByte;
  } else {
    final lenLen = lenByte & 0x7F;
    if (contentStart + lenLen > input.length) return null;
    length = 0;
    for (int i = 0; i < lenLen; i++) {
      length = (length << 8) | input[contentStart + i];
    }
    contentStart += lenLen;
  }

  final tagBytes = input.sublist(tagStart, tagEnd);
  final isConstructed = (tagBytes[0] & 0x20) != 0;

  if (indefinite) {
    final chunks = <int>[];
    var cursor = contentStart;
    while (cursor < input.length) {
      final child = _normalizeElement(input, cursor);
      if (child == null) return null;
      if (child.bytes.isEmpty) {
        cursor = child.nextIndex;
        break;
      }
      chunks.addAll(child.bytes);
      cursor = child.nextIndex;
    }
    final lengthBytes = _encodeLength(chunks.length);
    final out = Uint8List(tagBytes.length + lengthBytes.length + chunks.length);
    var o = 0;
    out.setRange(o, o + tagBytes.length, tagBytes);
    o += tagBytes.length;
    out.setRange(o, o + lengthBytes.length, lengthBytes);
    o += lengthBytes.length;
    out.setRange(o, o + chunks.length, chunks);
    return _NormalizeResult(out, cursor);
  }

  if (contentStart + length > input.length) return null;
  final contentEnd = contentStart + length;
  if (!isConstructed) {
    return _NormalizeResult(
      input.sublist(tagStart, contentEnd),
      contentEnd,
    );
  }

  final chunks = <int>[];
  var cursor = contentStart;
  while (cursor < contentEnd) {
    final child = _normalizeElement(input, cursor);
    if (child == null) return null;
    if (child.bytes.isEmpty) {
      cursor = child.nextIndex;
      break;
    }
    chunks.addAll(child.bytes);
    cursor = child.nextIndex;
  }
  if (chunks.isEmpty) {
    return _NormalizeResult(
      input.sublist(tagStart, contentEnd),
      contentEnd,
    );
  }

  final lengthBytes = _encodeLength(chunks.length);
  final out = Uint8List(tagBytes.length + lengthBytes.length + chunks.length);
  var o = 0;
  out.setRange(o, o + tagBytes.length, tagBytes);
  o += tagBytes.length;
  out.setRange(o, o + lengthBytes.length, lengthBytes);
  o += lengthBytes.length;
  out.setRange(o, o + chunks.length, chunks);
  return _NormalizeResult(out, contentEnd);
}

bool _verifyCmsSignature(Uint8List cmsBytes) {
  try {
    final parsed = _parseCmsSignerInfoAndCert(cmsBytes);
    if (parsed == null || parsed.signerInfo == null || parsed.certs.isEmpty) {
      return false;
    }
    final signerInfo = parsed.signerInfo!;

    final parsedSigner = _parseSignerInfo(signerInfo);
    if (parsedSigner.signature == null ||
        parsedSigner.signedAttrsTagged == null) {
      return false;
    }

    final signedAttrsTagged = parsedSigner.signedAttrsTagged!;
    final signatureBytes = parsedSigner.signature!;
    final digestOid = parsedSigner.digestOid;

    final candidates = _extractSignedAttrsCandidates(signedAttrsTagged);
    final signerSid = _parseSignerIdentifier(signerInfo);
    final primaryCert = _findSignerCert(parsed.certs, signerSid);
    final certsToTry = <Uint8List>[
      if (primaryCert != null) primaryCert,
      ...parsed.certs
          .where((c) => primaryCert == null || !_listEquals(c, primaryCert)),
    ];

    for (final certDer in certsToTry) {
      final publicKey = _rsaPublicKeyFromCert(certDer);
      if (publicKey == null) continue;
      for (final data in candidates) {
        if (_verifyRsaWithDigest(publicKey, data, signatureBytes, digestOid)) {
          return true;
        }
      }

      final engine = PKCS1Encoding(RSAEngine())
        ..init(false, PublicKeyParameter<RSAPublicKey>(publicKey));
      final decrypted = engine.process(signatureBytes);

      for (final data in candidates) {
        final digestInfo = _buildDigestInfoWithDigest(data, digestOid);
        if (digestInfo == null) continue;
        if (_listEquals(decrypted, digestInfo)) {
          return true;
        }
      }
    }

    return false;
  } catch (_) {
    return false;
  }
}

PdfSignatureCertificateInfo? _parseCertificateInfo(Uint8List certDer) {
  try {
    final certSeqObj = ASN1Parser(certDer).nextObject();
    final certSeq = certSeqObj is ASN1Sequence ? certSeqObj : null;
    if (certSeq == null || certSeq.elements.isEmpty) return null;
    final tbs = _asAsn1Sequence(certSeq.elements.first);
    if (tbs == null) return null;

    int idx = 0;
    if (_readTagNumber(tbs.elements.first) == 0) {
      idx = 1;
    }
    final serialObj = tbs.elements[idx] as ASN1Integer;
    final issuerObj = tbs.elements[idx + 2];
    final validityObj = tbs.elements[idx + 3];
    final subjectObj = tbs.elements[idx + 4];

    final issuerSeq = _asAsn1Sequence(issuerObj);
    final subjectSeq = _asAsn1Sequence(subjectObj);
    if (issuerSeq == null || subjectSeq == null) return null;

    DateTime? notBefore;
    DateTime? notAfter;
    final validitySeq = _asAsn1Sequence(validityObj);
    if (validitySeq != null && validitySeq.elements.length >= 2) {
      notBefore = _parseAsn1Time(validitySeq.elements[0]);
      notAfter = _parseAsn1Time(validitySeq.elements[1]);
    }

    final otherNames = _extractOtherNamesFromCert(certDer);
    var icpBrasilIds = PdfSignatureIcpBrasilIds.fromOtherNames(otherNames);
    if (icpBrasilIds != null && icpBrasilIds.cpf == null) {
      final cpfFromSubject = _extractCpfFromSubject(_formatX509Name(subjectSeq));
      if (cpfFromSubject != null) {
        icpBrasilIds = PdfSignatureIcpBrasilIds(
          cpf: cpfFromSubject,
          cnpj: icpBrasilIds.cnpj,
          nis: icpBrasilIds.nis,
          responsavelCpf: icpBrasilIds.responsavelCpf,
          responsavelNome: icpBrasilIds.responsavelNome,
          tituloEleitor: icpBrasilIds.tituloEleitor,
          cei: icpBrasilIds.cei,
          dateOfBirth: icpBrasilIds.dateOfBirth,
          raw: icpBrasilIds.raw,
        );
      }
    }
    if (icpBrasilIds == null) {
      final cpfFromSubject = _extractCpfFromSubject(_formatX509Name(subjectSeq));
      if (cpfFromSubject != null) {
        icpBrasilIds = PdfSignatureIcpBrasilIds(
          cpf: cpfFromSubject,
          cnpj: null,
          nis: null,
          responsavelCpf: null,
          responsavelNome: null,
          tituloEleitor: null,
          cei: null,
          dateOfBirth: null,
          raw: null,
        );
      }
    }

    return PdfSignatureCertificateInfo(
      subject: _formatX509Name(subjectSeq),
      issuer: _formatX509Name(issuerSeq),
      serial: serialObj.valueAsBigInteger,
      notBefore: notBefore,
      notAfter: notAfter,
      otherNames: otherNames,
      icpBrasilIds: icpBrasilIds,
    );
  } catch (_) {
    return null;
  }
}

DateTime? _parseAsn1Time(ASN1Object obj) {
  Uint8List? bytes;
  if (obj is ASN1UtcTime || obj is ASN1GeneralizedTime) {
    bytes = obj.valueBytes();
  } else {
    try {
      final dynamic dyn = obj;
      final b = dyn.valueBytes;
      if (b is Uint8List) bytes = b;
      if (b is List<int>) bytes = Uint8List.fromList(b);
    } catch (_) {}
  }
  if (bytes == null || bytes.isEmpty) return null;
  final text = String.fromCharCodes(bytes).trim();
  if (text.isEmpty) return null;

  // Formats: YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ (optionally with timezone offset)
  try {
    if (text.endsWith('Z')) {
      final t = text.substring(0, text.length - 1);
      if (t.length == 12) {
        final year = int.parse(t.substring(0, 2));
        final fullYear = year >= 50 ? 1900 + year : 2000 + year;
        return DateTime.utc(
          fullYear,
          int.parse(t.substring(2, 4)),
          int.parse(t.substring(4, 6)),
          int.parse(t.substring(6, 8)),
          int.parse(t.substring(8, 10)),
          int.parse(t.substring(10, 12)),
        );
      }
      if (t.length == 14) {
        return DateTime.utc(
          int.parse(t.substring(0, 4)),
          int.parse(t.substring(4, 6)),
          int.parse(t.substring(6, 8)),
          int.parse(t.substring(8, 10)),
          int.parse(t.substring(10, 12)),
          int.parse(t.substring(12, 14)),
        );
      }
    }
    // Fallback: try parse with DateTime.parse if looks like ISO.
    return DateTime.tryParse(text);
  } catch (_) {
    return null;
  }
}

String _formatX509Name(ASN1Sequence nameSeq) {
  final parts = <String>[];
  for (final rdn in nameSeq.elements) {
    if (rdn is! ASN1Set) continue;
    for (final atv in rdn.elements) {
      if (atv is! ASN1Sequence || atv.elements.length < 2) continue;
      final oidObj = atv.elements[0];
      final valObj = atv.elements[1];
      if (oidObj is! ASN1ObjectIdentifier) continue;
      final oid = _oidToString(oidObj) ?? '';
      final key = _oidShortName(oid);
      final val = _asn1ValueToString(valObj).trim();
      if (val.isEmpty) continue;
      parts.add('${key.isEmpty ? oid : key}=$val');
    }
  }
  return parts.join(', ');
}

String _normalizeX509Name(ASN1Sequence nameSeq) {
  final parts = <String>[];
  for (final rdn in nameSeq.elements) {
    if (rdn is! ASN1Set) continue;
    for (final atv in rdn.elements) {
      if (atv is! ASN1Sequence || atv.elements.length < 2) continue;
      final oidObj = atv.elements[0];
      final valObj = atv.elements[1];
      if (oidObj is! ASN1ObjectIdentifier) continue;
      final oid = _oidToString(oidObj) ?? '';
      final key = (_oidShortName(oid).isEmpty ? oid : _oidShortName(oid))
          .toUpperCase();
      final rawVal = _asn1ValueToString(valObj).trim().toLowerCase();
      if (rawVal.isEmpty) continue;
      parts.add('$key=$rawVal');
    }
  }
  parts.sort();
  return parts.join(';');
}

bool _nameIsSubset(Uint8List subjectDer, Uint8List issuerDer) {
  final subjectAttrs = _extractNameAttributesFromDer(subjectDer);
  final issuerAttrs = _extractNameAttributesFromDer(issuerDer);
  if (subjectAttrs == null || issuerAttrs == null) return false;
  for (final entry in issuerAttrs.entries) {
    final subjectValues = subjectAttrs[entry.key];
    if (subjectValues == null || subjectValues.isEmpty) return false;
    final issuerValues = entry.value;
    var matched = false;
    for (final value in issuerValues) {
      if (subjectValues.contains(value)) {
        matched = true;
        break;
      }
    }
    if (!matched) return false;
  }
  return true;
}

Map<String, List<String>>? _extractNameAttributesFromDer(Uint8List nameDer) {
  try {
    final obj = ASN1Parser(nameDer).nextObject();
    final seq = obj is ASN1Sequence ? obj : _asAsn1Sequence(obj);
    if (seq == null) return null;
    return _extractNameAttributes(seq);
  } catch (_) {
    return null;
  }
}

Map<String, List<String>> _extractNameAttributes(ASN1Sequence nameSeq) {
  final map = <String, List<String>>{};
  for (final rdn in nameSeq.elements) {
    if (rdn is! ASN1Set) continue;
    for (final atv in rdn.elements) {
      if (atv is! ASN1Sequence || atv.elements.length < 2) continue;
      final oidObj = atv.elements[0];
      final valObj = atv.elements[1];
      if (oidObj is! ASN1ObjectIdentifier) continue;
      final oid = _oidToString(oidObj) ?? '';
      final value = _asn1ValueToString(valObj).trim().toLowerCase();
      if (oid.isEmpty || value.isEmpty) continue;
      map.putIfAbsent(oid, () => <String>[]).add(value);
    }
  }
  return map;
}

Uint8List? _readSubjectKeyIdentifier(Uint8List certDer) {
  const oidSki = '2.5.29.14';
  final extBytes = _findExtensionValue(certDer, oidSki);
  if (extBytes == null || extBytes.isEmpty) return null;
  try {
    final obj = ASN1Parser(extBytes).nextObject();
    if (obj is ASN1OctetString) return obj.valueBytes();
    final bytes = _readTaggedValueBytes(obj);
    if (bytes != null && bytes.isNotEmpty) return bytes;
  } catch (_) {}
  return null;
}

Uint8List? _readAuthorityKeyIdentifier(Uint8List certDer) {
  const oidAki = '2.5.29.35';
  final extBytes = _findExtensionValue(certDer, oidAki);
  if (extBytes == null || extBytes.isEmpty) return null;
  try {
    final obj = ASN1Parser(extBytes).nextObject();
    final seq = obj is ASN1Sequence ? obj : _asAsn1Sequence(obj);
    if (seq == null) return null;
    for (final el in seq.elements) {
      final tag = _readTagNumber(el);
      if (tag == 0) {
        final unwrapped = _unwrapTagged(el);
        if (unwrapped is ASN1OctetString) return unwrapped.valueBytes();
        if (unwrapped is ASN1Object) {
          final bytes = _readTaggedValueBytes(unwrapped);
          if (bytes != null && bytes.isNotEmpty) return bytes;
        }
      }
    }
  } catch (_) {}
  return null;
}

String _asn1ValueToString(ASN1Object obj) {
  if (obj is ASN1ObjectIdentifier) {
    return _oidToString(obj) ?? '';
  }
  try {
    final bytes = _readTaggedValueBytes(obj);
    if (bytes != null && bytes.isNotEmpty) {
      return String.fromCharCodes(bytes);
    }
  } catch (_) {}
  return obj.toString();
}

String _oidShortName(String oid) {
  switch (oid) {
    case '2.5.4.3':
      return 'CN';
    case '2.5.4.6':
      return 'C';
    case '2.5.4.7':
      return 'L';
    case '2.5.4.8':
      return 'ST';
    case '2.5.4.10':
      return 'O';
    case '2.5.4.11':
      return 'OU';
    case '2.5.4.5':
      return 'SERIALNUMBER';
    case '1.2.840.113549.1.9.1':
      return 'EMAIL';
    default:
      return '';
  }
}

List<PdfSignatureOtherName> _extractOtherNamesFromCert(Uint8List certDer) {
  const oidSan = '2.5.29.17';
  final extBytes = _findExtensionValue(certDer, oidSan);
  if (extBytes == null || extBytes.isEmpty)
    return const <PdfSignatureOtherName>[];

  try {
    final obj = ASN1Parser(extBytes).nextObject();
    final out = <PdfSignatureOtherName>[];

    void walk(ASN1Object node) {
      final tag = _readTagNumber(node);
      if (tag == 0) {
        final otherNameSeq = _coerceSequence(node);
        if (otherNameSeq == null || otherNameSeq.elements.length < 2) return;
        final oidObj = otherNameSeq.elements[0];
        final valueObj = otherNameSeq.elements[1];
        if (oidObj is! ASN1ObjectIdentifier) return;
        final oid = _oidToString(oidObj) ?? '';
        final value = _extractOtherNameValue(valueObj);
        if (oid.isNotEmpty && value != null && value.isNotEmpty) {
          out.add(PdfSignatureOtherName(oid, value));
        }
        return;
      }

      if (node is ASN1Sequence) {
        for (final el in node.elements) {
          walk(el);
        }
      } else if (node is ASN1Set) {
        for (final el in node.elements) {
          walk(el);
        }
      }
    }

    walk(obj);
    return out;
  } catch (_) {
    return const <PdfSignatureOtherName>[];
  }
}

ASN1Sequence? _coerceSequence(dynamic obj) {
  if (obj is ASN1Sequence) return obj;
  if (obj is ASN1Object) {
    final unwrapped = _unwrapTagged(obj);
    if (unwrapped is ASN1Sequence) return unwrapped;
    try {
      if (unwrapped != null) {
        final parsed = ASN1Parser(unwrapped.encodedBytes).nextObject();
        if (parsed is ASN1Sequence) return parsed;
      }
    } catch (_) {}
  }
  return null;
}

String? _extractOtherNameValue(dynamic valueObj) {
  if (valueObj is ASN1Object) {
    if (_readTagNumber(valueObj) != null) {
      final inner = _unwrapTagged(valueObj);
      if (inner != null) return _extractOtherNameValue(inner);
    }
    if (valueObj is ASN1OctetString) {
      final octets = valueObj.valueBytes();
      if (octets.isEmpty) return null;
      try {
        final parsed = ASN1Parser(octets).nextObject();
        final parsedValue = _extractOtherNameValue(parsed);
        if (parsedValue != null && parsedValue.isNotEmpty) return parsedValue;
      } catch (_) {}
      return _bytesToPrintable(octets);
    }
    if (valueObj is ASN1Sequence) {
      for (final item in valueObj.elements) {
        final str = _extractOtherNameValue(item);
        if (str != null && str.isNotEmpty) return str;
      }
    }
    if (valueObj is ASN1ObjectIdentifier) return _oidToString(valueObj);
    final bytes = _readTaggedValueBytes(valueObj);
    if (bytes != null && bytes.isNotEmpty) {
      return String.fromCharCodes(bytes);
    }
  }
  try {
    return valueObj?.toString();
  } catch (_) {
    return null;
  }
}

String _bytesToPrintable(List<int> bytes) {
  final buffer = StringBuffer();
  for (final b in bytes) {
    if (b >= 32 && b <= 126) {
      buffer.writeCharCode(b);
    } else {
      buffer.write('.');
    }
  }
  return buffer.toString();
}

String _onlyDigits(String input) => input.replaceAll(RegExp(r'\D'), '');

({DateTime dob, String cpf})? _parseDobCpfFromIcpOtherName(String raw) {
  final digits = _onlyDigits(raw);
  if (digits.length < 19) return null;
  final dobPart = digits.substring(0, 8);
  final cpfPart = digits.substring(8, 19);
  if (dobPart == '00000000') return null;
  final dob = _tryParseDdMmAaaa(dobPart);
  if (dob == null) return null;
  return (dob: dob, cpf: cpfPart);
}

DateTime? _tryParseDdMmAaaa(String digits) {
  if (digits.length < 8) return null;
  final d = int.tryParse(digits.substring(0, 2));
  final m = int.tryParse(digits.substring(2, 4));
  final y = int.tryParse(digits.substring(4, 8));
  if (d == null || m == null || y == null) return null;
  if (y < 1900 || y > 2100) return null;
  if (m < 1 || m > 12) return null;
  if (d < 1 || d > 31) return null;
  try {
    return DateTime(y, m, d);
  } catch (_) {
    return null;
  }
}

String? _extractCpfFromDigits(String digits, {bool allowLast11 = false}) {
  if (digits.length == 11) return digits;
  if (digits.length >= 19) {
    return digits.substring(8, 19);
  }
  if (allowLast11 && digits.length >= 11) {
    return digits.substring(digits.length - 11);
  }
  return null;
}

String? _extractCnpjFromDigits(String digits) {
  if (digits.length == 14) return digits;
  if (digits.length > 14) return digits.substring(digits.length - 14);
  return null;
}

String? _extractNisFromDigits(String digits) {
  if (digits.length == 11) return digits;
  if (digits.length > 11) return digits.substring(digits.length - 11);
  return null;
}

String? _extractCpfFromSubject(String subject) {
  final m = RegExp(r':(\d{11})').firstMatch(subject);
  if (m != null) return m.group(1);
  final digits = _onlyDigits(subject);
  final fallback = RegExp(r'(\d{11})').firstMatch(digits);
  return fallback?.group(1);
}

List<Uint8List> _extractSignedAttrsCandidates(ASN1Object signedAttrsTagged) {
  final candidates = <Uint8List>[];

  void addCandidate(Uint8List? data) {
    if (data == null || data.isEmpty) return;
    for (final existing in candidates) {
      if (_listEquals(existing, data)) return;
    }
    candidates.add(data);
  }

  if (signedAttrsTagged is ASN1Set) {
    addCandidate(signedAttrsTagged.encodedBytes);
  }

  try {
    final encoded = signedAttrsTagged.encodedBytes;
    addCandidate(encoded);
    if (encoded.isNotEmpty) {
      final normalized = Uint8List.fromList(encoded);
      normalized[0] = 0x31; // SET tag
      addCandidate(normalized);
    }
  } catch (_) {}

  final valueBytes = _readTaggedValueBytes(signedAttrsTagged);
  if (valueBytes != null && valueBytes.isNotEmpty) {
    if (valueBytes[0] == 0x31) {
      addCandidate(valueBytes);
    } else {
      addCandidate(_wrapSet(valueBytes));
    }
  }

  final unwrapped = _unwrapTagged(signedAttrsTagged);
  if (unwrapped != null) {
    try {
      addCandidate(unwrapped.encodedBytes);
    } catch (_) {}
  }

  return candidates;
}

bool _verifyRsaWithDigest(
  RSAPublicKey publicKey,
  Uint8List data,
  Uint8List signature,
  String? digestOid,
) {
  try {
    final algorithm = _digestOidToSigner(digestOid);
    if (algorithm == null) return false;
    final signer = Signer(algorithm)
      ..init(false, PublicKeyParameter<RSAPublicKey>(publicKey));
    return signer.verifySignature(data, RSASignature(signature));
  } catch (_) {
    return false;
  }
}

String? _digestOidToSigner(String? oid) {
  switch (oid) {
    case '1.3.14.3.2.26':
      return 'SHA-1/RSA';
    case '2.16.840.1.101.3.4.2.1':
      return 'SHA-256/RSA';
    case '2.16.840.1.101.3.4.2.3':
      return 'SHA-512/RSA';
    default:
      return 'SHA-256/RSA';
  }
}

Uint8List? _buildDigestInfoWithDigest(Uint8List data, String? oid) {
  final digest = _digestForOid(data, oid);
  if (digest == null) return null;
  switch (oid) {
    case '1.3.14.3.2.26':
      return _buildDigestInfoSha1(digest);
    case '2.16.840.1.101.3.4.2.3':
      return _buildDigestInfoSha512(digest);
    case '2.16.840.1.101.3.4.2.1':
    default:
      return _buildDigestInfoSha256(digest);
  }
}

Uint8List? _digestForOid(Uint8List data, String? oid) {
  if (oid == '1.3.14.3.2.26') {
    final digest = crypto.sha1.convert(data).bytes;
    return Uint8List.fromList(digest);
  }
  if (oid == '2.16.840.1.101.3.4.2.3') {
    final digest = crypto.sha512.convert(data).bytes;
    return Uint8List.fromList(digest);
  }
  final digest = crypto.sha256.convert(data).bytes;
  return Uint8List.fromList(digest);
}

Uint8List _buildDigestInfoSha1(Uint8List digest) {
  final algId = ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromComponentString('1.3.14.3.2.26'))
    ..add(ASN1Null());
  final digestOctet = ASN1OctetString(digest);
  final seq = ASN1Sequence()
    ..add(algId)
    ..add(digestOctet);
  return seq.encodedBytes;
}

Uint8List _buildDigestInfoSha512(Uint8List digest) {
  final algId = ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromComponentString('2.16.840.1.101.3.4.2.3'))
    ..add(ASN1Null());
  final digestOctet = ASN1OctetString(digest);
  final seq = ASN1Sequence()
    ..add(algId)
    ..add(digestOctet);
  return seq.encodedBytes;
}

Uint8List _buildDigestInfoSha384(Uint8List digest) {
  final algId = ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromComponentString('2.16.840.1.101.3.4.2.2'))
    ..add(ASN1Null());
  final digestOctet = ASN1OctetString(digest);
  final seq = ASN1Sequence()
    ..add(algId)
    ..add(digestOctet);
  return seq.encodedBytes;
}

Uint8List? _buildDigestInfoForDigest(Uint8List digest, String? oid) {
  switch (oid) {
    case '1.3.14.3.2.26':
      return _buildDigestInfoSha1(digest);
    case '2.16.840.1.101.3.4.2.2':
      return _buildDigestInfoSha384(digest);
    case '2.16.840.1.101.3.4.2.3':
      return _buildDigestInfoSha512(digest);
    case '2.16.840.1.101.3.4.2.1':
    default:
      return _buildDigestInfoSha256(digest);
  }
}

class _SignerInfoParsed {
  _SignerInfoParsed({
    required this.signedAttrsTagged,
    required this.signature,
    required this.digestOid,
  });

  final ASN1Object? signedAttrsTagged;
  final Uint8List? signature;
  final String? digestOid;
}

class _SignerId {
  _SignerId(this.issuerDer, this.serial);
  final Uint8List issuerDer;
  final BigInt serial;
}

bool _looksLikeSignerInfos(ASN1Set set) {
  if (set.elements.isEmpty) return false;
  for (final el in set.elements) {
    if (el is! ASN1Sequence) continue;
    if (el.elements.length < 5) continue;
    for (final inner in el.elements) {
      if (inner is ASN1OctetString) {
        return true;
      }
    }
  }
  return false;
}

List<Uint8List> _parseCmsCertificates(ASN1Object certsTag) {
  final out = <Uint8List>[];
  ASN1Object? certsObj = _unwrapTagged(certsTag);
  final raw = _readTaggedValueBytes(certsTag);
  if (certsObj is! ASN1Set && certsObj is! ASN1Sequence) {
    if (raw != null && raw.isNotEmpty) {
      try {
        certsObj = ASN1Parser(_wrapSet(raw)).nextObject();
      } catch (_) {}
    }
  }
  void addIfCertificate(ASN1Object el) {
    if (el is ASN1Sequence && el.elements.length >= 3) {
      final tbs = _asAsn1Sequence(el.elements.first);
      final sigVal = el.elements[2];
      if (tbs != null && sigVal is ASN1BitString) {
        out.add(el.encodedBytes);
      }
    }
  }

  if (certsObj is ASN1Sequence && _looksLikeCertificateSeq(certsObj)) {
    if (raw != null && raw.isNotEmpty) {
      try {
        final wrapped = ASN1Parser(_wrapSet(raw)).nextObject();
        if (wrapped is ASN1Set) {
          for (final el in wrapped.elements) {
            addIfCertificate(el);
          }
          return out;
        }
      } catch (_) {}
    }
    addIfCertificate(certsObj);
  } else if (certsObj is ASN1Set) {
    for (final el in certsObj.elements) {
      addIfCertificate(el);
    }
  } else if (certsObj is ASN1Sequence) {
    for (final el in certsObj.elements) {
      addIfCertificate(el);
    }
  }
  return out;
}

bool _looksLikeCertificateSeq(ASN1Sequence seq) {
  if (seq.elements.length < 3) return false;
  final sigVal = seq.elements[2];
  final algo = seq.elements[1];
  return sigVal is ASN1BitString && algo is ASN1Sequence;
}

_SignerId? _parseSignerIdentifier(ASN1Sequence signerInfo) {
  if (signerInfo.elements.length < 2) return null;
  final sid = signerInfo.elements[1];
  if (sid is! ASN1Sequence || sid.elements.length < 2) return null;
  final issuer = sid.elements[0];
  final serialObj = sid.elements[1];
  if (serialObj is! ASN1Integer) return null;
  return _SignerId(issuer.encodedBytes, serialObj.valueAsBigInteger);
}

Uint8List? _findSignerCert(List<Uint8List> certs, _SignerId? signerId) {
  if (certs.isEmpty) return null;
  if (signerId == null) return certs.first;
  for (final certDer in certs) {
    final info = _parseCertIssuerAndSerial(certDer);
    if (info == null) continue;
    if (info.serial == signerId.serial &&
        _listEquals(info.issuerDer, signerId.issuerDer)) {
      return certDer;
    }
  }
  return certs.first;
}

({Uint8List issuerDer, BigInt serial})? _parseCertIssuerAndSerial(
    Uint8List certDer) {
  try {
    final certSeqObj = ASN1Parser(certDer).nextObject();
    final certSeq = certSeqObj is ASN1Sequence ? certSeqObj : null;
    if (certSeq == null || certSeq.elements.isEmpty) return null;
    final tbs = _asAsn1Sequence(certSeq.elements.first);
    if (tbs == null) return null;
    int idx = 0;
    if (tbs.elements.first is! ASN1Integer) {
      idx = 1;
    }
    final serialObj = tbs.elements[idx] as ASN1Integer;
    final issuerObj = tbs.elements[idx + 2];
    final issuerSeq = _asAsn1Sequence(issuerObj);
    if (issuerSeq == null) return null;
    return (
      issuerDer: issuerSeq.encodedBytes,
      serial: serialObj.valueAsBigInteger
    );
  } catch (_) {
    return null;
  }
}

_SignerInfoParsed _parseSignerInfo(ASN1Sequence signerInfo) {
  ASN1Object? signedAttrsTagged;
  Uint8List? signature;
  String? digestOid;

  if (signerInfo.elements.length >= 6) {
    final sa = signerInfo.elements[3];
    if (_isTagged(sa, 0)) {
      signedAttrsTagged = sa;
    }
    final sigEl = signerInfo.elements[5];
    if (sigEl is ASN1OctetString) {
      signature = sigEl.valueBytes();
    }
    final digestAlg = signerInfo.elements[2];
    final digestAlgSeq =
        digestAlg is ASN1Sequence ? digestAlg : _asAsn1Sequence(digestAlg);
    if (digestAlgSeq != null && digestAlgSeq.elements.isNotEmpty) {
      final first = digestAlgSeq.elements.first;
      if (first is ASN1ObjectIdentifier) {
        digestOid = _oidToString(first);
      }
    }
  }

  if (signedAttrsTagged == null || signature == null) {
    for (final el in signerInfo.elements) {
      if (signedAttrsTagged == null && _isTagged(el, 0)) {
        signedAttrsTagged = el;
      }
      if (signature == null && el is ASN1OctetString) {
        signature = el.valueBytes();
      }
      if (digestOid == null) {
        final seq = el is ASN1Sequence ? el : _asAsn1Sequence(el);
        if (seq == null || seq.elements.isEmpty) {
          continue;
        }
        final first = seq.elements.first;
        if (first is ASN1ObjectIdentifier) {
          digestOid = _oidToString(first);
        }
      }
    }
  }

  return _SignerInfoParsed(
    signedAttrsTagged: signedAttrsTagged,
    signature: signature,
    digestOid: digestOid,
  );
}

RSAPublicKey? _rsaPublicKeyFromCert(Uint8List certDer) {
  try {
    final certSeqObj = ASN1Parser(certDer).nextObject();
    final certSeq = certSeqObj is ASN1Sequence ? certSeqObj : null;
    if (certSeq == null || certSeq.elements.isEmpty) return null;
    final tbs = _asAsn1Sequence(certSeq.elements.first);
    if (tbs == null) return null;
    int idx = 0;
    if (_readTagNumber(tbs.elements.first) == 0) {
      idx = 1;
    }
    final spki = tbs.elements[idx + 5] as ASN1Sequence;
    final pubKeyBitString = spki.elements[1] as ASN1BitString;
    var pubBytes = pubKeyBitString.valueBytes();
    if (pubBytes.isNotEmpty && pubBytes.first == 0x00) {
      pubBytes = pubBytes.sublist(1);
    }

    final rsaSeq = ASN1Parser(pubBytes).nextObject() as ASN1Sequence;
    final modulus = (rsaSeq.elements[0] as ASN1Integer).valueAsBigInteger;
    final exponent = (rsaSeq.elements[1] as ASN1Integer).valueAsBigInteger;
    return RSAPublicKey(modulus, exponent);
  } catch (_) {
    return null;
  }
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

Uint8List _wrapSet(Uint8List content) {
  final lengthBytes = _encodeLength(content.length);
  final out = Uint8List(1 + lengthBytes.length + content.length);
  out[0] = 0x31;
  out.setRange(1, 1 + lengthBytes.length, lengthBytes);
  out.setRange(1 + lengthBytes.length, out.length, content);
  return out;
}

Uint8List _encodeLength(int length) {
  if (length < 128) {
    return Uint8List.fromList([length]);
  }
  final bytes = <int>[];
  var n = length;
  while (n > 0) {
    bytes.insert(0, n & 0xFF);
    n >>= 8;
  }
  return Uint8List.fromList([0x80 | bytes.length, ...bytes]);
}

String _byteRangeKey(List<int> range) => range.join(',');

DateTime? _parsePdfDate(String raw) {
  var text = raw.trim();
  if (text.isEmpty) return null;
  if (text.startsWith('D:')) {
    text = text.substring(2);
  }
  final digits = RegExp(r'^\d{4,14}').firstMatch(text)?.group(0) ?? '';
  if (digits.length < 4) return null;
  final year = int.parse(digits.substring(0, 4));
  final month = digits.length >= 6 ? int.parse(digits.substring(4, 6)) : 1;
  final day = digits.length >= 8 ? int.parse(digits.substring(6, 8)) : 1;
  final hour = digits.length >= 10 ? int.parse(digits.substring(8, 10)) : 0;
  final minute = digits.length >= 12 ? int.parse(digits.substring(10, 12)) : 0;
  final second = digits.length >= 14 ? int.parse(digits.substring(12, 14)) : 0;

  var offsetSign = 0;
  var offsetHours = 0;
  var offsetMinutes = 0;
  final tzMatch = RegExp(r'([+\-Z])').firstMatch(text.substring(digits.length));
  if (tzMatch != null) {
    final tz = tzMatch.group(1);
    if (tz == 'Z') {
      offsetSign = 0;
    } else if (tz == '+' || tz == '-') {
      offsetSign = tz == '+' ? 1 : -1;
      final rest = text.substring(digits.length + 1);
      final hh = RegExp(r'\d{2}').firstMatch(rest)?.group(0);
      if (hh != null) offsetHours = int.parse(hh);
      final mm = RegExp(r"'?(\d{2})'?").allMatches(rest).map((m) => m.group(1)).toList();
      if (mm.length > 1 && mm[1] != null) {
        offsetMinutes = int.parse(mm[1]!);
      } else if (mm.isNotEmpty && mm.first != null) {
        offsetMinutes = int.parse(mm.first!);
      }
    }
  }

  final utc = DateTime.utc(year, month, day, hour, minute, second);
  if (offsetSign == 0) return utc;
  final offset = Duration(hours: offsetHours, minutes: offsetMinutes);
  return utc.subtract(offsetSign > 0 ? offset : -offset);
}

String? _scanSigningTimeNearByteRange(Uint8List pdfBytes, List<int> range) {
  if (range.length < 4) return null;
  final gapStart = range[0] + range[1];
  final gapEnd = range[2];
  const windowSize = 524288;
  final windowStart = gapStart - windowSize >= 0 ? gapStart - windowSize : 0;
  final windowEnd = gapEnd + windowSize <= pdfBytes.length
      ? gapEnd + windowSize
      : pdfBytes.length;
  if (windowStart >= windowEnd) return null;
  final window = pdfBytes.sublist(windowStart, windowEnd);
  try {
    final text = latin1.decode(window, allowInvalid: true);
    final match = RegExp(r'/M\s*\(([^)]*)\)').firstMatch(text);
    return match?.group(1);
  } catch (_) {
    return null;
  }
}

ASN1Object? _unwrapTagged(ASN1Object obj) {
  final tag = _readTagNumber(obj);
  if (tag == null) return obj;
  final dynamic dyn = obj;
  try {
    final value = dyn.value;
    if (value is ASN1Object) return value;
  } catch (_) {}

  final bytes = _readTaggedValueBytes(obj);
  if (bytes != null && bytes.isNotEmpty) {
    return ASN1Parser(bytes).nextObject();
  }
  return obj;
}

bool _isTagged(ASN1Object obj, int tag) {
  final t = _readTagNumber(obj);
  return t == tag;
}

Uint8List? _readTaggedValueBytes(ASN1Object obj) {
  final dynamic dyn = obj;
  try {
    final bytes = dyn.valueBytes;
    if (bytes is Uint8List) return bytes;
    if (bytes is List<int>) return Uint8List.fromList(bytes);
    if (bytes is Function) {
      final result = bytes();
      if (result is Uint8List) return result;
      if (result is List<int>) return Uint8List.fromList(result);
    }
  } catch (_) {}
  return null;
}

int? _readTagNumber(ASN1Object obj) {
  final dynamic dyn = obj;
  try {
    final tag = dyn.tag;
    if (tag is int) {
      if (tag >= 0xA0 && tag <= 0xBF) {
        return tag & 0x1F;
      }
      if (tag >= 0x80 && tag <= 0x9F) {
        return tag & 0x1F;
      }
      return tag;
    }
  } catch (_) {}
  return null;
}

String? _oidToString(ASN1ObjectIdentifier oid) {
  final dynamic dyn = oid;
  try {
    final v = dyn.objectIdentifierAsString;
    return v?.toString();
  } catch (_) {}
  try {
    final v = dyn.oidName;
    return v?.toString();
  } catch (_) {}
  try {
    final v = oid.toString();
    const prefix = 'ObjectIdentifier(';
    if (v.startsWith(prefix) && v.endsWith(')')) {
      return v.substring(prefix.length, v.length - 1);
    }
    return v;
  } catch (_) {}
  return null;
}

Uint8List? _extractMessageDigest(Uint8List cmsBytes) {
  final parsed = _parseCmsSignerInfoAndCert(cmsBytes);
  if (parsed == null || parsed.signerInfo == null) {
    return _extractMessageDigestByScan(cmsBytes);
  }
  final signerInfo = parsed.signerInfo!;
  final signedAttrsTagged = _findSignedAttrsTagged(signerInfo);
  if (signedAttrsTagged == null) {
    return _extractMessageDigestByScan(cmsBytes);
  }

  final signedAttrsDer = _extractSignedAttrsDer(signedAttrsTagged);
  if (signedAttrsDer == null || signedAttrsDer.isEmpty) {
    return _extractMessageDigestByScan(cmsBytes);
  }

  try {
    final attrsObj = ASN1Parser(signedAttrsDer).nextObject();
    if (attrsObj is! ASN1Set) return null;
    for (final el in attrsObj.elements) {
      if (el is! ASN1Sequence || el.elements.length < 2) continue;
      final oidObj = el.elements.first;
      if (oidObj is! ASN1ObjectIdentifier) continue;
      if (_oidToString(oidObj) != '1.2.840.113549.1.9.4') continue;
      final valuesObj = el.elements[1];
      if (valuesObj is ASN1Set && valuesObj.elements.isNotEmpty) {
        final v = valuesObj.elements.first;
        if (v is ASN1OctetString) {
          return v.valueBytes();
        }
      }
      if (valuesObj is ASN1OctetString) {
        return valuesObj.valueBytes();
      }
    }
  } catch (_) {}
  return _extractMessageDigestByScan(cmsBytes);
}

DateTime? _extractSigningTimeFromCms(Uint8List cmsBytes) {
  final signedAttrs = _extractSignedAttrsSet(cmsBytes);
  if (signedAttrs == null) return null;
  for (final el in signedAttrs.elements) {
    if (el is! ASN1Sequence || el.elements.length < 2) continue;
    final oidObj = el.elements.first;
    if (oidObj is! ASN1ObjectIdentifier) continue;
    if (_oidToString(oidObj) != '1.2.840.113549.1.9.5') continue;
    final valuesObj = el.elements[1];
    if (valuesObj is ASN1Set && valuesObj.elements.isNotEmpty) {
      return _parseAsn1Time(valuesObj.elements.first);
    }
    return _parseAsn1Time(valuesObj);
  }
  return null;
}

String? _extractSignaturePolicyOid(Uint8List cmsBytes) {
  // id-aa-ets-sigPolicyId = 1.2.840.113549.1.9.16.2.15
  final signedAttrs = _extractSignedAttrsSet(cmsBytes);
  if (signedAttrs == null) return null;
  for (final el in signedAttrs.elements) {
    if (el is! ASN1Sequence || el.elements.length < 2) continue;
    final oidObj = el.elements.first;
    if (oidObj is! ASN1ObjectIdentifier) continue;
    if (_oidToString(oidObj) != '1.2.840.113549.1.9.16.2.15') continue;
    final valuesObj = el.elements[1];
    ASN1Object? policyObj;
    if (valuesObj is ASN1Set && valuesObj.elements.isNotEmpty) {
      policyObj = valuesObj.elements.first;
    } else if (valuesObj is ASN1Sequence) {
      policyObj = valuesObj;
    }
    if (policyObj is ASN1Sequence && policyObj.elements.isNotEmpty) {
      final policyIdObj = policyObj.elements.first;
      if (policyIdObj is ASN1ObjectIdentifier) {
        return _oidToString(policyIdObj);
      }
    }
  }
  return null;
}

List<String>? _extractSignedAttrsOids(Uint8List cmsBytes) {
  final signedAttrs = _extractSignedAttrsSet(cmsBytes);
  if (signedAttrs == null) return null;
  final out = <String>[];
  for (final el in signedAttrs.elements) {
    if (el is! ASN1Sequence || el.elements.isEmpty) continue;
    final oidObj = el.elements.first;
    if (oidObj is ASN1ObjectIdentifier) {
      final oid = _oidToString(oidObj);
      if (oid != null) out.add(oid);
    }
  }
  return out.isEmpty ? null : out;
}

PdfSignatureSignedAttrsReport _buildSignedAttrsReport(
  List<String>? presentOids,
) {
  const requiredOids = <String>[
    '1.2.840.113549.1.9.3', // contentType
    '1.2.840.113549.1.9.4', // messageDigest
  ];
  const optionalOids = <String>[
    '1.2.840.113549.1.9.5', // signingTime
    '1.2.840.113549.1.9.16.2.15', // sigPolicyId (CAdES)
    '1.2.840.113549.1.9.16.2.47', // signingCertificateV2
  ];

  final present = presentOids ?? const <String>[];
  final missingRequired = <String>[];
  for (final oid in requiredOids) {
    if (!present.contains(oid)) missingRequired.add(oid);
  }

  return PdfSignatureSignedAttrsReport(
    requiredOids: requiredOids,
    optionalOids: optionalOids,
    missingRequiredOids: missingRequired,
    presentOids: present,
  );
}

ASN1Set? _extractSignedAttrsSet(Uint8List cmsBytes) {
  final parsed = _parseCmsSignerInfoAndCert(cmsBytes);
  if (parsed == null || parsed.signerInfo == null) return null;
  final signerInfo = parsed.signerInfo!;
  final signedAttrsTagged = _findSignedAttrsTagged(signerInfo);
  if (signedAttrsTagged == null) return null;
  final signedAttrsDer = _extractSignedAttrsDer(signedAttrsTagged);
  if (signedAttrsDer == null || signedAttrsDer.isEmpty) return null;
  try {
    final attrsObj = ASN1Parser(signedAttrsDer).nextObject();
    return attrsObj is ASN1Set ? attrsObj : null;
  } catch (_) {
    return null;
  }
}

Uint8List? _extractMessageDigestByScan(Uint8List cmsBytes) {
  final oid = ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.9.4')
      .encodedBytes;
  final pos = _indexOfSequence(cmsBytes, oid, 0, cmsBytes.length);
  if (pos == -1) return null;

  int i = pos + oid.length;
  while (i < cmsBytes.length && cmsBytes[i] != 0x04) {
    i++;
  }
  if (i >= cmsBytes.length) return null;
  i++;
  if (i >= cmsBytes.length) return null;

  final lenByte = cmsBytes[i++];
  int length = 0;
  if ((lenByte & 0x80) == 0) {
    length = lenByte;
  } else {
    final lenLen = lenByte & 0x7F;
    if (i + lenLen > cmsBytes.length) return null;
    for (int k = 0; k < lenLen; k++) {
      length = (length << 8) | cmsBytes[i++];
    }
  }
  if (i + length > cmsBytes.length) return null;
  return cmsBytes.sublist(i, i + length);
}

String? _extractDigestOid(Uint8List cmsBytes) {
  final parsed = _parseCmsSignerInfoAndCert(cmsBytes);
  if (parsed == null || parsed.signerInfo == null) return null;
  final parsedSigner = _parseSignerInfo(parsed.signerInfo!);
  return parsedSigner.digestOid;
}

ASN1Object? _findSignedAttrsTagged(ASN1Sequence signerInfo) {
  if (signerInfo.elements.length >= 6) {
    final sa = signerInfo.elements[3];
    if (_isTagged(sa, 0)) return sa;
  }
  for (final el in signerInfo.elements) {
    if (_isTagged(el, 0)) return el;
  }
  return null;
}

Uint8List? _extractSignedAttrsDer(ASN1Object signedAttrsTagged) {
  if (signedAttrsTagged is ASN1Set) {
    return signedAttrsTagged.encodedBytes;
  }
  final valueBytes = _readTaggedValueBytes(signedAttrsTagged);
  if (valueBytes != null && valueBytes.isNotEmpty) {
    if (valueBytes[0] == 0x31) return valueBytes;
    return _wrapSet(valueBytes);
  }
  try {
    final encoded = signedAttrsTagged.encodedBytes;
    if (encoded.isNotEmpty) {
      final normalized = Uint8List.fromList(encoded);
      normalized[0] = 0x31;
      return normalized;
    }
  } catch (_) {}
  return null;
}

({ASN1Sequence? signerInfo, List<Uint8List> certs})? _parseCmsSignerInfoAndCert(
  Uint8List cmsBytes,
) {
  try {
    final contentInfo = ASN1Parser(cmsBytes).nextObject();
    if (contentInfo is! ASN1Sequence || contentInfo.elements.length < 2) {
      return null;
    }
    final signedDataObj = _unwrapTagged(contentInfo.elements[1]);
    if (signedDataObj is! ASN1Sequence || signedDataObj.elements.length < 4) {
      return null;
    }

    ASN1Object? certsTag;
    ASN1Set? signerInfos;
    ASN1Set? lastSet;
    for (final element in signedDataObj.elements) {
      if (certsTag == null && _isTagged(element, 0)) {
        certsTag = element;
      }
      if (element is ASN1Set) {
        lastSet = element;
        if (_looksLikeSignerInfos(element)) {
          signerInfos = element;
        }
      }
    }
    signerInfos ??= lastSet;
    if (signerInfos == null || signerInfos.elements.isEmpty) {
      return null;
    }

    final certs =
        certsTag != null ? _parseCmsCertificates(certsTag) : <Uint8List>[];
    final signerInfo = signerInfos.elements.first;
    if (signerInfo is! ASN1Sequence) return null;
    return (signerInfo: signerInfo, certs: certs);
  } catch (_) {
    return null;
  }
}

Uint8List _hexToBytes(List<int> hexBytes) {
  final out = Uint8List(hexBytes.length ~/ 2);
  for (int i = 0; i < hexBytes.length; i += 2) {
    final hi = _hexValue(hexBytes[i]);
    final lo = _hexValue(hexBytes[i + 1]);
    if (hi < 0 || lo < 0) {
      throw FormatException('Hex inválido em /Contents.');
    }
    out[i ~/ 2] = (hi << 4) | lo;
  }
  return out;
}

int _hexValue(int b) {
  if (b >= 0x30 && b <= 0x39) return b - 0x30;
  if (b >= 0x41 && b <= 0x46) return b - 0x41 + 10;
  if (b >= 0x61 && b <= 0x66) return b - 0x61 + 10;
  return -1;
}

int _indexOfSequence(Uint8List bytes, List<int> pattern, int start, int end) {
  if (pattern.isEmpty) return -1;
  final max = end - pattern.length;
  for (int i = start; i <= max; i++) {
    var ok = true;
    for (int j = 0; j < pattern.length; j++) {
      if (bytes[i + j] != pattern[j]) {
        ok = false;
        break;
      }
    }
    if (ok) return i;
  }
  return -1;
}

int _skipPdfWsAndComments(Uint8List bytes, int i, int end) {
  while (i < end) {
    final b = bytes[i];
    if (b == 0x00 ||
        b == 0x09 ||
        b == 0x0A ||
        b == 0x0C ||
        b == 0x0D ||
        b == 0x20) {
      i++;
      continue;
    }
    if (b == 0x25 /* % */) {
      i++;
      while (i < end) {
        final c = bytes[i];
        if (c == 0x0A || c == 0x0D) break;
        i++;
      }
      continue;
    }
    break;
  }
  return i;
}

({int value, int nextIndex}) _readInt(Uint8List bytes, int i, int end) {
  if (i >= end) throw StateError('Fim inesperado ao ler inteiro');
  var neg = false;
  if (bytes[i] == 0x2D /* - */) {
    neg = true;
    i++;
  }
  var value = 0;
  var digits = 0;
  while (i < end) {
    final b = bytes[i];
    if (b < 0x30 || b > 0x39) break;
    value = (value * 10) + (b - 0x30);
    i++;
    digits++;
  }
  if (digits == 0) throw StateError('Inteiro inválido');
  return (value: neg ? -value : value, nextIndex: i);
}

bool _listEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
