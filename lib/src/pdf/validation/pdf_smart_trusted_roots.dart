import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/src/pdf/crypto/pdf_crypto.dart';
import 'package:pdf_plus/src/pki/x509_certificate.dart';

import 'pdf_signature_validator.dart';

/// Named trusted-roots source used by the smart selector.
class PdfTrustedRootsSource {
  const PdfTrustedRootsSource({
    required this.id,
    required this.provider,
  });

  final String id;
  final TrustedRootsProvider provider;
}

/// In-memory roots provider useful for VM and Web.
class PdfInMemoryTrustedRootsProvider implements TrustedRootsProvider {
  const PdfInMemoryTrustedRootsProvider(this._roots);

  final List<Uint8List> _roots;

  @override
  Future<List<Uint8List>> getTrustedRootsDer() async => _roots;
}

/// Index of trusted roots for fast source selection.
class PdfTrustedRootsIndex {
  PdfTrustedRootsIndex._(this._entries);

  final Map<String, _IndexedRootSource> _entries;

  static Future<PdfTrustedRootsIndex> build(
    List<PdfTrustedRootsSource> sources,
  ) async {
    final entries = <String, _IndexedRootSource>{};
    for (final source in sources) {
      final roots = await source.provider.getTrustedRootsDer();
      final dedupedRoots = _dedupeRoots(roots);
      final subjects = <String>{};
      for (final der in dedupedRoots) {
        try {
          final cert = X509Certificate.fromDer(der);
          final normalized = _normalizeName(cert.subject.toString());
          if (normalized != null) subjects.add(normalized);
        } catch (_) {
          // Ignore malformed roots in index and keep remaining valid ones.
        }
      }
      entries[source.id] = _IndexedRootSource(
        id: source.id,
        roots: dedupedRoots,
        normalizedSubjects: subjects,
      );
    }
    return PdfTrustedRootsIndex._(entries);
  }

  List<String> get sourceIds => _entries.keys.toList(growable: false);

  List<Uint8List> rootsForSource(String sourceId) =>
      List<Uint8List>.from(_entries[sourceId]?.roots ?? const <Uint8List>[]);

  List<Uint8List> allRoots() {
    final merged = <Uint8List>[];
    final seen = <String>{};
    for (final source in _entries.values) {
      for (final der in source.roots) {
        final key = base64Encode(der);
        if (seen.add(key)) merged.add(der);
      }
    }
    return merged;
  }

  Set<String> subjectsForSource(String sourceId) =>
      Set<String>.from(_entries[sourceId]?.normalizedSubjects ?? const <String>{});
}

/// Selection result containing the chosen roots and diagnostics.
class PdfTrustedRootsSelection {
  const PdfTrustedRootsSelection({
    required this.selectedSourceIds,
    required this.roots,
    required this.fallbackToAllSources,
    required this.reason,
  });

  final List<String> selectedSourceIds;
  final List<Uint8List> roots;
  final bool fallbackToAllSources;
  final String reason;

  TrustedRootsProvider get provider => PdfInMemoryTrustedRootsProvider(roots);
}

/// Smart roots selector based on signer issuer names extracted from PDF CMS.
class PdfSmartTrustedRootsSelector {
  PdfSmartTrustedRootsSelector(
    this.index, {
    this.fallbackToAllSources = true,
    this.requireFullIssuerCoverage = true,
  });

  final PdfTrustedRootsIndex index;
  final bool fallbackToAllSources;
  final bool requireFullIssuerCoverage;
  final PdfSignatureExtractor _extractor = PdfSignatureExtractor();
  final Map<String, PdfTrustedRootsSelection> _selectionCache = {};

  Future<PdfTrustedRootsSelection> selectForPdf(Uint8List pdfBytes) async {
    final cacheKey = _sha256Hex(pdfBytes);
    final cached = _selectionCache[cacheKey];
    if (cached != null) return cached;

    final issuerNames = await _extractSignerIssuers(pdfBytes);
    if (issuerNames.isEmpty) {
      final result = _selectAll('No signer issuer found in CMS.');
      _selectionCache[cacheKey] = result;
      return result;
    }

    final unresolved = issuerNames.toSet();
    final selectedIds = <String>[];
    for (final sourceId in index.sourceIds) {
      final subjects = index.subjectsForSource(sourceId);
      if (_matchesAnyIssuer(unresolved, subjects)) {
        selectedIds.add(sourceId);
        unresolved.removeWhere((issuer) => _subjectMatchesIssuer(issuer, subjects));
      }
      if (unresolved.isEmpty) break;
    }

    if (selectedIds.isEmpty) {
      final result = _selectAll('No trusted-root source matched signer issuer.');
      _selectionCache[cacheKey] = result;
      return result;
    }

    if (requireFullIssuerCoverage && unresolved.isNotEmpty) {
      final result = fallbackToAllSources
          ? _selectAll('Partial issuer coverage; using all sources for safety.')
          : _fromSelection(
              selectedIds: selectedIds,
              fallback: false,
              reason: 'Partial issuer coverage without fallback.',
            );
      _selectionCache[cacheKey] = result;
      return result;
    }

    final result = _fromSelection(
      selectedIds: selectedIds,
      fallback: false,
      reason: 'Matched by signer issuer.',
    );
    _selectionCache[cacheKey] = result;
    return result;
  }

  void clearCache() => _selectionCache.clear();

  Future<List<String>> _extractSignerIssuers(Uint8List pdfBytes) async {
    final extraction = await _extractor.extractSignatures(
      pdfBytes,
      includeCertificates: true,
      includeSignatureFields: false,
    );
    final issuers = <String>{};
    for (final sig in extraction.signatures) {
      final normalized = _normalizeName(sig.signerCertificate?.issuer);
      if (normalized != null) issuers.add(normalized);
    }
    return issuers.toList(growable: false);
  }

  PdfTrustedRootsSelection _selectAll(String reason) {
    if (!fallbackToAllSources) {
      return const PdfTrustedRootsSelection(
        selectedSourceIds: <String>[],
        roots: <Uint8List>[],
        fallbackToAllSources: false,
        reason: 'Fallback disabled.',
      );
    }
    return PdfTrustedRootsSelection(
      selectedSourceIds: index.sourceIds,
      roots: index.allRoots(),
      fallbackToAllSources: true,
      reason: reason,
    );
  }

  PdfTrustedRootsSelection _fromSelection({
    required List<String> selectedIds,
    required bool fallback,
    required String reason,
  }) {
    final roots = <Uint8List>[];
    final seen = <String>{};
    for (final sourceId in selectedIds) {
      for (final der in index.rootsForSource(sourceId)) {
        final key = base64Encode(der);
        if (seen.add(key)) roots.add(der);
      }
    }
    return PdfTrustedRootsSelection(
      selectedSourceIds: selectedIds,
      roots: roots,
      fallbackToAllSources: fallback,
      reason: reason,
    );
  }
}

/// Smart validation result including report and root-selection diagnostics.
class PdfSmartSignatureValidationResult {
  const PdfSmartSignatureValidationResult({
    required this.report,
    required this.rootsSelection,
  });

  final PdfSignatureValidationReport report;
  final PdfTrustedRootsSelection rootsSelection;
}

/// Wrapper around [PdfSignatureValidator] with smart trusted-root selection.
class PdfSmartSignatureValidator {
  PdfSmartSignatureValidator({PdfSignatureValidator? validator})
      : _validator = validator ?? PdfSignatureValidator();

  final PdfSignatureValidator _validator;

  Future<PdfSmartSignatureValidationResult> validateAllSignatures(
    Uint8List pdfBytes, {
    required PdfSmartTrustedRootsSelector rootsSelector,
    List<String>? trustedRootsPem,
    List<TrustedRootsProvider>? additionalTrustedRootsProviders,
    bool strictRevocation = false,
    bool fetchCrls = false,
    bool fetchOcsp = false,
    bool validateTemporal = false,
    bool temporalUseSigningTime = false,
    DateTime? validationTime,
    bool temporalExpiredNeedsLtv = true,
    PdfRevocationDataProvider? revocationDataProvider,
    bool includeCertificates = false,
    bool includeSignatureFields = true,
  }) async {
    final selection = await rootsSelector.selectForPdf(pdfBytes);
    final report = await _validator.validateAllSignatures(
      pdfBytes,
      trustedRootsPem: trustedRootsPem,
      trustedRootsProvider: selection.provider,
      trustedRootsProviders: additionalTrustedRootsProviders,
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
    return PdfSmartSignatureValidationResult(
      report: report,
      rootsSelection: selection,
    );
  }
}

class _IndexedRootSource {
  const _IndexedRootSource({
    required this.id,
    required this.roots,
    required this.normalizedSubjects,
  });

  final String id;
  final List<Uint8List> roots;
  final Set<String> normalizedSubjects;
}

List<Uint8List> _dedupeRoots(List<Uint8List> roots) {
  final out = <Uint8List>[];
  final seen = <String>{};
  for (final der in roots) {
    final key = base64Encode(der);
    if (seen.add(key)) out.add(der);
  }
  return out;
}

bool _matchesAnyIssuer(Set<String> issuers, Set<String> subjects) {
  for (final issuer in issuers) {
    if (_subjectMatchesIssuer(issuer, subjects)) return true;
  }
  return false;
}

bool _subjectMatchesIssuer(String issuer, Set<String> subjects) {
  for (final subject in subjects) {
    if (subject == issuer || subject.contains(issuer) || issuer.contains(subject)) {
      return true;
    }
  }
  return false;
}

String? _normalizeName(String? value) {
  if (value == null) return null;
  final normalized = value.toLowerCase().replaceAll(RegExp(r'[^a-z0-9]'), '');
  return normalized.isEmpty ? null : normalized;
}

String _sha256Hex(Uint8List bytes) {
  final digest = PdfCrypto.sha256(bytes);
  final sb = StringBuffer();
  for (final b in digest) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}
