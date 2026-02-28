import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

import 'pki_asset_loader.dart';

const _lpaCadesPath = 'test/assets/policy/engine/artifacts/LPA_CAdES.der';

void main() {
  test('PdfValidationApi exposes efficiency and product APIs', () async {
    final file = File('test/assets/pdfs/documento assinado erro.pdf');
    expect(file.existsSync(), isTrue, reason: 'Missing file: ${file.path}');
    final lpaFile = File(_lpaCadesPath);
    expect(lpaFile.existsSync(), isTrue,
        reason: 'Missing LPA file: ${lpaFile.path}');

    final bytes = Uint8List.fromList(file.readAsBytesSync());
    final roots = AssetTrustedRootsProvider.loadDefaultRoots();
    final lpa = PdfLpa.parse(Uint8List.fromList(lpaFile.readAsBytesSync()));
    final api = PdfValidationApi();

    final preflight = await api.preflightSignaturesFast(
      bytes,
      incremental: false,
    );
    expect(preflight.signatures, isNotEmpty);
    expect(preflight.signatures.first.policyOid, isNotNull);
    final aki = preflight.signatures.first.authorityKeyIdentifierHex;
    if (aki != null) {
      expect(aki, isNotEmpty);
      expect(RegExp(r'^[0-9a-fA-F]+$').hasMatch(aki), isTrue);
    }

    final result = await api.validateWithTrustProfiles(
      bytes,
      trustProfiles: [
        PdfTrustProfile(
          id: 'default',
          provider: PdfInMemoryTrustedRootsProvider(roots),
        ),
      ],
      includeCertificates: true,
      includeSignatureFields: true,
      lpa: lpa,
    );

    expect(result.report.signatures, isNotEmpty);
    expect(result.trustResolutionBySignature, isNotEmpty);
    expect(result.revocationEvidence, isNotEmpty);
    expect(result.policyResolver, isNotEmpty);
    final revEvidence = result.revocationEvidence.first.toJson();
    expect(revEvidence['checkedAt'], isNotNull);
    expect(
      revEvidence.keys,
      containsAll(
        [
          'status',
          'source',
          'checkedAt',
          'ocspResponder',
          'crlIssuer',
          'nextUpdate',
          'softFailReason',
        ],
      ),
    );
    expect(result.policyResolver.first.toJson().containsKey('digestMatch'),
        isTrue);
    final docMdpJson = result.docMdpEvaluation.toJson();
    expect(docMdpJson['code'], matches(RegExp(r'^[A-Z0-9_]+$')));
    final docMdpRoundtrip = PdfDocMdpEvaluation.fromJson(docMdpJson);
    expect(docMdpRoundtrip.code, result.docMdpEvaluation.code);

    final summary = api.toUiSummary(result, locale: 'pt_BR');
    expect(summary.signatures, isNotEmpty);
    expect(summary.locale, 'pt_BR');

    final compliance = api.toComplianceReport(
      pdfBytes: bytes,
      result: result,
      format: PdfComplianceReportFormat.json,
      fileName: 'documento assinado erro.pdf',
    );

    expect(compliance.json, isNotNull);
    expect(compliance.json!['file'], isNotNull);
    final complianceText = api.toComplianceReport(
      pdfBytes: bytes,
      result: result,
      format: PdfComplianceReportFormat.itiText,
      fileName: 'documento assinado erro.pdf',
    );
    expect(complianceText.text, isNotNull);
    expect(complianceText.text!.isNotEmpty, isTrue);

    final batch = await api.validateBatch(
      [
        PdfBatchValidationInput(id: 'doc1', pdfBytes: bytes),
      ],
      trustProfiles: [
        PdfTrustProfile(
          id: 'default',
          provider: PdfInMemoryTrustedRootsProvider(roots),
        ),
      ],
      includeCertificates: false,
      includeSignatureFields: true,
    );

    expect(batch.items.length, 1);
    expect(batch.items.first.id, 'doc1');
  });

  test('PdfValidationApi supports incremental preflight and JSON cache hooks',
      () async {
    final file = File('test/assets/pdfs/documento assinado erro.pdf');
    expect(file.existsSync(), isTrue, reason: 'Missing file: ${file.path}');

    final bytes = Uint8List.fromList(file.readAsBytesSync());
    final roots = AssetTrustedRootsProvider.loadDefaultRoots();
    final api = PdfValidationApi();

    final jsonCache = <String, String>{};
    final hooks = PdfValidationCacheHooks(
      getJson: (key) async => jsonCache[key],
      putJson: (key, value, _) async => jsonCache[key] = value,
    );

    final p1 = await api.preflightSignaturesFast(
      bytes,
      cacheHooks: hooks,
      incremental: true,
    );
    expect(p1.signatures, isNotEmpty);
    expect(jsonCache.keys.any((k) => k.startsWith('preflight-fast:')), isTrue);

    final p2 = await api.preflightSignaturesFast(
      bytes,
      cacheHooks: hooks,
      incremental: true,
    );
    expect(p2.signatures.length, p1.signatures.length);

    final v1 = await api.validateWithTrustProfiles(
      bytes,
      trustProfiles: [
        PdfTrustProfile(
          id: 'default',
          provider: PdfInMemoryTrustedRootsProvider(roots),
        ),
      ],
      cacheHooks: hooks,
      includeCertificates: true,
      includeSignatureFields: true,
    );
    expect(v1.report.signatures, isNotEmpty);
    expect(
      jsonCache.keys.any((k) => k.startsWith('validate-with-profiles:')),
      isTrue,
    );

    final v2 = await api.validateWithTrustProfiles(
      bytes,
      trustProfiles: [
        PdfTrustProfile(
          id: 'default',
          provider: PdfInMemoryTrustedRootsProvider(roots),
        ),
      ],
      cacheHooks: hooks,
      includeCertificates: true,
      includeSignatureFields: true,
    );
    expect(v2.report.signatures.length, v1.report.signatures.length);
  });

  test('PdfValidationApi supports object cache hooks', () async {
    final file = File('test/assets/pdfs/documento assinado erro.pdf');
    expect(file.existsSync(), isTrue, reason: 'Missing file: ${file.path}');

    final bytes = Uint8List.fromList(file.readAsBytesSync());
    final api = PdfValidationApi();

    final objectCache = <String, Object>{};
    var putCount = 0;
    final hooks = PdfValidationCacheHooks(
      get: (key) async => objectCache[key],
      put: (key, value, _) async {
        putCount++;
        objectCache[key] = value;
      },
    );

    final first = await api.preflightSignaturesFast(
      bytes,
      cacheHooks: hooks,
      incremental: true,
    );
    final second = await api.preflightSignaturesFast(
      bytes,
      cacheHooks: hooks,
      incremental: true,
    );

    expect(first.signatures, isNotEmpty);
    expect(putCount, 1);
    expect(identical(first, second), isTrue);
  });

  test('evaluateDocMdp covers decision matrix', () {
    final api = PdfValidationApi();
    PdfSignatureInfoReport sig({
      required int index,
      required bool isCertification,
      int? permissionP,
    }) {
      return PdfSignatureInfoReport(
        signatureIndex: index,
        cmsValid: true,
        digestValid: true,
        intact: true,
        docMdp: PdfSignatureDocMdpInfo(
          isCertificationSignature: isCertification,
          permissionP: permissionP,
        ),
        revocation: const PdfSignatureRevocationInfo(revocationUnknown: false),
        validationStatus: PdfSignatureValidationStatus.approved,
      );
    }

    expect(
      api
          .evaluateDocMdp(
            PdfSignatureValidationReport(
              signatures: const <PdfSignatureInfoReport>[],
            ),
          )
          .code,
      PdfDocMdpDecisionCode.noCertification,
    );
    expect(
      api
          .evaluateDocMdp(
            PdfSignatureValidationReport(
              signatures: <PdfSignatureInfoReport>[
                sig(index: 0, isCertification: true, permissionP: 1),
              ],
            ),
          )
          .code,
      PdfDocMdpDecisionCode.p1Blocked,
    );
    expect(
      api
          .evaluateDocMdp(
            PdfSignatureValidationReport(
              signatures: <PdfSignatureInfoReport>[
                sig(index: 0, isCertification: true, permissionP: 2),
              ],
            ),
          )
          .code,
      PdfDocMdpDecisionCode.p2Allowed,
    );
    expect(
      api
          .evaluateDocMdp(
            PdfSignatureValidationReport(
              signatures: <PdfSignatureInfoReport>[
                sig(index: 0, isCertification: true, permissionP: 3),
              ],
            ),
          )
          .code,
      PdfDocMdpDecisionCode.p3Allowed,
    );
    expect(
      api
          .evaluateDocMdp(
            PdfSignatureValidationReport(
              signatures: <PdfSignatureInfoReport>[
                sig(index: 0, isCertification: true),
              ],
            ),
          )
          .code,
      PdfDocMdpDecisionCode.unknown,
    );
  });

  test('PdfDocMdpEvaluation.fromJson accepts legacy camelCase code', () {
    final parsed = PdfDocMdpEvaluation.fromJson(
      <String, dynamic>{
        'canAppendSignature': true,
        'code': 'p2Allowed',
        'reason': 'legacy',
      },
    );
    expect(parsed.code, PdfDocMdpDecisionCode.p2Allowed);
    expect(parsed.canAppendSignature, isTrue);
  });

  test('validateBatch reuses trust profile index between items', () async {
    final file = File('test/assets/pdfs/documento assinado erro.pdf');
    expect(file.existsSync(), isTrue, reason: 'Missing file: ${file.path}');

    final bytes = Uint8List.fromList(file.readAsBytesSync());
    final roots = AssetTrustedRootsProvider.loadDefaultRoots();
    final countingProvider = _CountingTrustedRootsProvider(roots);
    final api = PdfValidationApi();

    final batch = await api.validateBatch(
      [
        PdfBatchValidationInput(id: 'doc1', pdfBytes: bytes),
        PdfBatchValidationInput(id: 'doc2', pdfBytes: bytes),
      ],
      trustProfiles: [
        PdfTrustProfile(
          id: 'default',
          provider: countingProvider,
        ),
      ],
      includeCertificates: false,
      includeSignatureFields: true,
    );

    expect(batch.items.length, 2);
    expect(countingProvider.getTrustedRootsCalls, 1);
  });
}

class _CountingTrustedRootsProvider implements TrustedRootsProvider {
  _CountingTrustedRootsProvider(this._roots);

  final List<Uint8List> _roots;
  int getTrustedRootsCalls = 0;

  @override
  Future<List<Uint8List>> getTrustedRootsDer() async {
    getTrustedRootsCalls++;
    return _roots;
  }
}
