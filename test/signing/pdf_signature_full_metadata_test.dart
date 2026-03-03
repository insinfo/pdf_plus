import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pki.dart';
import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  const pdfPath = 'test/assets/pdfs/documento (13).pdf';
  const bksIcp = 'test/assets/truststore/icp_brasil/cadeiasicpbrasil.bks';
  const bksGov = 'test/assets/truststore/gov.br/cadeia_govbr_unica.bks';
  const bksPassword = 'serprosigner';
  const lpaPath = 'test/assets/policy/engine/artifacts/LPA_CAdES.der';

  Future<(List<Uint8List>, List<Uint8List>)> _loadBksRoots() async {
    final icpRoots = await IcpBrasilCertificateLoader(
      bksPath: bksIcp,
      bksPassword: bksPassword,
    ).loadFromBks(tryDecryptKeys: false);

    final govRoots = await IcpBrasilCertificateLoader(
      bksPath: bksGov,
      bksPassword: bksPassword,
    ).loadFromBks(tryDecryptKeys: false);

    return (icpRoots, govRoots);
  }

  test('extracts advanced signature metadata from documento (13)', () async {
    for (final path in [pdfPath, bksIcp, bksGov]) {
      expect(
        File(path).existsSync(),
        isTrue,
        reason: 'Arquivo obrigatório não encontrado: $path',
      );
    }

    final bytes = Uint8List.fromList(File(pdfPath).readAsBytesSync());
    final (icpRoots, govRoots) = await _loadBksRoots();
    final allRoots = <Uint8List>[...icpRoots, ...govRoots];

    final report = await PdfSignatureValidator().validateAllSignatures(
      bytes,
      trustedRootsProvider: PdfInMemoryTrustedRootsProvider(allRoots),
      includeCertificates: true,
      includeSignatureFields: true,
    );

    expect(report.signatures.length, 2);
    expect(
        report.signatures.every((s) => s.cmsValid && s.digestValid && s.intact),
        isTrue);

    final byField = <String, PdfSignatureInfoReport>{
      for (final sig in report.signatures)
        if ((sig.signatureField?.fieldName ?? '').isNotEmpty)
          sig.signatureField!.fieldName!: sig,
    };

    final sig1 = byField['Signature1'];
    final sig2 = byField['AssinaturaInterna_2'];
    expect(sig1, isNotNull);
    expect(sig2, isNotNull);

    expect(sig1!.signatureField?.pageIndex, 25);
    expect(sig2!.signatureField?.pageIndex, 1);

    expect(sig1.signerCertificate?.subject, contains('UBIRATAN'));
    expect(sig2.signerCertificate?.subject, contains("Isaque Neves Sant'ana"));
    expect(sig1.signatureField?.reason, 'Assinador Serpro');
    expect(sig2.signatureField?.reason, isNotNull);
    expect(sig2.signatureField!.reason!.toLowerCase(), contains('sali'));

    expect(sig1.signerCertificate, isNotNull);
    expect(sig2.signerCertificate, isNotNull);
    expect(sig1.signerCertificate!.notAfter, isNotNull);
    expect(sig2.signerCertificate!.notAfter, isNotNull);

    expect(sig1.signerCertificate!.serial?.toRadixString(16),
        '7bbf2527e918845fea34f583');
    expect(sig2.signerCertificate!.serial?.toRadixString(16),
        '6823269cf81ad504604a5ba2a91197f0');

    expect(sig1.signaturePolicyOid, '2.16.76.1.7.1.1.2.3');
    expect(sig2.signaturePolicyOid, isNull);

    expect(sig1.signingTime, DateTime.parse('2026-02-20T22:58:20.000Z'));
    expect(sig2.signingTime, DateTime.parse('2026-02-27T21:42:08.000Z'));

    expect(sig1.certificates, isNotNull);
    expect(sig2.certificates, isNotNull);
    expect(sig1.certificates!.length, greaterThanOrEqualTo(2));
    expect(sig2.certificates!.length, greaterThanOrEqualTo(2));

    final lpaFile = File(lpaPath);
    final lpa = lpaFile.existsSync()
        ? PdfLpa.parse(Uint8List.fromList(lpaFile.readAsBytesSync()))
        : null;

    final api = PdfValidationApi();
    final withProfiles = await api.validateWithTrustProfiles(
      bytes,
      trustProfiles: [
        PdfTrustProfile(
          id: 'ICP-Brasil',
          provider: PdfInMemoryTrustedRootsProvider(icpRoots),
        ),
        PdfTrustProfile(
          id: 'gov.br',
          provider: PdfInMemoryTrustedRootsProvider(govRoots),
        ),
      ],
      includeCertificates: true,
      includeSignatureFields: true,
      lpa: lpa,
    );

    expect(withProfiles.trustResolutionBySignature.length, 2);
    expect(withProfiles.revocationEvidence.length, 2);
    expect(withProfiles.policyResolver.length, 2);

    final trustSig1 = withProfiles.trustResolutionBySignature
        .firstWhere((e) => e.signatureIndex == sig1.signatureIndex);
    final trustSig2 = withProfiles.trustResolutionBySignature
        .firstWhere((e) => e.signatureIndex == sig2.signatureIndex);

    expect(trustSig1.winningProfile, 'ICP-Brasil');
    expect(trustSig2.winningProfile, anyOf(isNull, equals('gov.br')));

    final policySig1 = withProfiles.policyResolver
        .firstWhere((e) => e.signatureIndex == sig1.signatureIndex);
    final policySig2 = withProfiles.policyResolver
        .firstWhere((e) => e.signatureIndex == sig2.signatureIndex);

    expect(policySig1.policyOid, '2.16.76.1.7.1.1.2.3');
    expect(policySig1.displayName, contains('PA_AD_RB_v2_3.der'));
    expect(policySig2.policyOid, isNull);

    final revSig1 = withProfiles.revocationEvidence
        .firstWhere((e) => e.signatureIndex == sig1.signatureIndex);
    final revSig2 = withProfiles.revocationEvidence
        .firstWhere((e) => e.signatureIndex == sig2.signatureIndex);

    expect(revSig1.status, anyOf(equals('unknown'), equals('good')));
    expect(revSig2.status, anyOf(equals('unknown'), equals('good')));
    expect(revSig1.source, isNotEmpty);
    expect(revSig2.source, isNotEmpty);
  });
}
