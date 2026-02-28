import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

import 'pki_asset_loader.dart';

const _pdfPath = 'test/assets/pdfs/documento assinado erro.pdf';
const _lpaCadesPath = 'test/assets/policy/engine/artifacts/LPA_CAdES.der';
const _expectedSha256 =
    '2728e47333a1225f135605b4c5b42c89ad1130bc49b682fb8ff5679da5c2e056';

void main() {
  group('documento assinado erro.pdf robust validation APIs', () {
    late Uint8List pdfBytes;
    late PdfSignatureValidationReport validation;

    setUpAll(() async {
      final pdfFile = File(_pdfPath);
      expect(pdfFile.existsSync(), isTrue, reason: 'Missing file: $_pdfPath');

      pdfBytes = Uint8List.fromList(pdfFile.readAsBytesSync());

      final rootsProvider = AssetTrustedRootsProvider(
        AssetTrustedRootsProvider.loadDefaultRoots(),
      );

      validation = await PdfSignatureValidator().validateAllSignatures(
        pdfBytes,
        trustedRootsProvider: rootsProvider,
        includeCertificates: true,
        includeSignatureFields: true,
        fetchCrls: false,
        fetchOcsp: false,
        validateTemporal: true,
        temporalUseSigningTime: true,
      );
    });

    test('validateAllSignatures covers crypto, policy, DocMDP and certificate chain',
        () {
      expect(validation.signatures.length, 1);

      final sig = validation.signatures.first;
      expect(sig.cmsValid, isTrue);
      expect(sig.digestValid, isTrue);
      expect(sig.intact, isTrue);
      expect(sig.validationStatus, PdfSignatureValidationStatus.approved);

      expect(sig.signaturePolicyOid, '2.16.76.1.7.1.1.2.3');
      expect(sig.signingTime, isNotNull);

      expect(sig.docMdp.isCertificationSignature, isTrue);
      expect(sig.docMdp.permissionP, 2);

      expect(sig.signatureDictionaryPresent, isTrue);
      final attrs = sig.signedAttrsReport;
      expect(attrs, isNotNull);
      expect(attrs!.missingRequiredOids, isEmpty);
      expect(attrs.presentOids, contains('1.2.840.113549.1.9.3'));
      expect(attrs.presentOids, contains('1.2.840.113549.1.9.4'));
      expect(attrs.presentOids, contains('1.2.840.113549.1.9.16.2.15'));
      expect(attrs.presentOids, contains('1.2.840.113549.1.9.16.2.47'));

      expect(sig.chainTrusted, isTrue);
      expect(sig.chainErrors, anyOf(isNull, isEmpty));
      expect(sig.certValid, isNot(isFalse));

      final signer = sig.signerCertificate;
      expect(signer, isNotNull);
      expect((signer!.subject ?? '').toLowerCase(), contains('ubiratan'));
      expect(signer.icpBrasilIds?.cpf, '08128478737');

      final certs = sig.certificates ?? const <PdfSignatureCertificateInfo>[];
      expect(certs.length, greaterThanOrEqualTo(2));

      final signingTime = sig.signingTime!;
      for (final cert in certs) {
        if (cert.notBefore == null || cert.notAfter == null) continue;
        final notBefore = cert.notBefore!.toUtc();
        final notAfter = cert.notAfter!.toUtc();
        expect(
          !signingTime.toUtc().isBefore(notBefore),
          isTrue,
          reason: 'Signing time before certificate validity window',
        );
        expect(
          !signingTime.toUtc().isAfter(notAfter),
          isTrue,
          reason: 'Signing time after certificate validity window',
        );
      }

      expect(sig.revocation.revocationUnknown, isTrue);
      expect(sig.revocation.ocspChecked, isFalse);
      expect(sig.revocation.crlChecked, isFalse);
    });

    test('extractSignatures and inspect expose consistent signature metadata',
        () async {
      final extraction = await PdfSignatureExtractor().extractSignatures(
        pdfBytes,
        includeCertificates: true,
        includeSignatureFields: true,
      );

      expect(extraction.signatures.length, 1);
      final extracted = extraction.signatures.first;
      expect(extracted.contentsPresent, isTrue);
      expect(extracted.signaturePolicyOid, '2.16.76.1.7.1.1.2.3');
      expect(extracted.signingTime, isNotNull);
      expect(extracted.signerCertificate, isNotNull);

      final rootsProvider = AssetTrustedRootsProvider(
        AssetTrustedRootsProvider.loadDefaultRoots(),
      );
      final inspection = await PdfSignatureInspector().inspect(
        pdfBytes,
        trustedRootsProvider: rootsProvider,
        includeCertificates: true,
        includeSignatureFields: true,
      );

      expect(inspection.signatures.length, 1);
      expect(inspection.allDocumentsIntact, isTrue);

      final summary = inspection.signatures.first;
      expect(summary.cmsSignatureValid, isTrue);
      expect(summary.byteRangeDigestOk, isTrue);
      expect(summary.documentIntact, isTrue);
      expect(summary.policyPresent, isTrue);
      expect(summary.docMdp?.permissionP, 2);
      expect((summary.signer?.subject ?? '').toLowerCase(), contains('ubiratan'));
    });

    test('ITI compliance report mirrors expected offline validation fields', () {
      final lpaFile = File(_lpaCadesPath);
      expect(lpaFile.existsSync(), isTrue, reason: 'Missing LPA file: $_lpaCadesPath');

      final lpa = PdfLpa.parse(Uint8List.fromList(lpaFile.readAsBytesSync()));

      final iti = PdfItiComplianceReport.fromValidation(
        pdfBytes: pdfBytes,
        validationReport: validation,
        metadata: PdfItiComplianceMetadata(
          name: 'Validar',
          verifierVersion: '2.21.1.2',
          validatorVersion: '3.0.5.2',
          verificationSource: 'Offline',
        ),
        fileName: 'documento assinado erro.pdf',
        lpa: lpa,
        lpaName: 'LPA CAdES v2',
        lpaOnline: true,
        paOnline: false,
      );

      expect(iti.fileHashSha256, _expectedSha256);
      expect(iti.signatureCount, 1);
      expect(iti.anchoredSignatureCount, 1);
      expect(iti.policyInfo?.paValidInLpa, isTrue);
      expect(iti.policyInfo?.paOnline, isFalse);
      expect(iti.lpaInfo?.lpaName, 'LPA CAdES v2');
      expect(iti.lpaInfo?.lpaOnline, isTrue);

      final sig = iti.signatures.single;
      expect(sig.signatureStatus, 'Aprovado');
      expect(sig.certPathStatus, 'Valid');
      expect(sig.signatureType, 'Destacada');
      expect(sig.incrementalCheck, contains('DocMDP - Com permissão 2'));
      expect(sig.message, 'Nenhuma mensagem de alerta');
      expect(sig.signaturePolicy.toLowerCase(), contains('pa_ad_rb_v2_3'));

      final requiredAttrNames = sig.requiredAttributes.map((a) => a.name).toSet();
      expect(requiredAttrNames, contains('IdMessageDigest'));
      expect(requiredAttrNames, contains('IdContentType'));
      expect(requiredAttrNames, contains('SignatureDictionary'));

      final text = iti.toText();
      expect(text, contains('Relatório de Conformidade'));
      expect(text, contains('Nome do arquivo: documento assinado erro.pdf'));
      expect(text, contains('Quantidade de assinaturas: 1'));
      expect(text, contains('OID da PA: PA_AD_RB_v2_3.der (2.16.76.1.7.1.1.2.3)'));
      expect(text, contains('LPA online: Sim'));
    });
  });
}
