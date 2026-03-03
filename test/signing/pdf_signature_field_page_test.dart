import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pki.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_fields.dart';
import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  const pdfPath = 'test/assets/pdfs/documento (13).pdf';
  const bksIcp = 'test/assets/truststore/icp_brasil/cadeiasicpbrasil.bks';
  const bksGov = 'test/assets/truststore/gov.br/cadeia_govbr_unica.bks';
  const bksPassword = 'serprosigner';

  Future<List<Uint8List>> loadRootsFromBks() async {
    final loaderIcp = IcpBrasilCertificateLoader(
      bksPath: bksIcp,
      bksPassword: bksPassword,
    );
    final loaderGov = IcpBrasilCertificateLoader(
      bksPath: bksGov,
      bksPassword: bksPassword,
    );

    final icpRoots = await loaderIcp.loadFromBks(tryDecryptKeys: false);
    final govRoots = await loaderGov.loadFromBks(tryDecryptKeys: false);
    return <Uint8List>[...icpRoots, ...govRoots];
  }

  test(
    'reports correct signature fieldName and page for documento (13)',
    () async {
      final required = <String>[pdfPath, bksIcp, bksGov];
      for (final path in required) {
        expect(
          File(path).existsSync(),
          isTrue,
          reason: 'Arquivo obrigatório não encontrado: $path',
        );
      }

      final pdfBytes = Uint8List.fromList(File(pdfPath).readAsBytesSync());
      final trustedRoots = await loadRootsFromBks();

      final report = await PdfSignatureValidator().validateAllSignatures(
        pdfBytes,
        trustedRootsProvider: PdfInMemoryTrustedRootsProvider(trustedRoots),
        includeCertificates: true,
        includeSignatureFields: true,
      );

      expect(report.signatures, isNotEmpty);
      expect(report.signatures.length, 2);
      expect(report.signatures.every((s) => s.intact), isTrue);

      final byFieldName = <String, PdfSignatureInfoReport>{
        for (final sig in report.signatures)
          if ((sig.signatureField?.fieldName ?? '').trim().isNotEmpty)
            sig.signatureField!.fieldName!.trim(): sig,
      };

      expect(byFieldName.containsKey('Signature1'), isTrue);
      expect(byFieldName.containsKey('AssinaturaInterna_2'), isTrue);

      final signature1 = byFieldName['Signature1']!;
      final signature1Page = signature1.signatureField?.pageIndex ?? -1;
      expect(signature1Page, 25);

      expect(signature1.cmsValid, isTrue);
      expect(signature1.digestValid, isTrue);

      final assinaturaInterna2 = byFieldName['AssinaturaInterna_2']!;
      final assinaturaInterna2Page =
          assinaturaInterna2.signatureField?.pageIndex ?? -1;
      expect(assinaturaInterna2Page, 1);
      expect(assinaturaInterna2.cmsValid, isTrue);
      expect(assinaturaInterna2.digestValid, isTrue);
    },
  );

  test('scanner extracts /T as name token and not /Type prefix', () {
    final bytes = Uint8List.fromList(
      '[0 0] obj\n'
              '<< /Type /Annot /FT /Sig /ByteRange [0 10 20 30] /T /AssinaturaInterna_2 /V <<>> >>\n'
              'endobj\n'
          .codeUnits,
    );

    final fields = PdfParserFields.extractSignatureFieldsFromBytes(bytes);
    expect(fields, isNotEmpty);
    expect(fields.first.fieldName, 'AssinaturaInterna_2');
  });
}
