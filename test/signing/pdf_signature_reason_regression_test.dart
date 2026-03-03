import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  const pdfPath = 'test/assets/pdfs/documento (13).pdf';

  Uint8List _loadPdfBytes() {
    final file = File(pdfPath);
    expect(file.existsSync(), isTrue,
        reason: 'Arquivo obrigatório não encontrado: $pdfPath');
    return Uint8List.fromList(file.readAsBytesSync());
  }

  test('edit context extracts reason from indirect signature object', () {
    final bytes = _loadPdfBytes();
    final context = PdfDocumentParser(bytes).extractSignatureFieldEditContext();

    final internal = context.fields
        .where((f) => f.info.fieldName == 'AssinaturaInterna_2')
        .toList();
    expect(internal, isNotEmpty);

    final info = internal.first.info;
    expect(info.reason, isNotNull);
    expect(info.reason!.toLowerCase(), contains('sali'));
    expect(info.reason!, contains('assinatura_item_id:8'));
  });

  test('validator keeps distinct reason per signature', () async {
    final bytes = _loadPdfBytes();
    final report = await PdfSignatureValidator().validateAllSignatures(
      bytes,
      includeSignatureFields: true,
      includeCertificates: false,
    );

    expect(report.signatures.length, 2);
    final byField = <String, PdfSignatureInfoReport>{
      for (final sig in report.signatures)
        if ((sig.signatureField?.fieldName ?? '').trim().isNotEmpty)
          sig.signatureField!.fieldName!.trim(): sig,
    };

    final signature1 = byField['Signature1'];
    final assinaturaInterna2 = byField['AssinaturaInterna_2'];

    expect(signature1, isNotNull);
    expect(assinaturaInterna2, isNotNull);

    expect(signature1!.signatureField?.reason, 'Assinador Serpro');
    expect(assinaturaInterna2!.signatureField?.reason, isNotNull);
    expect(assinaturaInterna2.signatureField!.reason!.toLowerCase(),
        contains('sali'));
    expect(assinaturaInterna2.signatureField!.reason,
        isNot(signature1.signatureField?.reason));
  });

  test('prepared context path preserves per-signature reason', () async {
    final bytes = _loadPdfBytes();
    final validator = PdfSignatureValidator(enableInMemoryParseCache: true);

    final prepared = validator.prepareContext(
      bytes,
      includeSignatureFields: true,
      includeSignatureContents: false,
    );

    final report = await validator.validateAllSignatures(
      bytes,
      includeSignatureFields: true,
      includeCertificates: false,
      preparedContext: prepared,
    );

    final byField = <String, PdfSignatureInfoReport>{
      for (final sig in report.signatures)
        if ((sig.signatureField?.fieldName ?? '').trim().isNotEmpty)
          sig.signatureField!.fieldName!.trim(): sig,
    };

    expect(byField['Signature1']?.signatureField?.reason, 'Assinador Serpro');
    final reasonInternal =
        byField['AssinaturaInterna_2']?.signatureField?.reason;
    expect(reasonInternal, isNotNull);
    expect(reasonInternal!.toLowerCase(), contains('sali'));
  });
}
