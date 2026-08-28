import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  group('contrato publico de validacao usado pelo SALI', () {
    test('PDF valido sem assinatura nao gera falso positivo de corrupcao', () {
      final bytes = _readPdf('sample_no_signature.pdf');

      final quick = PdfQuickInfo.fromBytes(bytes);
      final inspection = PdfSecurityInspector().quickInspect(bytes);

      expect(quick.hasPdfHeader, isTrue);
      expect(quick.hasEofMarker, isTrue);
      expect(quick.isEncrypted, isFalse);
      expect(quick.hasSignatures, isFalse);
      expect(inspection.isPdf, isTrue);
      expect(inspection.isSigned, isFalse);
      expect(inspection.isCorrupted, isFalse);
      expect(inspection.signatureCount, 0);
      expect(inspection.issues, isEmpty);
    });

    test('PDF real do SALI preserva deteccao e integridade das assinaturas',
        () async {
      final bytes = _readPdf('documento (13).pdf');

      final quick = PdfQuickInfo.fromBytes(bytes);
      final inspection = PdfSecurityInspector().quickInspect(bytes);
      final report = await PdfSignatureValidator().validateAllSignatures(
        bytes,
        validateTemporal: false,
        includeCertificates: false,
        includeSignatureFields: true,
      );

      expect(quick.hasPdfHeader, isTrue);
      expect(quick.hasEofMarker, isTrue);
      expect(quick.isEncrypted, isFalse);
      expect(quick.hasSignatures, isTrue);
      expect(inspection.isPdf, isTrue);
      expect(inspection.isSigned, isTrue);
      expect(inspection.isCorrupted, isFalse);
      expect(inspection.hasValidByteRanges, isTrue);
      expect(inspection.signatureCount, 2);
      expect(report.signatures, hasLength(2));
      expect(
        report.signatures,
        everyElement(
          isA<PdfSignatureInfoReport>()
              .having((signature) => signature.cmsValid, 'CMS valido', isTrue)
              .having(
                (signature) => signature.digestValid,
                'digest valido',
                isTrue,
              )
              .having(
                (signature) => signature.intact,
                'documento integro',
                isTrue,
              ),
        ),
      );

      final fieldNames = report.signatures
          .map((signature) => signature.signatureField?.fieldName)
          .toSet();
      expect(fieldNames,
          containsAll(<String>{'Signature1', 'AssinaturaInterna_2'}));
    });

    test('ByteRange invalido continua reprovado como documento corrompido',
        () async {
      final bytes = _readPdf('ANDRESSA_assinatura_corrompida.pdf');

      final quick = PdfQuickInfo.fromBytes(bytes);
      final inspection = PdfSecurityInspector().quickInspect(bytes);
      final report = await PdfSignatureValidator().validateAllSignatures(
        bytes,
        validateTemporal: false,
        includeCertificates: false,
        includeSignatureFields: true,
      );

      expect(quick.hasPdfHeader, isTrue);
      expect(quick.hasEofMarker, isTrue);
      expect(quick.hasSignatures, isTrue);
      expect(inspection.isSigned, isTrue);
      expect(inspection.isCorrupted, isTrue);
      expect(inspection.hasValidByteRanges, isFalse);
      expect(
        inspection.issues,
        contains('ByteRange inconsistente com o tamanho do arquivo.'),
      );
      expect(
        report.signatures.where(
          (signature) =>
              signature.cmsValid &&
              signature.digestValid &&
              signature.intact &&
              signature.validationStatus ==
                  PdfSignatureValidationStatus.approved,
        ),
        isEmpty,
      );
    });

    test('PDF truncado continua reprovado sem excecao', () {
      final bytes = _readPdf('itext_2_1_3_truncated.pdf');

      final quick = PdfQuickInfo.fromBytes(bytes);
      final inspection = PdfSecurityInspector().quickInspect(bytes);

      expect(quick.hasPdfHeader, isTrue);
      expect(quick.hasEofMarker, isFalse);
      expect(inspection.isPdf, isTrue);
      expect(inspection.isCorrupted, isTrue);
      expect(inspection.issues, isNotEmpty);
    });
  });
}

Uint8List _readPdf(String fileName) {
  final path = 'test/assets/pdfs/$fileName';
  final file = File(path);
  expect(file.existsSync(), isTrue, reason: 'PDF de regressao ausente: $path');
  return file.readAsBytesSync();
}
