import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  group('/adbe.pkcs7.sha1 legacy signatures', () {
    // Every legacy /adbe.pkcs7.sha1 sample in the corpus. All of them encode the
    // signature WITHOUT signed attributes, so document integrity is verified via
    // the encapsulated SHA-1 (SHA1(ByteRange) == eContent) and the CMS signature
    // is checked directly over that eContent. This locks the common legacy path
    // against regression.
    const samples = <String>[
      'test/assets/pdfs/stf-fachin-1.pdf',
      'test/assets/pdfs/decisao-4874-assinada.pdf',
      'test/assets/pdfs/decisao-STF-prisao-Daniel-Silveira.pdf',
      'test/assets/pdfs/downloadPeca.pdf',
      'test/assets/pdfs/downloadPeca2013.pdf',
    ];

    for (final path in samples) {
      test('validates encapsulated SHA-1 ByteRange digest for ${_name(path)}',
          () async {
        final file = File(path);
        expect(file.existsSync(), isTrue,
            reason: 'File not found: ${file.path}');

        final report = await PdfSignatureValidator().validateAllSignatures(
          file.readAsBytesSync(),
          includeCertificates: false,
          includeSignatureFields: true,
          validateTemporal: false,
        );

        expect(report.signatures, isNotEmpty);
        final signature = report.signatures.first;

        expect(signature.signatureField?.subFilter, '/adbe.pkcs7.sha1');
        // No signed attributes: integrity comes from the encapsulated digest.
        expect(signature.signedAttrsOids ?? const <String>[], isEmpty);
        expect(signature.cmsValid, isTrue);
        expect(signature.digestValid, isTrue);
        expect(signature.intact, isTrue);
      });
    }

    test('detects tampering inside the signed ByteRange (no false "intact")',
        () async {
      final file = File('test/assets/pdfs/stf-fachin-1.pdf');
      final bytes = file.readAsBytesSync();

      // Flip one byte well inside the first signed span (content area, away from
      // the signature dictionary and xref). SHA1(ByteRange) must no longer match
      // the encapsulated eContent, so integrity must be reported as broken.
      final tampered = Uint8List.fromList(bytes);
      tampered[10000] ^= 0xFF;

      final report = await PdfSignatureValidator().validateAllSignatures(
        tampered,
        includeSignatureFields: true,
        validateTemporal: false,
      );

      final signature = report.signatures.single;
      expect(signature.signatureField?.subFilter, '/adbe.pkcs7.sha1');
      expect(signature.digestValid, isFalse);
      expect(signature.validationStatus, PdfSignatureValidationStatus.rejected);
      expect(
        signature.message,
        contains('Resumo criptográfico do ByteRange incompatível'),
      );
    });

    test('separates certificate-expiration diagnostics from integrity',
        () async {
      final file = File('test/assets/pdfs/stf-fachin-1.pdf');
      expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

      final report = await PdfSignatureValidator().validateAllSignatures(
        file.readAsBytesSync(),
        includeCertificates: true,
        includeSignatureFields: true,
        validateTemporal: true,
        validationTime: DateTime.utc(2026, 7, 10, 17, 11, 25),
      );

      expect(report.signatures, hasLength(1));
      final signature = report.signatures.single;

      expect(signature.signatureField?.subFilter, '/adbe.pkcs7.sha1');
      expect(signature.cmsValid, isTrue);
      expect(signature.digestValid, isTrue);
      expect(signature.intact, isTrue);
      // The certificate is expired at validation time: the document is intact,
      // so the outcome is indeterminate, NOT "document modified".
      expect(signature.validationStatus.toString(), contains('indeterminate'));
      expect(
        signature.message,
        contains('Certificado expirado no instante de validação'),
      );
      expect(
        signature.signerCertificate?.subject,
        contains('LUIZ EDSON FACHIN'),
      );
    });
  });

  group('ByteRange coverage', () {
    test('flags a signature that does not reach %%EOF but keeps it inspectable',
        () async {
      // stf-fachin-1.pdf carries a legitimate incremental update after the
      // signed span, so it does NOT cover the whole file — yet it is not
      // tampering. Coverage data must surface this without failing the doc.
      final file = File('test/assets/pdfs/stf-fachin-1.pdf');
      final report = await PdfSignatureValidator().validateAllSignatures(
        file.readAsBytesSync(),
        includeSignatureFields: true,
        validateTemporal: false,
      );
      final coverage = report.signatures.single.byteRangeCoverage;
      expect(coverage, isNotNull);
      expect(coverage!.startsAtDocumentStart, isTrue);
      expect(coverage.unsignedTrailingBytes, greaterThan(0));
      expect(coverage.coversEntireDocument, isFalse);
      // The trailing bytes are a well-formed incremental update, not garbage.
      expect(coverage.trailingBytesAreIncrementalUpdate, isTrue);
    });

    test('reports full end-to-end coverage when the signature reaches %%EOF',
        () async {
      final file = File('test/assets/pdfs/decisao-4874-assinada.pdf');
      final report = await PdfSignatureValidator().validateAllSignatures(
        file.readAsBytesSync(),
        includeSignatureFields: true,
        validateTemporal: false,
      );
      final coverage = report.signatures.first.byteRangeCoverage;
      expect(coverage, isNotNull);
      expect(coverage!.startsAtDocumentStart, isTrue);
      expect(coverage.unsignedTrailingBytes, 0);
      expect(coverage.coversEntireDocument, isTrue);
      expect(coverage.trailingBytesAreIncrementalUpdate, isNull);
    });
  });
}

String _name(String path) => path.split('/').last;
