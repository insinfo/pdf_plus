import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

import 'pki_asset_loader.dart';

void main() {
  group('doc_assinado_icp_brasil_thais.pdf', () {
    test('validates ICP-Brasil signature and signer metadata', () async {
      final file = File('test/assets/pdfs/doc_assinado_icp_brasil_thais.pdf');
      expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

      final bytes = file.readAsBytesSync();
      final contents = PdfSignatureValidator.extractAllSignatureContents(bytes);

      expect(contents, hasLength(1));
      expect(
          contents.single.length, _readDerElementTotalLength(contents.single));

      final report = await PdfSignatureValidator().validateAllSignatures(
        bytes,
        trustedRootsProvider: AssetTrustedRootsProvider(
          AssetTrustedRootsProvider.loadDefaultRoots(),
        ),
        includeCertificates: true,
        includeSignatureFields: true,
        fetchCrls: false,
      );

      expect(report.signatures, hasLength(1));
      final signature = report.signatures.single;

      expect(signature.intact, isTrue);
      expect(signature.digestValid, isTrue);
      expect(signature.cmsValid, isTrue);
      expect(signature.chainTrusted, isNot(false));
      expect(signature.certificates?.length, greaterThanOrEqualTo(4));
      expect(
        signature.signerCertificate?.subject,
        contains('THAIS BRAGANCA MELLO COELHO'),
      );
      expect(signature.signerCertificate?.icpBrasilIds?.cpf, '85936480704');
      expect(signature.signatureField?.subFilter, '/adbe.pkcs7.detached');
    });

    test('keeps creator and signing software metadata visible', () {
      final file = File('test/assets/pdfs/doc_assinado_icp_brasil_thais.pdf');
      expect(file.existsSync(), isTrue, reason: 'File not found: ${file.path}');

      final text = latin1.decode(file.readAsBytesSync(), allowInvalid: true);

      expect(text, contains('/Producer'));
      expect(text, contains('Microsoft'));
      expect(text, contains('Word LTSC'));
      expect(text, contains('iTextSharp'));
      expect(text, contains('/Reason(despacho)'));
      expect(text, contains('/Location(PMRO)'));
    });
  });
}

int _readDerElementTotalLength(Uint8List bytes) {
  var cursor = 1;
  if ((bytes[0] & 0x1F) == 0x1F) {
    while (cursor < bytes.length) {
      final b = bytes[cursor++];
      if ((b & 0x80) == 0) break;
    }
  }

  final lenByte = bytes[cursor++];
  if ((lenByte & 0x80) == 0) {
    return cursor + lenByte;
  }

  final lenLen = lenByte & 0x7F;
  var length = 0;
  for (var i = 0; i < lenLen; i++) {
    length = (length << 8) | bytes[cursor++];
  }
  return cursor + length;
}
