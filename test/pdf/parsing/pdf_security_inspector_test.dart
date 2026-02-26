import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

void main() {
  group('PdfSecurityInspector', () {
    test('detecta PDF normal sem assinatura e sem criptografia', () {
      final bytes = _readAsset('test/assets/pdfs/sample_no_signature.pdf');
      final inspector = PdfSecurityInspector();

      final result = inspector.quickInspect(bytes);

      expect(result.isPdf, isTrue);
      expect(result.isEncrypted, isFalse);
      expect(result.isSigned, isFalse);
      expect(result.isCorrupted, isFalse);
      expect(result.signatureCount, 0);
      expect(result.hasEofMarker, isTrue);
    });

    test('detecta assinatura em PDF assinado', () {
      final bytes =
          _readAsset('test/assets/pdfs/generated_doc_mdp_allow_signatures.pdf');
      final inspector = PdfSecurityInspector();

      final result = inspector.quickInspect(bytes);

      expect(result.isPdf, isTrue);
      expect(result.isSigned, isTrue);
      expect(result.signatureCount, greaterThan(0));
    });

    test('detecta corrupcao em PDF sem EOF', () {
      final bytes = _readAsset('test/assets/pdfs/itext_2_1_3_missing_eof.pdf');
      final inspector = PdfSecurityInspector();

      final result = inspector.quickInspect(bytes);

      expect(result.isPdf, isTrue);
      expect(result.isCorrupted, isTrue);
      expect(result.hasEofMarker, isFalse);
      expect(result.issues, isNotEmpty);
    });

    test('detecta corrupcao em PDF truncado', () {
      final bytes = _readAsset('test/assets/pdfs/itext_2_1_3_truncated.pdf');
      final inspector = PdfSecurityInspector();

      final result = inspector.quickInspect(bytes);

      expect(result.isCorrupted, isTrue);
      expect(result.issues, isNotEmpty);
    });

    test('detecta dicionario /Encrypt no trailer', () {
      final bytes = _buildSyntheticEncryptedPdf();
      final inspector = PdfSecurityInspector();

      final result = inspector.quickInspect(bytes);

      expect(result.isEncrypted, isTrue);
    });

    test('gera hash SHA-256 hexadecimal', () async {
      final bytes = _readAsset('test/assets/pdfs/sample_no_signature.pdf');
      final inspector = PdfSecurityInspector();

      final result = await inspector.inspect(
        bytes,
        includeSha256: true,
      );

      expect(result.sha256Hex, isNotNull);
      expect(result.sha256Hex!.length, 64);
    });

    test('detecta SubFilter suportado', () {
      final bytes = Uint8List.fromList(ascii.encode('''
%PDF-1.7
1 0 obj
<< /Type /Sig /SubFilter /adbe.pkcs7.detached /ByteRange [0 10 20 0] >>
endobj
startxref
1
%%EOF
'''));
      final inspector = PdfSecurityInspector();
      final result = inspector.quickInspect(bytes);
      expect(result.subFilters, isNotEmpty);
      expect(result.supportedSubFilters, isTrue);
    });

    test('marca SubFilter não suportado', () {
      final bytes = Uint8List.fromList(ascii.encode('''
%PDF-1.7
1 0 obj
<< /Type /Sig /SubFilter /adbe.x509.rsa_sha1 /ByteRange [0 10 20 0] >>
endobj
startxref
1
%%EOF
'''));
      final inspector = PdfSecurityInspector();
      final result = inspector.quickInspect(bytes);
      expect(result.supportedSubFilters, isFalse);
      expect(
        result.issues.any((e) => e.contains('SubFilter não suportado')),
        isTrue,
      );
    });

    test('ignora startxref inválido mais ao final e usa ocorrência válida', () {
      final bytes = Uint8List.fromList(ascii.encode('''
%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
startxref
12
%%EOF
startxref
-1157262503
%%EOF
'''));
      final inspector = PdfSecurityInspector();
      final result = inspector.quickInspect(bytes);
      expect(result.startXref, 12);
      expect(result.issues.where((e) => e.contains('startxref')).isEmpty, isTrue);
    });

    test('ativa modo reparo quando startxref ausente e xref existe', () {
      final bytes = Uint8List.fromList(ascii.encode('''
%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
xref
0 2
0000000000 65535 f
0000000010 00000 n
trailer
<< /Size 2 /Root 1 0 R >>
%%EOF
'''));
      final inspector = PdfSecurityInspector();
      final result = inspector.quickInspect(bytes);

      expect(result.startXref, greaterThan(0));
      expect(
        result.issues.any((e) => e.contains('modo reparo')),
        isTrue,
      );
      expect(result.isCorrupted, isTrue);
    });
  });
}

Uint8List _readAsset(String path) => File(path).readAsBytesSync();

Uint8List _buildSyntheticEncryptedPdf() {
  const content = '''
%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
xref
0 2
0000000000 65535 f 
0000000010 00000 n 
trailer
<< /Size 2 /Root 1 0 R /Encrypt 5 0 R >>
startxref
45
%%EOF
''';
  return Uint8List.fromList(ascii.encode(content));
}
