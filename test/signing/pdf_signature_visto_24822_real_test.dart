import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

import 'pki_asset_loader.dart';

void main() {
  test('validates VISTO 24822 ICP-Brasil signature', () async {
    final pdfFile =
        Directory('test/assets/pdfs').listSync().whereType<File>().firstWhere(
              (file) => file.path
                  .split(Platform.pathSeparator)
                  .last
                  .startsWith('VISTO 24822-2026 PL 055'),
            );

    final bytes = pdfFile.readAsBytesSync();
    final contents = PdfSignatureValidator.extractAllSignatureContents(bytes);
    expect(contents, hasLength(1));
    expect(contents.single.length, _readDerElementTotalLength(contents.single));
    expect(contents.single.last, 0x00);

    final report = await PdfSignatureValidator().validateAllSignatures(
      bytes,
      trustedRootsProvider: AssetTrustedRootsProvider(
        AssetTrustedRootsProvider.loadDefaultRoots(),
      ),
      includeCertificates: true,
      includeSignatureFields: true,
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
