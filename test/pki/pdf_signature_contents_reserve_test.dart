import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart' as core;
import 'package:pdf_plus/signing.dart' as pdf;
import 'package:test/test.dart';

void main() {
  test('contentsReserveSize controls /Contents placeholder length', () async {
    const int defaultReserve = 16384;
    const int customReserve = 20000;

    final pdf.PdfExternalSigningPrepared defaultPrepared =
        await _preparePdf(contentsReserveSize: defaultReserve);
    final pdf.PdfExternalSigningPrepared customPrepared =
        await _preparePdf(contentsReserveSize: customReserve);

    final int defaultLen =
        _contentsHexLength(defaultPrepared.preparedPdfBytes, defaultPrepared.byteRange);
    final int customLen =
        _contentsHexLength(customPrepared.preparedPdfBytes, customPrepared.byteRange);

    expect(customLen, greaterThan(defaultLen));
    expect(customLen - defaultLen, equals((customReserve - defaultReserve) * 2));
  });
}

Future<pdf.PdfExternalSigningPrepared> _preparePdf({
  required int contentsReserveSize,
}) async {
  final core.PdfDocument doc = core.PdfDocument();
  final page = core.PdfPage(doc);
  final g = page.getGraphics();
  g.drawString(core.PdfFont.helvetica(doc), 12, 'Reserve size', 50, 750);

  final Uint8List bytes = Uint8List.fromList(await doc.save());

  return pdf.PdfExternalSigning.preparePdf(
    inputBytes: bytes,
    pageNumber: 1,
    bounds: core.PdfRect.fromLTWH(100, 100, 200, 40),
    fieldName: 'Signature1',
    signature: pdf.PdfSignatureConfig(),
    contentsReserveSize: contentsReserveSize,
  );
}

int _contentsHexLength(Uint8List bytes, List<int> byteRange) {
  final int gapStart = byteRange[0] + byteRange[1];
  final int gapEnd = byteRange[2];

  int lt = -1;
  for (int i = gapStart; i < gapEnd; i++) {
    if (bytes[i] == 0x3C) {
      lt = i;
      break;
    }
  }
  if (lt == -1) {
    throw StateError('Delimitador < de /Contents não encontrado.');
  }

  int gt = -1;
  for (int i = lt + 1; i < gapEnd; i++) {
    if (bytes[i] == 0x3E) {
      gt = i;
      break;
    }
  }
  if (gt == -1 || gt <= lt) {
    throw StateError('Delimitador > de /Contents não encontrado.');
  }

  return gt - lt - 1;
}
