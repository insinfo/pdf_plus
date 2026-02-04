import 'dart:typed_data';

import '../document.dart';
import '../graphics.dart';
import '../parsing/pdf_document_parser.dart';
import '../rect.dart';
import 'pdf_external_signing.dart';
import 'pdf_signature_config.dart';

/// Convenience helpers for external signing workflows.
class PdfSignatureTools {
  /// Prepares a PDF for external signing using PDF-space bounds.
  static Future<PdfExternalSigningPrepared> prepareExternalSignature({
    required Uint8List inputBytes,
    required int pageNumber,
    required PdfRect bounds,
    required String fieldName,
    PdfSignatureConfig? signature,
    List<List<int>> publicCertificates = const <List<int>>[],
    void Function(PdfGraphics graphics, PdfRect bounds)? drawAppearance,
  }) {
    return PdfExternalSigning.preparePdf(
      inputBytes: inputBytes,
      pageNumber: pageNumber,
      bounds: bounds,
      fieldName: fieldName,
      signature: signature,
      publicCertificates: publicCertificates,
      drawAppearance: drawAppearance,
    );
  }

  /// Prepares a PDF for external signing using top-left coordinates.
  static Future<PdfExternalSigningPrepared> prepareExternalSignatureTopLeft({
    required Uint8List inputBytes,
    required int pageNumber,
    required double left,
    required double top,
    required double width,
    required double height,
    required String fieldName,
    PdfSignatureConfig? signature,
    List<List<int>> publicCertificates = const <List<int>>[],
    void Function(PdfGraphics graphics, PdfRect bounds)? drawAppearance,
  }) async {
    final parser = PdfDocumentParser(inputBytes);
    final document = PdfDocument.load(parser);
    final pageIndex = pageNumber - 1;
    if (pageIndex < 0 || pageIndex >= document.pdfPageList.pages.length) {
      throw RangeError.index(
          pageIndex, document.pdfPageList.pages, 'pageNumber');
    }
    final page = document.pdfPageList.pages[pageIndex];
    final pageHeight = page.pageFormat.height;
    final bounds = PdfRect(left, pageHeight - top - height, width, height);

    return PdfExternalSigning.preparePdf(
      inputBytes: inputBytes,
      pageNumber: pageNumber,
      bounds: bounds,
      fieldName: fieldName,
      signature: signature,
      publicCertificates: publicCertificates,
      drawAppearance: drawAppearance,
    );
  }

  /// Embeds a PKCS#7 signature into prepared PDF bytes.
  static Uint8List embedExternalSignature({
    required Uint8List preparedPdfBytes,
    required Uint8List pkcs7Bytes,
  }) {
    return PdfExternalSigning.embedSignature(
      preparedPdfBytes: preparedPdfBytes,
      pkcs7Bytes: pkcs7Bytes,
    );
  }
}
