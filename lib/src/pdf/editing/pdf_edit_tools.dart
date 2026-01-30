import 'dart:typed_data';

import '../document.dart';
import '../graphics.dart';
import '../obj/annotation.dart';
import '../obj/page.dart';
import '../parsing/pdf_document_parser.dart';
import '../rect.dart';

class PdfEditTools {
  static Future<Uint8List> addUriAnnotation({
    required Uint8List pdfBytes,
    required int pageNumber,
    required PdfRect bounds,
    required String uri,
  }) async {
    final parser = PdfDocumentParser(pdfBytes);
    final document = PdfDocument.load(parser);

    final pageIndex = pageNumber - 1;
    if (pageIndex < 0 || pageIndex >= document.pdfPageList.pages.length) {
      throw RangeError.index(pageIndex, document.pdfPageList.pages, 'pageNumber');
    }

    final page = document.pdfPageList.pages[pageIndex];
    PdfAnnot(page, PdfUriAnnotation(bounds: bounds, uri: uri));

    return document.save(useIsolate: false);
  }

  static Future<Uint8List> addUriAnnotationTopLeft({
    required Uint8List pdfBytes,
    required int pageNumber,
    required double left,
    required double top,
    required double width,
    required double height,
    required String uri,
  }) async {
    final parser = PdfDocumentParser(pdfBytes);
    final document = PdfDocument.load(parser);

    final pageIndex = pageNumber - 1;
    if (pageIndex < 0 || pageIndex >= document.pdfPageList.pages.length) {
      throw RangeError.index(pageIndex, document.pdfPageList.pages, 'pageNumber');
    }

    final page = document.pdfPageList.pages[pageIndex];
    final bounds = _rectFromTopLeft(
      page,
      left: left,
      top: top,
      width: width,
      height: height,
    );
    PdfAnnot(page, PdfUriAnnotation(bounds: bounds, uri: uri));

    return document.save(useIsolate: false);
  }

  static Future<Uint8List> addSignatureField({
    required Uint8List pdfBytes,
    required int pageNumber,
    required PdfRect bounds,
    required String fieldName,
    void Function(PdfGraphics graphics, PdfRect bounds)? drawAppearance,
  }) async {
    final parser = PdfDocumentParser(pdfBytes);
    final document = PdfDocument.load(parser);

    final pageIndex = pageNumber - 1;
    if (pageIndex < 0 || pageIndex >= document.pdfPageList.pages.length) {
      throw RangeError.index(pageIndex, document.pdfPageList.pages, 'pageNumber');
    }

    final page = document.pdfPageList.pages[pageIndex];
    final widget = PdfAnnotSign(rect: bounds, fieldName: fieldName);
    if (drawAppearance != null) {
      final g = widget.appearance(document, PdfAnnotAppearance.normal);
      drawAppearance(g, PdfRect(0, 0, bounds.width, bounds.height));
    }
    PdfAnnot(page, widget);

    return document.save(useIsolate: false);
  }

  static Future<Uint8List> addSignatureFieldTopLeft({
    required Uint8List pdfBytes,
    required int pageNumber,
    required double left,
    required double top,
    required double width,
    required double height,
    required String fieldName,
    void Function(PdfGraphics graphics, PdfRect bounds)? drawAppearance,
  }) async {
    final parser = PdfDocumentParser(pdfBytes);
    final document = PdfDocument.load(parser);

    final pageIndex = pageNumber - 1;
    if (pageIndex < 0 || pageIndex >= document.pdfPageList.pages.length) {
      throw RangeError.index(pageIndex, document.pdfPageList.pages, 'pageNumber');
    }

    final page = document.pdfPageList.pages[pageIndex];
    final bounds = _rectFromTopLeft(
      page,
      left: left,
      top: top,
      width: width,
      height: height,
    );
    final widget = PdfAnnotSign(rect: bounds, fieldName: fieldName);
    if (drawAppearance != null) {
      final g = widget.appearance(document, PdfAnnotAppearance.normal);
      drawAppearance(g, PdfRect(0, 0, bounds.width, bounds.height));
    }
    PdfAnnot(page, widget);

    return document.save(useIsolate: false);
  }
}

PdfRect _rectFromTopLeft(
  PdfPage page, {
  required double left,
  required double top,
  required double width,
  required double height,
}) {
  final pageHeight = page.pageFormat.height;
  final bottom = pageHeight - top - height;
  return PdfRect(left, bottom, width, height);
}
