import 'dart:typed_data';

import '../document.dart';
import '../parsing/pdf_document_parser.dart';

class PdfLtvService {
  const PdfLtvService();

  Future<({Uint8List bytes, bool applied})> applyLtv({
    required Uint8List pdfBytes,
    List<Uint8List> crl = const <Uint8List>[],
    List<Uint8List> ocsp = const <Uint8List>[],
    List<Uint8List> certs = const <Uint8List>[],
  }) async {
    if (crl.isEmpty && ocsp.isEmpty && certs.isEmpty) {
      return (bytes: pdfBytes, applied: false);
    }

    final parser = PdfDocumentParser(pdfBytes);
    final document = PdfDocument.load(parser);
    document.ensureDss();

    for (final c in crl) {
      document.dss!.addCrlBytes(c);
    }
    for (final o in ocsp) {
      document.dss!.addOcspBytes(o);
    }
    for (final cert in certs) {
      document.dss!.addCertBytes(cert);
    }

    if (document.dss!.isEmpty) {
      return (bytes: pdfBytes, applied: false);
    }

    final out = await document.save();
    return (bytes: Uint8List.fromList(out), applied: true);
  }
}