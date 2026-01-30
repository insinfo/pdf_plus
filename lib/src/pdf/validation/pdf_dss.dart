import 'dart:typed_data';

import '../document.dart';
import '../obj/object_stream.dart';

class PdfDssData {
  PdfDssData(this.document);

  final PdfDocument document;
  final List<PdfObjectStream> crl = <PdfObjectStream>[];
  final List<PdfObjectStream> cert = <PdfObjectStream>[];
  final List<PdfObjectStream> ocsp = <PdfObjectStream>[];

  bool get isEmpty => crl.isEmpty && cert.isEmpty && ocsp.isEmpty;

  void addCrlBytes(Uint8List bytes) {
    if (bytes.isEmpty) return;
    crl.add(PdfObjectStream(document)..buf.putBytes(bytes));
  }

  void addOcspBytes(Uint8List bytes) {
    if (bytes.isEmpty) return;
    ocsp.add(PdfObjectStream(document)..buf.putBytes(bytes));
  }

  void addCertBytes(Uint8List bytes) {
    if (bytes.isEmpty) return;
    cert.add(PdfObjectStream(document)..buf.putBytes(bytes));
  }
}