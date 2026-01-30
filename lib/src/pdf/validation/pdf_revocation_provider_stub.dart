import 'dart:typed_data';

import 'pdf_signature_validator.dart';

class HttpRevocationDataProvider implements PdfRevocationDataProvider {
  const HttpRevocationDataProvider();

  @override
  Future<Uint8List?> fetchCrl(Uri url) async {
    throw UnsupportedError('HttpRevocationDataProvider não é suportado na web.');
  }

  @override
  Future<Uint8List?> fetchOcsp(Uri url, Uint8List requestDer) async {
    throw UnsupportedError('HttpRevocationDataProvider não é suportado na web.');
  }
}
