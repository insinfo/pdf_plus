import 'dart:typed_data';

import 'pdf_signature_validator.dart';

class HttpCertificateFetcher implements PdfCertificateFetcher {
  const HttpCertificateFetcher();

  @override
  Future<Uint8List?> fetchBytes(Uri url) async {
    throw UnsupportedError('HttpCertificateFetcher não é suportado nesta plataforma.');
  }
}
