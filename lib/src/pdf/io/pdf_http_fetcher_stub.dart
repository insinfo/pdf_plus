import 'dart:typed_data';

import 'package:pdf_plus/src/pdf/io/pdf_http_fetcher_base.dart';

class PdfHttpFetcher implements PdfHttpFetcherBase {
  const PdfHttpFetcher();

  @override
  Future<Uint8List?> fetchBytes(Uri url) async {
    throw UnsupportedError(
        'HttpCertificateFetcher não é suportado nesta plataforma.');
  }

  @override
  Future<PdfHttpResponse> postBytes(
    Uri url, {
    Map<String, String>? headers,
    Uint8List? body,
    Duration? timeout,
  }) async {
    throw UnsupportedError(
        'HttpCertificateFetcher não é suportado nesta plataforma.');
  }
}
