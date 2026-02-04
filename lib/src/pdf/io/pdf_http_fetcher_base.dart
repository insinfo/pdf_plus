import 'dart:typed_data';

export 'pdf_http_fetcher_stub.dart'
    if (dart.library.io) 'pdf_http_fetcher_io.dart'
    if (dart.library.html) 'pdf_http_fetcher_web.dart';

class PdfHttpResponse {
  const PdfHttpResponse({
    required this.statusCode,
    required this.body,
    this.headers = const <String, String>{},
    this.requestTime,
    this.responseTime,
    this.totalTime,
  });

  final int statusCode;
  final Uint8List body;
  final Map<String, String> headers;
  final Duration? requestTime;
  final Duration? responseTime;
  final Duration? totalTime;
}

/// Provider de download de certificados (AIA/caIssuers) e POST simples.
abstract class PdfHttpFetcherBase {
  Future<Uint8List?> fetchBytes(Uri url);

  Future<PdfHttpResponse> postBytes(
    Uri url, {
    Map<String, String>? headers,
    Uint8List? body,
    Duration? timeout,
  });
}
