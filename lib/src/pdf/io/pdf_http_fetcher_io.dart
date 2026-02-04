import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/src/pdf/io/pdf_http_fetcher_base.dart';

class PdfHttpFetcher implements PdfHttpFetcherBase {
  PdfHttpFetcher({
    this.timeout = const Duration(seconds: 10),
    this.userAgent,
    HttpClient? client,
  }) : _client = client ?? HttpClient();

  final Duration timeout;
  final String? userAgent;
  final HttpClient _client;

  @override
  Future<Uint8List?> fetchBytes(Uri url) async {
    try {
      final req = await _client.getUrl(url).timeout(timeout);
      if (userAgent != null) {
        req.headers.set(HttpHeaders.userAgentHeader, userAgent!);
      }
      final res = await req.close().timeout(timeout);
      if (res.statusCode < 200 || res.statusCode >= 300) {
        return null;
      }
      final bytes = await res.fold<List<int>>(<int>[], (p, e) => p..addAll(e));
      return bytes.isEmpty ? null : Uint8List.fromList(bytes);
    } catch (_) {
      return null;
    }
  }

  @override
  Future<PdfHttpResponse> postBytes(
    Uri url, {
    Map<String, String>? headers,
    Uint8List? body,
    Duration? timeout,
  }) async {
    final effectiveTimeout = timeout ?? this.timeout;
    final requestWatch = Stopwatch()..start();
    try {
      final req = await _client.postUrl(url).timeout(effectiveTimeout);
      if (userAgent != null) {
        req.headers.set(HttpHeaders.userAgentHeader, userAgent!);
      }
      headers?.forEach(req.headers.set);
      if (body != null && body.isNotEmpty) {
        req.add(body);
      }

      final res = await req.close().timeout(effectiveTimeout);
      requestWatch.stop();

      final responseWatch = Stopwatch()..start();
      final bytes = await res.fold<List<int>>(<int>[], (p, e) => p..addAll(e));
      responseWatch.stop();

      return PdfHttpResponse(
        statusCode: res.statusCode,
        body: Uint8List.fromList(bytes),
        requestTime: requestWatch.elapsed,
        responseTime: responseWatch.elapsed,
        totalTime: requestWatch.elapsed + responseWatch.elapsed,
      );
    } catch (_) {
      requestWatch.stop();
      return PdfHttpResponse(
        statusCode: 0,
        body: Uint8List(0),
      );
    }
  }
}
