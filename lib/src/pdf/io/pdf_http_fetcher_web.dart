import 'dart:async';
import 'dart:html' as html;
import 'dart:typed_data';
import 'package:pdf_plus/src/pdf/io/pdf_http_fetcher_base.dart';

class PdfHttpFetcher implements PdfHttpFetcherBase {
  PdfHttpFetcher({this.timeout = const Duration(seconds: 10)});

  final Duration timeout;

  @override
  Future<Uint8List?> fetchBytes(Uri url) async {
    try {
      final future = html.HttpRequest.request(
        url.toString(),
        method: 'GET',
        responseType: 'arraybuffer',
      );
      final response = await future.timeout(timeout);
      final status = response.status ?? 0;
      if (status != 0 && (status < 200 || status >= 300)) {
        return null;
      }
      final data = response.response;
      if (data is ByteBuffer) {
        return Uint8List.view(data);
      }
      if (data is Uint8List) {
        return data;
      }
      return null;
    } on TimeoutException {
      return null;
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
    final watch = Stopwatch()..start();
    try {
      final response = await html.HttpRequest.request(
        url.toString(),
        method: 'POST',
        responseType: 'arraybuffer',
        requestHeaders: headers ?? const <String, String>{},
        sendData: body,
      ).timeout(effectiveTimeout);
      watch.stop();

      final status = response.status ?? 0;
      final data = response.response;
      Uint8List bytes;
      if (data is ByteBuffer) {
        bytes = Uint8List.view(data);
      } else if (data is Uint8List) {
        bytes = data;
      } else {
        bytes = Uint8List(0);
      }

      return PdfHttpResponse(
        statusCode: status,
        body: bytes,
        totalTime: watch.elapsed,
      );
    } on TimeoutException {
      watch.stop();
      return PdfHttpResponse(
        statusCode: 0,
        body: Uint8List(0),
      );
    } catch (_) {
      watch.stop();
      return PdfHttpResponse(
        statusCode: 0,
        body: Uint8List(0),
      );
    }
  }
}
