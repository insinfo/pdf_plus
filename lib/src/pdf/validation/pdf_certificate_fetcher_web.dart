import 'dart:async';
import 'dart:html' as html;
import 'dart:typed_data';

import 'pdf_signature_validator.dart';

class HttpCertificateFetcher implements PdfCertificateFetcher {
  const HttpCertificateFetcher({this.timeout = const Duration(seconds: 10)});

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
}
