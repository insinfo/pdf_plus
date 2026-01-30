import 'dart:io';
import 'dart:typed_data';

import 'pdf_signature_validator.dart';

class HttpCertificateFetcher implements PdfCertificateFetcher {
  const HttpCertificateFetcher({
    this.timeout = const Duration(seconds: 10),
    this.userAgent,
  });

  final Duration timeout;
  final String? userAgent;

  @override
  Future<Uint8List?> fetchBytes(Uri url) async {
    final client = HttpClient();
    try {
      final req = await client.getUrl(url).timeout(timeout);
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
    } finally {
      client.close(force: true);
    }
  }
}
