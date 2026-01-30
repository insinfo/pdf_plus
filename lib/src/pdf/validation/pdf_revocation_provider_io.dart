import 'dart:io';
import 'dart:typed_data';

import 'pdf_signature_validator.dart';

class HttpRevocationDataProvider implements PdfRevocationDataProvider {
  const HttpRevocationDataProvider({
    this.timeout = const Duration(seconds: 10),
    this.userAgent,
  });

  final Duration timeout;
  final String? userAgent;

  @override
  Future<Uint8List?> fetchCrl(Uri url) async {
    return _getBytes(url, contentType: 'application/pkix-crl');
  }

  @override
  Future<Uint8List?> fetchOcsp(Uri url, Uint8List requestDer) async {
    return _postBytes(
      url,
      body: requestDer,
      contentType: 'application/ocsp-request',
      accept: 'application/ocsp-response',
    );
  }

  Future<Uint8List?> _getBytes(Uri url, {String? contentType}) async {
    final client = HttpClient();
    try {
      final req = await client.getUrl(url).timeout(timeout);
      if (userAgent != null) {
        req.headers.set(HttpHeaders.userAgentHeader, userAgent!);
      }
      if (contentType != null) {
        req.headers.set(HttpHeaders.acceptHeader, contentType);
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

  Future<Uint8List?> _postBytes(
    Uri url, {
    required Uint8List body,
    required String contentType,
    String? accept,
  }) async {
    final client = HttpClient();
    try {
      final req = await client.postUrl(url).timeout(timeout);
      if (userAgent != null) {
        req.headers.set(HttpHeaders.userAgentHeader, userAgent!);
      }
      req.headers.set(HttpHeaders.contentTypeHeader, contentType);
      if (accept != null) {
        req.headers.set(HttpHeaders.acceptHeader, accept);
      }
      req.add(body);
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
