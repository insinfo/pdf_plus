@TestOn('browser')

import 'dart:convert';
import 'dart:html';
import 'dart:typed_data';

import 'package:test/test.dart';

import '../../tool/benchmark/pdf_validation_benchmark_core.dart';

const _resultPrefix = 'BENCH_RESULT_WEB=';

void main() {
  test(
    'benchmark pdf signature validation on browser',
    () async {
      const envUrl = String.fromEnvironment('PDF_BENCHMARK_URL');
      final urls = <String>[
        if (envUrl.isNotEmpty) envUrl,
        '/test/assets/pdfs/documento%20assinado%20erro.pdf',
        'test/assets/pdfs/documento%20assinado%20erro.pdf',
        '/packages/pdf_plus/test/assets/pdfs/documento%20assinado%20erro.pdf',
        'packages/pdf_plus/test/assets/pdfs/documento%20assinado%20erro.pdf',
      ];

      Uint8List bytes;
      try {
        bytes = await _loadBytesFromAnyUrl(urls);
      } on StateError catch (e) {
        markTestSkipped(e.message);
        return;
      }
      final result = await runValidationBenchmark(
        pdfBytes: bytes,
        platform: 'chrome-web',
      );

      print('$_resultPrefix${jsonEncode(result.toJson())}');
      expect(result.signaturesCount, greaterThanOrEqualTo(0));
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );
}

Future<Uint8List> _loadBytesFromAnyUrl(List<String> urls) async {
  final errors = <String>[];
  for (final url in urls) {
    try {
      final response = await HttpRequest.request(
        url,
        method: 'GET',
        responseType: 'arraybuffer',
      );
      final status = response.status ?? 0;
      if (status != 200 && status != 0) {
        errors.add('$url -> HTTP $status');
        continue;
      }

      final raw = response.response;
      if (raw is ByteBuffer) {
        return Uint8List.fromList(Uint8List.view(raw));
      }
      errors.add('$url -> response type ${raw.runtimeType}');
    } catch (e) {
      errors.add('$url -> $e');
    }
  }

  throw StateError(
    'Could not load benchmark PDF in browser. Attempts:\n${errors.join('\n')}',
  );
}
