@TestOn('browser')

import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/base64_impl.dart' as pure_impl;
import 'package:pdf_plus/src/crypto/base64_web.dart' as web_impl;
import 'package:test/test.dart';

import 'base64_benchmark_core.dart';

const _resultPrefix = 'BENCH_RESULT_BASE64=';
const _iterations =
    int.fromEnvironment('BASE64_BENCH_ITERS', defaultValue: 350);
const _payloadBytes =
    int.fromEnvironment('BASE64_BENCH_BYTES', defaultValue: 64 * 1024);

void main() {
  test('benchmark base64 encode/decode on browser', () {
    final report = runBase64Benchmark(
      platform: 'browser-web',
      payloadBytes: _payloadBytes,
      iterations: _iterations,
      cases: <Base64BenchmarkCase>[
        Base64BenchmarkCase(
          name: 'dart_convert',
          encode: (bytes) => base64.encode(bytes),
          decode: (encoded) => Uint8List.fromList(base64.decode(encoded)),
        ),
        Base64BenchmarkCase(
          name: 'pure_dart_impl',
          encode: pure_impl.base64EncodeBytesImpl,
          decode: pure_impl.base64DecodeToBytesImpl,
        ),
        Base64BenchmarkCase(
          name: 'web_native_btoa_atob',
          encode: web_impl.base64EncodeBytesImpl,
          decode: web_impl.base64DecodeToBytesImpl,
        ),
      ],
    );

    print('$_resultPrefix${jsonEncode(report.toJson())}');
    expect(report.results.length, 3);
  }, timeout: const Timeout(Duration(minutes: 5)));
}
