@TestOn('vm')

import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/crypto.dart' as public_crypto;
import 'package:pdf_plus/src/crypto/base64_impl.dart' as pure_impl;
import 'package:test/test.dart';

import 'base64_benchmark_core.dart';

const _resultPrefix = 'BENCH_RESULT_BASE64=';
const _iterations =
    int.fromEnvironment('BASE64_BENCH_ITERS', defaultValue: 500);
const _payloadBytes =
    int.fromEnvironment('BASE64_BENCH_BYTES', defaultValue: 64 * 1024);

void main() {
  test('benchmark base64 encode/decode on dart vm', () {
    final report = runBase64Benchmark(
      platform: 'dart-vm',
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
          name: 'public_crypto_api',
          encode: public_crypto.base64EncodeBytes,
          decode: public_crypto.base64DecodeToBytes,
        ),
      ],
    );

    print('$_resultPrefix${jsonEncode(report.toJson())}');
    expect(report.results.length, 3);
  }, timeout: const Timeout(Duration(minutes: 5)));
}
