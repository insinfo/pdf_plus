import 'dart:convert';
import 'dart:typed_data';

typedef BytesToBase64 = String Function(Uint8List bytes);
typedef Base64ToBytes = Uint8List Function(String encoded);

class Base64BenchmarkCase {
  const Base64BenchmarkCase({
    required this.name,
    required this.encode,
    required this.decode,
  });

  final String name;
  final BytesToBase64 encode;
  final Base64ToBytes decode;
}

class Base64BenchmarkResult {
  const Base64BenchmarkResult({
    required this.name,
    required this.encodeMicros,
    required this.decodeMicros,
    required this.encodeMiBPerSec,
    required this.decodeMiBPerSec,
  });

  final String name;
  final int encodeMicros;
  final int decodeMicros;
  final double encodeMiBPerSec;
  final double decodeMiBPerSec;

  Map<String, Object> toJson() => <String, Object>{
        'name': name,
        'encodeMicros': encodeMicros,
        'decodeMicros': decodeMicros,
        'encodeMiBPerSec': encodeMiBPerSec,
        'decodeMiBPerSec': decodeMiBPerSec,
      };
}

class Base64BenchmarkReport {
  const Base64BenchmarkReport({
    required this.platform,
    required this.payloadBytes,
    required this.iterations,
    required this.results,
  });

  final String platform;
  final int payloadBytes;
  final int iterations;
  final List<Base64BenchmarkResult> results;

  Map<String, Object> toJson() => <String, Object>{
        'platform': platform,
        'payloadBytes': payloadBytes,
        'iterations': iterations,
        'results': results.map((item) => item.toJson()).toList(),
      };
}

Base64BenchmarkReport runBase64Benchmark({
  required String platform,
  required List<Base64BenchmarkCase> cases,
  int payloadBytes = 64 * 1024,
  int iterations = 400,
}) {
  if (cases.isEmpty) {
    throw ArgumentError.value(cases, 'cases', 'Must not be empty');
  }

  final payload = Uint8List.fromList(
    List<int>.generate(payloadBytes, (index) => (index * 31 + 17) & 0xff),
  );
  final expectedEncoded = base64.encode(payload);

  for (final item in cases) {
    final encoded = item.encode(payload);
    if (encoded != expectedEncoded) {
      throw StateError('Encode mismatch for ${item.name}');
    }
    final decoded = item.decode(expectedEncoded);
    if (!_equalsBytes(decoded, payload)) {
      throw StateError('Decode mismatch for ${item.name}');
    }
  }

  for (final item in cases) {
    for (var i = 0; i < 8; i++) {
      item.encode(payload);
      item.decode(expectedEncoded);
    }
  }

  final results = <Base64BenchmarkResult>[];
  for (final item in cases) {
    final encodeWatch = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      item.encode(payload);
    }
    encodeWatch.stop();

    final decodeWatch = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      item.decode(expectedEncoded);
    }
    decodeWatch.stop();

    final encodeMicros = encodeWatch.elapsedMicroseconds;
    final decodeMicros = decodeWatch.elapsedMicroseconds;
    final processedBytes = payloadBytes * iterations;

    results.add(
      Base64BenchmarkResult(
        name: item.name,
        encodeMicros: encodeMicros,
        decodeMicros: decodeMicros,
        encodeMiBPerSec: _mibPerSec(processedBytes, encodeMicros),
        decodeMiBPerSec: _mibPerSec(processedBytes, decodeMicros),
      ),
    );
  }

  return Base64BenchmarkReport(
    platform: platform,
    payloadBytes: payloadBytes,
    iterations: iterations,
    results: results,
  );
}

double _mibPerSec(int bytes, int micros) {
  if (micros <= 0) return 0;
  return (bytes * 1000000.0) / (micros * 1024.0 * 1024.0);
}

bool _equalsBytes(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  for (var i = 0; i < left.length; i++) {
    if (left[i] != right[i]) return false;
  }
  return true;
}
