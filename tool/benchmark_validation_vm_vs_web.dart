import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'benchmark/pdf_validation_benchmark_core.dart';

const _webResultPrefix = 'BENCH_RESULT_WEB=';

Future<void> main(List<String> args) async {
  final config = _parseArgs(args);
  final pdfFile = File(config.pdfPath);
  if (!pdfFile.existsSync()) {
    stderr.writeln('PDF not found: ${pdfFile.path}');
    exitCode = 2;
    return;
  }

  final bytes = Uint8List.fromList(await pdfFile.readAsBytes());
  stdout.writeln(
    'Benchmark input: ${pdfFile.path} (${bytes.length} bytes), '
    'warmup=${config.warmupRuns}, runs=${config.measuredRuns}',
  );

  final vm = await runValidationBenchmark(
    pdfBytes: bytes,
    platform: 'dart-vm',
    warmupRuns: config.warmupRuns,
    measuredRuns: config.measuredRuns,
  );

  final web = await _runBrowserBenchmark(config, bytes);
  final ratioMean = web.meanMs == 0 ? 0 : vm.meanMs / web.meanMs;
  final ratioMedian = web.medianMs == 0 ? 0 : vm.medianMs / web.medianMs;

  stdout.writeln('');
  stdout.writeln('Comparison (lower is faster)');
  stdout.writeln(
    'VM   mean=${vm.meanMs.toStringAsFixed(2)}ms '
    'median=${vm.medianMs.toStringAsFixed(2)}ms '
    'p90=${vm.p90Ms.toStringAsFixed(2)}ms',
  );
  stdout.writeln(
    'WEB  mean=${web.meanMs.toStringAsFixed(2)}ms '
    'median=${web.medianMs.toStringAsFixed(2)}ms '
    'p90=${web.p90Ms.toStringAsFixed(2)}ms',
  );
  stdout.writeln(
    'Ratio VM/WEB mean=${ratioMean.toStringAsFixed(2)}x '
    'median=${ratioMedian.toStringAsFixed(2)}x',
  );
  stdout.writeln(
    'Signatures: vm=${vm.signaturesCount}, web=${web.signaturesCount}; '
    'valid vm=${vm.validSignaturesCount}, web=${web.validSignaturesCount}',
  );
  stdout.writeln('');
  stdout.writeln('JSON_VM=${jsonEncode(vm.toJson())}');
  stdout.writeln('JSON_WEB=${jsonEncode(web.toJson())}');
}

Future<ValidationBenchmarkResult> _runBrowserBenchmark(
  _BenchmarkConfig config,
  Uint8List pdfBytes,
) async {
  stdout.writeln('Running Chrome benchmark...');

  final generatedTestFile = File(
      'test/benchmark/_generated_pdf_validation_browser_benchmark_test.dart');
  await generatedTestFile.writeAsString(
    _buildBrowserBenchmarkTestSource(
      pdfBytes: pdfBytes,
      warmupRuns: config.warmupRuns,
      measuredRuns: config.measuredRuns,
    ),
  );

  final process = await Process.start(
    'dart',
    <String>[
      'test',
      '-p',
      'chrome',
      generatedTestFile.path,
      '--reporter',
      'expanded',
      '--timeout',
      config.browserTimeout,
      '--name',
      'generated browser benchmark',
    ],
    runInShell: true,
  );

  final stdoutBuffer = StringBuffer();
  final stderrBuffer = StringBuffer();
  process.stdout
      .transform(utf8.decoder)
      .transform(const LineSplitter())
      .listen((line) {
    stdout.writeln(line);
    stdoutBuffer.writeln(line);
  });
  process.stderr
      .transform(utf8.decoder)
      .transform(const LineSplitter())
      .listen((line) {
    stderr.writeln(line);
    stderrBuffer.writeln(line);
  });

  try {
    final exit = await process.exitCode;
    final fullOutput = '${stdoutBuffer.toString()}\n${stderrBuffer.toString()}';
    final jsonLine = _extractResultJsonLine(fullOutput, _webResultPrefix);

    if (exit != 0) {
      throw ProcessException(
        'dart test -p chrome',
        <String>[
          generatedTestFile.path,
        ],
        'Browser benchmark failed with exit=$exit.\n$fullOutput',
        exit,
      );
    }
    if (jsonLine == null) {
      throw StateError(
        'Browser benchmark did not print $_webResultPrefix line.\n$fullOutput',
      );
    }

    return ValidationBenchmarkResult.fromJson(
      jsonDecode(jsonLine) as Map<String, dynamic>,
    );
  } finally {
    if (generatedTestFile.existsSync()) {
      generatedTestFile.deleteSync();
    }
  }
}

String? _extractResultJsonLine(String output, String prefix) {
  for (final line in const LineSplitter().convert(output)) {
    final trimmed = line.trim();
    if (trimmed.startsWith(prefix)) {
      return trimmed.substring(prefix.length);
    }
  }
  return null;
}

String _buildBrowserBenchmarkTestSource({
  required Uint8List pdfBytes,
  required int warmupRuns,
  required int measuredRuns,
}) {
  final b64 = base64Encode(pdfBytes);
  final chunks =
      _chunkString(b64, 16384).map((chunk) => "    '$chunk'").join('\n');
  return '''
@TestOn('browser')

import 'dart:convert';

import 'package:test/test.dart';

import '../../tool/benchmark/pdf_validation_benchmark_core.dart';

const _resultPrefix = '$_webResultPrefix';
const _pdfBase64 =
$chunks
    '';

void main() {
  test(
    'generated browser benchmark',
    () async {
      final bytes = base64Decode(_pdfBase64);
      final result = await runValidationBenchmark(
        pdfBytes: bytes,
        platform: 'chrome-web',
        warmupRuns: $warmupRuns,
        measuredRuns: $measuredRuns,
      );
      print('\$_resultPrefix\${jsonEncode(result.toJson())}');
      expect(result.signaturesCount, greaterThanOrEqualTo(0));
    },
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
''';
}

Iterable<String> _chunkString(String value, int chunkSize) sync* {
  for (var i = 0; i < value.length; i += chunkSize) {
    final end = (i + chunkSize < value.length) ? i + chunkSize : value.length;
    yield value.substring(i, end);
  }
}

_BenchmarkConfig _parseArgs(List<String> args) {
  var pdfPath = 'test/assets/pdfs/documento assinado erro.pdf';
  var warmupRuns = 2;
  var measuredRuns = 8;
  var browserTimeout = '3m';

  for (var i = 0; i < args.length; i++) {
    final arg = args[i];
    if (arg == '--pdf' && i + 1 < args.length) {
      pdfPath = args[++i];
    } else if (arg == '--warmup' && i + 1 < args.length) {
      warmupRuns = int.parse(args[++i]);
    } else if (arg == '--runs' && i + 1 < args.length) {
      measuredRuns = int.parse(args[++i]);
    } else if (arg == '--browser-timeout' && i + 1 < args.length) {
      browserTimeout = args[++i];
    } else if (arg == '--help' || arg == '-h') {
      _printUsage();
      exit(0);
    } else {
      stderr.writeln('Unknown argument: $arg');
      _printUsage();
      exit(2);
    }
  }

  if (warmupRuns < 0 || measuredRuns <= 0) {
    stderr.writeln('Invalid runs: warmup >= 0 and runs > 0 are required.');
    exit(2);
  }

  return _BenchmarkConfig(
    pdfPath: pdfPath,
    warmupRuns: warmupRuns,
    measuredRuns: measuredRuns,
    browserTimeout: browserTimeout,
  );
}

void _printUsage() {
  stdout.writeln('Usage: dart run tool/benchmark_validation_vm_vs_web.dart [');
  stdout.writeln('  --pdf <path>');
  stdout.writeln('  --warmup <int>');
  stdout.writeln('  --runs <int>');
  stdout.writeln('  --browser-timeout <duration>');
  stdout.writeln(']');
}

class _BenchmarkConfig {
  const _BenchmarkConfig({
    required this.pdfPath,
    required this.warmupRuns,
    required this.measuredRuns,
    required this.browserTimeout,
  });

  final String pdfPath;
  final int warmupRuns;
  final int measuredRuns;
  final String browserTimeout;
}
