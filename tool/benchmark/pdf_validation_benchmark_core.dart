import 'dart:math' as math;
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';

class ValidationBenchmarkResult {
  const ValidationBenchmarkResult({
    required this.platform,
    required this.warmupRuns,
    required this.measuredRuns,
    required this.durationsMs,
    required this.meanMs,
    required this.medianMs,
    required this.minMs,
    required this.maxMs,
    required this.p90Ms,
    required this.signaturesCount,
    required this.validSignaturesCount,
  });

  factory ValidationBenchmarkResult.fromJson(Map<String, dynamic> json) {
    return ValidationBenchmarkResult(
      platform: json['platform'] as String? ?? 'unknown',
      warmupRuns: (json['warmupRuns'] as num?)?.toInt() ?? 0,
      measuredRuns: (json['measuredRuns'] as num?)?.toInt() ?? 0,
      durationsMs: (json['durationsMs'] as List<dynamic>? ?? const <dynamic>[])
          .map((e) => (e as num).toDouble())
          .toList(growable: false),
      meanMs: (json['meanMs'] as num?)?.toDouble() ?? 0.0,
      medianMs: (json['medianMs'] as num?)?.toDouble() ?? 0.0,
      minMs: (json['minMs'] as num?)?.toDouble() ?? 0.0,
      maxMs: (json['maxMs'] as num?)?.toDouble() ?? 0.0,
      p90Ms: (json['p90Ms'] as num?)?.toDouble() ?? 0.0,
      signaturesCount: (json['signaturesCount'] as num?)?.toInt() ?? 0,
      validSignaturesCount:
          (json['validSignaturesCount'] as num?)?.toInt() ?? 0,
    );
  }

  final String platform;
  final int warmupRuns;
  final int measuredRuns;
  final List<double> durationsMs;
  final double meanMs;
  final double medianMs;
  final double minMs;
  final double maxMs;
  final double p90Ms;
  final int signaturesCount;
  final int validSignaturesCount;

  Map<String, dynamic> toJson() {
    return {
      'platform': platform,
      'warmupRuns': warmupRuns,
      'measuredRuns': measuredRuns,
      'durationsMs': durationsMs,
      'meanMs': meanMs,
      'medianMs': medianMs,
      'minMs': minMs,
      'maxMs': maxMs,
      'p90Ms': p90Ms,
      'signaturesCount': signaturesCount,
      'validSignaturesCount': validSignaturesCount,
    };
  }
}

Future<ValidationBenchmarkResult> runValidationBenchmark({
  required Uint8List pdfBytes,
  required String platform,
  int warmupRuns = 2,
  int measuredRuns = 8,
  bool includeCertificates = false,
  bool includeSignatureFields = true,
}) async {
  if (warmupRuns < 0) {
    throw ArgumentError.value(warmupRuns, 'warmupRuns', 'must be >= 0');
  }
  if (measuredRuns <= 0) {
    throw ArgumentError.value(measuredRuns, 'measuredRuns', 'must be > 0');
  }

  final validator = PdfSignatureValidator();

  for (var i = 0; i < warmupRuns; i++) {
    await validator.validateAllSignatures(
      pdfBytes,
      includeCertificates: includeCertificates,
      includeSignatureFields: includeSignatureFields,
    );
  }

  final samples = <double>[];
  PdfSignatureValidationReport? lastReport;
  for (var i = 0; i < measuredRuns; i++) {
    final stopwatch = Stopwatch()..start();
    lastReport = await validator.validateAllSignatures(
      pdfBytes,
      includeCertificates: includeCertificates,
      includeSignatureFields: includeSignatureFields,
    );
    stopwatch.stop();
    samples.add(stopwatch.elapsedMicroseconds / 1000.0);
  }

  final sorted = List<double>.from(samples)..sort();
  final mean = samples.reduce((a, b) => a + b) / samples.length;
  final median = sorted.length.isOdd
      ? sorted[sorted.length ~/ 2]
      : (sorted[sorted.length ~/ 2 - 1] + sorted[sorted.length ~/ 2]) / 2.0;
  final min = sorted.first;
  final max = sorted.last;
  final p90Index = math.max(0, (sorted.length * 0.9).ceil() - 1);
  final p90 = sorted[p90Index];

  final report = lastReport ??
      const PdfSignatureValidationReport(
        signatures: <PdfSignatureInfoReport>[],
      );
  final validCount = report.signatures
      .where((s) => s.cmsValid && s.digestValid && s.intact)
      .length;

  return ValidationBenchmarkResult(
    platform: platform,
    warmupRuns: warmupRuns,
    measuredRuns: measuredRuns,
    durationsMs: samples,
    meanMs: mean,
    medianMs: median,
    minMs: min,
    maxMs: max,
    p90Ms: p90,
    signaturesCount: report.signatures.length,
    validSignaturesCount: validCount,
  );
}
