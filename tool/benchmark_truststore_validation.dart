import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pki.dart';
import 'package:pdf_plus/signing.dart';

const String _defaultPdf1 =
    r'test/assets/pdfs/sample_token_icpbrasil_assinado.pdf';
const String _defaultPdf2 =
    r'test/assets/pdfs/3 ass leonardo e stefan e mauricio.pdf';

const String _defaultJksIcpBrasil =
    r'test/assets/truststore/keystore_icp_brasil/keystore_ICP_Brasil.jks';
const String _defaultJksGovBr =
    r'test/assets/truststore/gov.br/cadeia_govbr_unica.jks';

const String _defaultBksIcpBrasil =
    r'test/assets/truststore/icp_brasil/cadeiasicpbrasil.bks';
const String _defaultBksGovBr =
    r'test/assets/truststore/gov.br/cadeia_govbr_unica.bks';

const String _defaultJksPassword = '12345678';
const String _defaultBksPassword = 'serprosigner';

Future<void> main(List<String> args) async {
  var runs = 3;
  var smartRoots = true;
  var jksPassword = _defaultJksPassword;
  var bksPassword = _defaultBksPassword;

  final jksPaths = <String>[_defaultJksIcpBrasil, _defaultJksGovBr];
  final bksPaths = <String>[_defaultBksIcpBrasil, _defaultBksGovBr];
  final pdfs = <String>[_defaultPdf1, _defaultPdf2];

  for (var i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--runs':
        runs = int.parse(args[++i]);
        break;
      case '--smart-roots':
        smartRoots = true;
        break;
      case '--no-smart-roots':
        smartRoots = false;
        break;
      case '--jks':
        jksPaths
          ..clear()
          ..add(args[++i]);
        break;
      case '--jks-add':
        jksPaths.add(args[++i]);
        break;
      case '--bks':
        bksPaths
          ..clear()
          ..add(args[++i]);
        break;
      case '--bks-add':
        bksPaths.add(args[++i]);
        break;
      case '--jks-pass':
        jksPassword = args[++i];
        break;
      case '--bks-pass':
        bksPassword = args[++i];
        break;
      case '--pdf':
        pdfs.add(args[++i]);
        break;
      case '--help':
      case '-h':
        _printHelp();
        return;
      default:
        stderr.writeln('Argumento invalido: ${args[i]}');
        _printHelp();
        exitCode = 2;
        return;
    }
  }

  if (runs <= 0) {
    stderr.writeln('--runs deve ser > 0');
    exitCode = 2;
    return;
  }

  final uniquePdfs = pdfs.toSet().toList(growable: false);
  final uniqueJksPaths = jksPaths.toSet().toList(growable: false);
  final uniqueBksPaths = bksPaths.toSet().toList(growable: false);

  for (final path in [...uniqueJksPaths, ...uniqueBksPaths, ...uniquePdfs]) {
    if (!File(path).existsSync()) {
      stderr.writeln('Arquivo nao encontrado: $path');
      exitCode = 2;
      return;
    }
  }

  final pdfBytesByPath = <String, Uint8List>{};
  for (final path in uniquePdfs) {
    pdfBytesByPath[path] = File(path).readAsBytesSync();
  }

  stdout.writeln('Benchmark truststore + validacao de assinatura PDF');
  stdout.writeln('Runs: $runs');
  stdout.writeln('Smart roots: ${smartRoots ? "on" : "off"}');
  stdout.writeln('JKSs:');
  for (final p in uniqueJksPaths) {
    stdout.writeln('  - $p');
  }
  stdout.writeln('BKSs:');
  for (final p in uniqueBksPaths) {
    stdout.writeln('  - $p');
  }
  stdout.writeln('PDFs:');
  for (final path in uniquePdfs) {
    stdout.writeln('  - $path (${File(path).lengthSync()} bytes)');
  }
  stdout.writeln('');

  final jksResult = smartRoots
      ? await _runScenarioSmart(
          name: 'JKS (smart)',
          runs: runs,
          buildContext: () => _buildSmartContextFromJks(
            jksPaths: uniqueJksPaths,
            jksPassword: jksPassword,
          ),
          pdfBytesByPath: pdfBytesByPath,
        )
      : await _runScenarioClassic(
          name: 'JKS',
          runs: runs,
          loadRoots: () => _loadMergedJksRoots(
            jksPaths: uniqueJksPaths,
            jksPassword: jksPassword,
          ),
          pdfBytesByPath: pdfBytesByPath,
        );

  final bksResult = smartRoots
      ? await _runScenarioSmart(
          name: 'BKS (smart)',
          runs: runs,
          buildContext: () => _buildSmartContextFromBks(
            bksPaths: uniqueBksPaths,
            bksPassword: bksPassword,
          ),
          pdfBytesByPath: pdfBytesByPath,
        )
      : await _runScenarioClassic(
          name: 'BKS',
          runs: runs,
          loadRoots: () => _loadMergedBksRoots(
            bksPaths: uniqueBksPaths,
            bksPassword: bksPassword,
          ),
          pdfBytesByPath: pdfBytesByPath,
        );

  _printSummary(jksResult, bksResult);

  if (smartRoots) {
    final jksCtx = await _buildSmartContextFromJks(
      jksPaths: uniqueJksPaths,
      jksPassword: jksPassword,
    );
    final bksCtx = await _buildSmartContextFromBks(
      bksPaths: uniqueBksPaths,
      bksPassword: bksPassword,
    );
    await _printFunctionalReportSmart('JKS (smart)', jksCtx, pdfBytesByPath);
    await _printFunctionalReportSmart('BKS (smart)', bksCtx, pdfBytesByPath);
  } else {
    final jksRoots = await _loadMergedJksRoots(
      jksPaths: uniqueJksPaths,
      jksPassword: jksPassword,
    );
    final bksRoots = await _loadMergedBksRoots(
      bksPaths: uniqueBksPaths,
      bksPassword: bksPassword,
    );
    await _printFunctionalReport('JKS', jksRoots, pdfBytesByPath);
    await _printFunctionalReport('BKS', bksRoots, pdfBytesByPath);
  }
}

Future<List<Uint8List>> _loadMergedJksRoots({
  required List<String> jksPaths,
  required String jksPassword,
}) async {
  final merged = <Uint8List>[];
  final seen = <String>{};
  for (final path in jksPaths) {
    final loader = IcpBrasilCertificateLoader(
      jksPath: path,
      jksPassword: jksPassword,
    );
    final roots = await loader.loadFromJks(verifyIntegrity: true);
    for (final cert in roots) {
      final key = base64Encode(cert);
      if (seen.add(key)) merged.add(cert);
    }
  }
  return merged;
}

Future<List<Uint8List>> _loadMergedBksRoots({
  required List<String> bksPaths,
  required String bksPassword,
}) async {
  final merged = <Uint8List>[];
  final seen = <String>{};
  for (final path in bksPaths) {
    final loader = IcpBrasilCertificateLoader(
      bksPath: path,
      bksPassword: bksPassword,
    );
    final roots = await loader.loadFromBks(tryDecryptKeys: false);
    for (final cert in roots) {
      final key = base64Encode(cert);
      if (seen.add(key)) merged.add(cert);
    }
  }
  return merged;
}

Future<_SmartContext> _buildSmartContextFromJks({
  required List<String> jksPaths,
  required String jksPassword,
}) async {
  final sources = <PdfTrustedRootsSource>[];
  final sourceLabels = <String, String>{};
  var certCount = 0;

  for (final path in jksPaths) {
    final loader = IcpBrasilCertificateLoader(
      jksPath: path,
      jksPassword: jksPassword,
    );
    final roots = await loader.loadFromJks(verifyIntegrity: true);
    certCount += roots.length;
    final id = 'jks:${File(path).uri.pathSegments.last}';
    sourceLabels[id] = path;
    sources.add(
      PdfTrustedRootsSource(
        id: id,
        provider: PdfInMemoryTrustedRootsProvider(roots),
      ),
    );
  }

  final index = await PdfTrustedRootsIndex.build(sources);
  final selector = PdfSmartTrustedRootsSelector(index);
  final validator = PdfSmartSignatureValidator();
  return _SmartContext(
    selector: selector,
    validator: validator,
    sourceLabels: sourceLabels,
    certCount: certCount,
  );
}

Future<_SmartContext> _buildSmartContextFromBks({
  required List<String> bksPaths,
  required String bksPassword,
}) async {
  final sources = <PdfTrustedRootsSource>[];
  final sourceLabels = <String, String>{};
  var certCount = 0;

  for (final path in bksPaths) {
    final loader = IcpBrasilCertificateLoader(
      bksPath: path,
      bksPassword: bksPassword,
    );
    final roots = await loader.loadFromBks(tryDecryptKeys: false);
    certCount += roots.length;
    final id = 'bks:${File(path).uri.pathSegments.last}';
    sourceLabels[id] = path;
    sources.add(
      PdfTrustedRootsSource(
        id: id,
        provider: PdfInMemoryTrustedRootsProvider(roots),
      ),
    );
  }

  final index = await PdfTrustedRootsIndex.build(sources);
  final selector = PdfSmartTrustedRootsSelector(index);
  final validator = PdfSmartSignatureValidator();
  return _SmartContext(
    selector: selector,
    validator: validator,
    sourceLabels: sourceLabels,
    certCount: certCount,
  );
}

Future<_ScenarioResult> _runScenarioSmart({
  required String name,
  required int runs,
  required Future<_SmartContext> Function() buildContext,
  required Map<String, Uint8List> pdfBytesByPath,
}) async {
  final loadTimesMs = <int>[];
  final validationTimesMs = <int>[];
  final rssLoadDeltaBytes = <int>[];
  final rssTotalDeltaBytes = <int>[];
  var certCount = 0;
  final signaturesByPdf = <String, int>{};
  final validByPdf = <String, int>{};

  stdout.writeln('== $name ==');
  for (var i = 1; i <= runs; i++) {
    final rssBefore = ProcessInfo.currentRss;

    final swLoad = Stopwatch()..start();
    final context = await buildContext();
    swLoad.stop();
    certCount = context.certCount;
    final rssAfterLoad = ProcessInfo.currentRss;

    final swValidation = Stopwatch()..start();
    for (final entry in pdfBytesByPath.entries) {
      final result = await context.validator.validateAllSignatures(
        entry.value,
        rootsSelector: context.selector,
        includeCertificates: false,
        includeSignatureFields: true,
      );
      signaturesByPdf[entry.key] = result.report.signatures.length;
      validByPdf[entry.key] = result.report.signatures
          .where((s) => s.cmsValid && s.digestValid && s.intact)
          .length;
      final selected = _formatSelectedStores(
        result.rootsSelection.selectedSourceIds,
        context.sourceLabels,
      );
      stdout.writeln('  smart[${entry.key}] => $selected');
    }
    swValidation.stop();
    final rssAfterAll = ProcessInfo.currentRss;

    loadTimesMs.add(swLoad.elapsedMilliseconds);
    validationTimesMs.add(swValidation.elapsedMilliseconds);
    rssLoadDeltaBytes.add(rssAfterLoad - rssBefore);
    rssTotalDeltaBytes.add(rssAfterAll - rssBefore);

    stdout.writeln(
      'run $i: load=${swLoad.elapsedMilliseconds} ms, '
      'validate=${swValidation.elapsedMilliseconds} ms, '
      'rssLoadDelta=${_fmtBytes(rssAfterLoad - rssBefore)}, '
      'rssTotalDelta=${_fmtBytes(rssAfterAll - rssBefore)}',
    );
  }
  stdout.writeln('');

  return _ScenarioResult(
    name: name,
    certCount: certCount,
    loadTimesMs: loadTimesMs,
    validationTimesMs: validationTimesMs,
    rssLoadDeltaBytes: rssLoadDeltaBytes,
    rssTotalDeltaBytes: rssTotalDeltaBytes,
    signaturesByPdf: signaturesByPdf,
    validByPdf: validByPdf,
  );
}

Future<_ScenarioResult> _runScenarioClassic({
  required String name,
  required int runs,
  required Future<List<Uint8List>> Function() loadRoots,
  required Map<String, Uint8List> pdfBytesByPath,
}) async {
  final validator = PdfSignatureValidator();
  final loadTimesMs = <int>[];
  final validationTimesMs = <int>[];
  final rssLoadDeltaBytes = <int>[];
  final rssTotalDeltaBytes = <int>[];
  var certCount = 0;
  final signaturesByPdf = <String, int>{};
  final validByPdf = <String, int>{};

  stdout.writeln('== $name ==');
  for (var i = 1; i <= runs; i++) {
    final rssBefore = ProcessInfo.currentRss;

    final swLoad = Stopwatch()..start();
    final roots = await loadRoots();
    swLoad.stop();
    certCount = roots.length;
    final rssAfterLoad = ProcessInfo.currentRss;

    final provider = PdfInMemoryTrustedRootsProvider(roots);
    final swValidation = Stopwatch()..start();
    for (final entry in pdfBytesByPath.entries) {
      final report = await validator.validateAllSignatures(
        entry.value,
        trustedRootsProvider: provider,
        includeCertificates: false,
        includeSignatureFields: true,
      );
      signaturesByPdf[entry.key] = report.signatures.length;
      validByPdf[entry.key] = report.signatures
          .where((s) => s.cmsValid && s.digestValid && s.intact)
          .length;
    }
    swValidation.stop();
    final rssAfterAll = ProcessInfo.currentRss;

    loadTimesMs.add(swLoad.elapsedMilliseconds);
    validationTimesMs.add(swValidation.elapsedMilliseconds);
    rssLoadDeltaBytes.add(rssAfterLoad - rssBefore);
    rssTotalDeltaBytes.add(rssAfterAll - rssBefore);

    stdout.writeln(
      'run $i: load=${swLoad.elapsedMilliseconds} ms, '
      'validate=${swValidation.elapsedMilliseconds} ms, '
      'rssLoadDelta=${_fmtBytes(rssAfterLoad - rssBefore)}, '
      'rssTotalDelta=${_fmtBytes(rssAfterAll - rssBefore)}',
    );
  }
  stdout.writeln('');

  return _ScenarioResult(
    name: name,
    certCount: certCount,
    loadTimesMs: loadTimesMs,
    validationTimesMs: validationTimesMs,
    rssLoadDeltaBytes: rssLoadDeltaBytes,
    rssTotalDeltaBytes: rssTotalDeltaBytes,
    signaturesByPdf: signaturesByPdf,
    validByPdf: validByPdf,
  );
}

void _printSummary(_ScenarioResult a, _ScenarioResult b) {
  void printScenario(_ScenarioResult r) {
    stdout.writeln('--- ${r.name} summary ---');
    stdout.writeln('certificados carregados: ${r.certCount}');
    stdout.writeln(
      'load: avg=${_avg(r.loadTimesMs).toStringAsFixed(1)} ms, '
      'min=${r.loadTimesMs.reduce((x, y) => x < y ? x : y)} ms',
    );
    stdout.writeln(
      'validate: avg=${_avg(r.validationTimesMs).toStringAsFixed(1)} ms, '
      'min=${r.validationTimesMs.reduce((x, y) => x < y ? x : y)} ms',
    );
    stdout.writeln(
      'rss load delta avg=${_fmtBytes(_avgInt(r.rssLoadDeltaBytes))}, '
      'rss total delta avg=${_fmtBytes(_avgInt(r.rssTotalDeltaBytes))}',
    );
    for (final entry in r.signaturesByPdf.entries) {
      final ok = r.validByPdf[entry.key] ?? 0;
      stdout.writeln('  ${entry.key}: assinaturas=$ok/${entry.value} validas');
    }
    stdout.writeln('');
  }

  printScenario(a);
  printScenario(b);

  final loadWinner = _avg(a.loadTimesMs) <= _avg(b.loadTimesMs) ? a : b;
  final validateWinner =
      _avg(a.validationTimesMs) <= _avg(b.validationTimesMs) ? a : b;
  final memWinner =
      _avgInt(a.rssTotalDeltaBytes) <= _avgInt(b.rssTotalDeltaBytes) ? a : b;

  stdout.writeln('=== Resultado objetivo ===');
  stdout.writeln('Mais rapido para abrir truststore: ${loadWinner.name}');
  stdout.writeln('Mais rapido na validacao (roots + PDF): ${validateWinner.name}');
  stdout.writeln('Menor impacto de memoria (RSS delta medio): ${memWinner.name}');
}

Future<void> _printFunctionalReportSmart(
  String truststoreName,
  _SmartContext context,
  Map<String, Uint8List> pdfBytesByPath,
) async {
  final inspector = PdfSecurityInspector();

  stdout.writeln('');
  stdout.writeln('=== Relatorio funcional ($truststoreName) ===');
  for (final entry in pdfBytesByPath.entries) {
    final pdfPath = entry.key;
    final bytes = entry.value;
    final fileName = File(pdfPath).uri.pathSegments.last;

    final security = await inspector.inspect(
      bytes,
      validateSignatures: true,
      includeSha256: true,
    );

    final result = await context.validator.validateAllSignatures(
      bytes,
      rootsSelector: context.selector,
      includeCertificates: true,
      includeSignatureFields: true,
    );

    final selectedStores = _formatSelectedStores(
      result.rootsSelection.selectedSourceIds,
      context.sourceLabels,
    );

    final report = result.report;
    final pdfIntegrity = security.isPdf &&
        !security.isCorrupted &&
        security.hasValidByteRanges &&
        (security.allSignaturesIntact ?? true);
    final approvedCount = report.signatures
        .where((s) => s.validationStatus == PdfSignatureValidationStatus.approved)
        .length;

    stdout.writeln('');
    stdout.writeln('Arquivo: $fileName');
    stdout.writeln('Truststores selecionados: $selectedStores');
    stdout.writeln('SHA-256: ${security.sha256Hex ?? '-'}');
    stdout.writeln('PDF valido: ${security.isPdf ? 'sim' : 'nao'}');
    stdout.writeln('Integridade do PDF: ${pdfIntegrity ? 'integro' : 'comprometido'}');
    stdout.writeln(
      'Assinaturas aprovadas: $approvedCount/${report.signatures.length}',
    );

    for (var i = 0; i < report.signatures.length; i++) {
      final sig = report.signatures[i];
      final signer = sig.signerCertificate;
      final signerName =
          _extractSignerName(signer) ?? sig.signatureField?.name ?? '-';
      final cpf = signer?.icpBrasilIds?.cpf;
      final serialHex = signer?.serial?.toRadixString(16);
      final signingTime = sig.signingTime?.toUtc().toIso8601String() ?? '-';
      final approvedText = _statusLabel(sig.validationStatus);

      stdout.writeln('  Assinatura #${i + 1}: $approvedText');
      stdout.writeln('    Signatario: $signerName');
      if (cpf != null && cpf.isNotEmpty) {
        stdout.writeln('    CPF: $cpf');
      }
      if (serialHex != null) {
        stdout.writeln('    Serie cert: 0x$serialHex');
      }
      stdout.writeln('    Data assinatura: $signingTime');
      stdout.writeln(
        '    Checks: intact=${sig.intact} digest=${sig.digestValid} cms=${sig.cmsValid} chain=${sig.chainTrusted} cert=${sig.certValid}',
      );
      if (sig.message != null && sig.message!.trim().isNotEmpty) {
        stdout.writeln('    Motivo: ${_sanitizeMessage(sig.message!)}');
      }
    }
  }
}

Future<void> _printFunctionalReport(
  String truststoreName,
  List<Uint8List> roots,
  Map<String, Uint8List> pdfBytesByPath,
) async {
  final validator = PdfSignatureValidator();
  final inspector = PdfSecurityInspector();
  final provider = PdfInMemoryTrustedRootsProvider(roots);

  stdout.writeln('');
  stdout.writeln('=== Relatorio funcional ($truststoreName) ===');
  for (final entry in pdfBytesByPath.entries) {
    final pdfPath = entry.key;
    final bytes = entry.value;
    final fileName = File(pdfPath).uri.pathSegments.last;

    final security = await inspector.inspect(
      bytes,
      validateSignatures: true,
      includeSha256: true,
    );
    final report = await validator.validateAllSignatures(
      bytes,
      trustedRootsProvider: provider,
      includeCertificates: true,
      includeSignatureFields: true,
    );

    final pdfIntegrity = security.isPdf &&
        !security.isCorrupted &&
        security.hasValidByteRanges &&
        (security.allSignaturesIntact ?? true);
    final approvedCount = report.signatures
        .where((s) => s.validationStatus == PdfSignatureValidationStatus.approved)
        .length;

    stdout.writeln('');
    stdout.writeln('Arquivo: $fileName');
    stdout.writeln('SHA-256: ${security.sha256Hex ?? '-'}');
    stdout.writeln('PDF valido: ${security.isPdf ? 'sim' : 'nao'}');
    stdout.writeln('Integridade do PDF: ${pdfIntegrity ? 'integro' : 'comprometido'}');
    stdout.writeln(
      'Assinaturas aprovadas: $approvedCount/${report.signatures.length}',
    );

    for (var i = 0; i < report.signatures.length; i++) {
      final sig = report.signatures[i];
      final signer = sig.signerCertificate;
      final signerName =
          _extractSignerName(signer) ?? sig.signatureField?.name ?? '-';
      final cpf = signer?.icpBrasilIds?.cpf;
      final serialHex = signer?.serial?.toRadixString(16);
      final signingTime = sig.signingTime?.toUtc().toIso8601String() ?? '-';
      final approvedText = _statusLabel(sig.validationStatus);

      stdout.writeln('  Assinatura #${i + 1}: $approvedText');
      stdout.writeln('    Signatario: $signerName');
      if (cpf != null && cpf.isNotEmpty) {
        stdout.writeln('    CPF: $cpf');
      }
      if (serialHex != null) {
        stdout.writeln('    Serie cert: 0x$serialHex');
      }
      stdout.writeln('    Data assinatura: $signingTime');
      stdout.writeln(
        '    Checks: intact=${sig.intact} digest=${sig.digestValid} cms=${sig.cmsValid} chain=${sig.chainTrusted} cert=${sig.certValid}',
      );
      if (sig.message != null && sig.message!.trim().isNotEmpty) {
        stdout.writeln('    Motivo: ${_sanitizeMessage(sig.message!)}');
      }
    }
  }
}

void _printHelp() {
  stdout.writeln('Uso: dart run tool/benchmark_truststore_validation.dart [opcoes]');
  stdout.writeln('  --runs <n>         Numero de repeticoes (padrao: 3)');
  stdout.writeln('  --smart-roots      Seleciona truststore por PDF (padrao)');
  stdout.writeln('  --no-smart-roots   Usa roots mescladas por formato');
  stdout.writeln('  --jks <path>       Define JKS principal (substitui defaults)');
  stdout.writeln('  --jks-add <path>   Acrescenta JKS para merge/selecao');
  stdout.writeln('  --bks <path>       Define BKS principal (substitui defaults)');
  stdout.writeln('  --bks-add <path>   Acrescenta BKS para merge/selecao');
  stdout.writeln('  --jks-pass <pass>  Senha JKS');
  stdout.writeln('  --bks-pass <pass>  Senha BKS');
  stdout.writeln('  --pdf <path>       Adiciona PDF para teste (pode repetir)');
}

String _sanitizeMessage(String input) {
  final normalized = input.replaceAll('\r', '').trim();
  if (normalized.isEmpty) return '-';
  final firstLine = normalized.split('\n').first.trim();
  if (firstLine.isEmpty) return '-';
  return firstLine.length > 220 ? '${firstLine.substring(0, 220)}...' : firstLine;
}

String _formatSelectedStores(
  List<String> selectedSourceIds,
  Map<String, String> sourceLabels,
) {
  final values = selectedSourceIds
      .map((id) => (sourceLabels[id] ?? id).trim())
      .where((v) => v.isNotEmpty)
      .map((p) => File(p).uri.pathSegments.last.trim())
      .where((v) => v.isNotEmpty)
      .toSet()
      .toList(growable: false);
  if (values.isEmpty) return '-';
  return values.join(', ');
}

String _statusLabel(PdfSignatureValidationStatus status) {
  switch (status) {
    case PdfSignatureValidationStatus.approved:
      return 'Assinatura aprovada';
    case PdfSignatureValidationStatus.indeterminate:
      return 'Assinatura indeterminada';
    case PdfSignatureValidationStatus.rejected:
      return 'Assinatura reprovada';
  }
}

String? _extractSignerName(PdfSignatureCertificateInfo? cert) {
  final subject = cert?.subject;
  if (subject == null || subject.isEmpty) return null;
  final parts = subject.split(',');
  for (final raw in parts) {
    final p = raw.trim();
    if (p.startsWith('CN=')) return p.substring(3);
  }
  return subject;
}

double _avg(List<int> values) =>
    values.isEmpty ? 0 : values.reduce((a, b) => a + b) / values.length;

int _avgInt(List<int> values) =>
    values.isEmpty ? 0 : (values.reduce((a, b) => a + b) ~/ values.length);

String _fmtBytes(int bytes) {
  final sign = bytes < 0 ? '-' : '';
  final b = bytes.abs();
  if (b < 1024) return '$sign$b B';
  if (b < 1024 * 1024) return '$sign${(b / 1024).toStringAsFixed(1)} KiB';
  return '$sign${(b / (1024 * 1024)).toStringAsFixed(2)} MiB';
}

class _ScenarioResult {
  const _ScenarioResult({
    required this.name,
    required this.certCount,
    required this.loadTimesMs,
    required this.validationTimesMs,
    required this.rssLoadDeltaBytes,
    required this.rssTotalDeltaBytes,
    required this.signaturesByPdf,
    required this.validByPdf,
  });

  final String name;
  final int certCount;
  final List<int> loadTimesMs;
  final List<int> validationTimesMs;
  final List<int> rssLoadDeltaBytes;
  final List<int> rssTotalDeltaBytes;
  final Map<String, int> signaturesByPdf;
  final Map<String, int> validByPdf;
}

class _SmartContext {
  const _SmartContext({
    required this.selector,
    required this.validator,
    required this.sourceLabels,
    required this.certCount,
  });

  final PdfSmartTrustedRootsSelector selector;
  final PdfSmartSignatureValidator validator;
  final Map<String, String> sourceLabels;
  final int certCount;
}
