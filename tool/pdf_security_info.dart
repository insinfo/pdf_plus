import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:pdf_plus/src/pdf/crypto/pdf_crypto.dart';
import 'package:pdf_plus/src/pdf/io/pdf_random_access_reader_io.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_fields.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_misc.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_xref.dart';

Future<void> main(List<String> args) async {
  final stopwatch = Stopwatch()..start();
  if (args.isEmpty) {
    _printUsage();
    exitCode = 2;
    return;
  }

  var includeSha256 = false;
  var validateSignatures = false;
  var deepSignatures = false;
  final pathParts = <String>[];

  for (final arg in args) {
    switch (arg) {
      case '--sha256':
        includeSha256 = true;
        break;
      case '--validate-signatures':
        validateSignatures = true;
        break;
      case '--deep-signatures':
        deepSignatures = true;
        break;
      case '--help':
      case '-h':
        _printUsage();
        return;
      default:
        pathParts.add(arg);
    }
  }

  if (pathParts.isEmpty) {
    stderr.writeln('Arquivo PDF não informado.');
    _printUsage();
    exitCode = 2;
    return;
  }

  final path = pathParts.join(' ');
  final file = File(path);
  if (!file.existsSync()) {
    stderr.writeln('Arquivo não encontrado: $path');
    exitCode = 2;
    return;
  }

  late PdfSecurityInspectionResult result;
  try {
    result = await _inspectFromFile(
      file,
      validateSignatures: validateSignatures,
      deepSignatures: deepSignatures,
    );
  } catch (e) {
    stderr.writeln('Falha ao inspecionar PDF: $e');
    exitCode = 1;
    return;
  }

  if (includeSha256) {
    final hex = await _sha256FileHex(file);
    result = PdfSecurityInspectionResult(
      isPdf: result.isPdf,
      isEncrypted: result.isEncrypted,
      isSigned: result.isSigned,
      isCorrupted: result.isCorrupted,
      signatureCount: result.signatureCount,
      pdfVersion: result.pdfVersion,
      startXref: result.startXref,
      hasEofMarker: result.hasEofMarker,
      hasValidByteRanges: result.hasValidByteRanges,
      issues: result.issues,
      subFilters: result.subFilters,
      supportedSubFilters: result.supportedSubFilters,
      allSignaturesIntact: result.allSignaturesIntact,
      sha256Hex: hex,
    );
  }

  stopwatch.stop();
  _printReport(path, file.lengthSync(), result, validateSignatures);
  stdout.writeln('Tempo de execucao: ${_formatElapsed(stopwatch.elapsed)}');
}

Future<PdfSecurityInspectionResult> _inspectFromFile(
  File file, {
  required bool validateSignatures,
  required bool deepSignatures,
}) async {
  final reader = PdfRandomAccessFileReader.openSync(file);
  try {
    final len = reader.length;
    final head = reader.readRange(0, len > 1024 ? 1024 : len);
    final tail8k = reader.readRange(
      len > 8 * 1024 ? len - 8 * 1024 : 0,
      len > 8 * 1024 ? 8 * 1024 : len,
    );
    final tail2m = reader.readRange(
      len > 2 * 1024 * 1024 ? len - 2 * 1024 * 1024 : 0,
      len > 2 * 1024 * 1024 ? 2 * 1024 * 1024 : len,
    );

    final isPdf = PdfParserFields.hasPdfHeader(head);
    final version = PdfParserFields.readPdfVersion(head);
    final hasEof = PdfParserFields.hasEofMarker(tail8k);
    final isEncrypted = PdfParserFields.hasEncryptDictionary(tail2m);

    var startXref = PdfParserXref.findStartXrefFromReader(reader);
    var repairUsed = false;
    if (startXref <= 0 || startXref >= len) {
      final repaired = PdfParserXref.computeXrefOffsetFromReader(reader);
      if (repaired > 0 && repaired < len) {
        startXref = repaired;
        repairUsed = true;
      }
    }

    final tailSigWindowSize = len > 32 * 1024 * 1024 ? 32 * 1024 * 1024 : len;
    final tailSigBytes = reader.readRange(len - tailSigWindowSize, tailSigWindowSize);
    final quickRanges = PdfParserMisc.findAllByteRangesFromBytes(tailSigBytes);
    final quickSubFilters = _extractSubFiltersFast(tailSigBytes);

    var signatureCount = quickRanges.length;
    var isSigned = signatureCount > 0;
    var subFilters = quickSubFilters.toSet().toList(growable: false);
    var hasValidByteRanges = quickRanges.every((r) => _isByteRangeValid(len, r));

    if (deepSignatures || validateSignatures) {
      final parser = PdfDocumentParser.fromReader(reader, allowRepair: true);
      final sigFields = parser.extractSignatureFields();
      signatureCount = sigFields.length;
      isSigned = signatureCount > 0;
      subFilters = sigFields
          .map((f) => (f.subFilter ?? '').trim())
          .where((v) => v.isNotEmpty)
          .map((v) => v.startsWith('/') ? v.substring(1) : v)
          .toSet()
          .toList(growable: false);
      hasValidByteRanges = sigFields.every((f) {
        final range = f.byteRange;
        if (range == null) return true;
        return _isByteRangeValid(len, range);
      });
    }
    final supportedSubFilters = subFilters.every(_isSupportedSubFilter);

    bool? allSignaturesIntact;
    if (validateSignatures && isSigned) {
      final bytes = reader.readAll();
      final report = await PdfSignatureValidator().validateAllSignatures(
        bytes,
        includeCertificates: false,
        includeSignatureFields: false,
      );
      allSignaturesIntact = report.signatures.isNotEmpty &&
          report.signatures.every((sig) => sig.intact);
    }

    final issues = <String>[];
    if (!isPdf) issues.add('Cabecalho %PDF- ausente.');
    if (!hasEof) issues.add('Marcador %%EOF ausente.');
    if (startXref <= 0) {
      issues.add('startxref ausente ou invalido.');
    } else if (repairUsed) {
      issues.add(
        'startxref ausente ou invalido; xref localizado por varredura (modo reparo).',
      );
    }
    if (startXref >= len) {
      issues.add('startxref fora dos limites do arquivo.');
    }
    if (!hasValidByteRanges) {
      issues.add('ByteRange inconsistente com o tamanho do arquivo.');
    }
    if (isSigned && subFilters.isEmpty) {
      issues.add('SubFilter ausente em assinatura PDF.');
    }
    if (!supportedSubFilters) {
      issues.add('SubFilter não suportado detectado.');
    }
    if (allSignaturesIntact == false) {
      issues.add('Assinatura presente, mas integridade do documento falhou.');
    }

    return PdfSecurityInspectionResult(
      isPdf: isPdf,
      isEncrypted: isEncrypted,
      isSigned: isSigned,
      isCorrupted: issues.isNotEmpty,
      signatureCount: signatureCount,
      pdfVersion: version,
      startXref: startXref,
      hasEofMarker: hasEof,
      hasValidByteRanges: hasValidByteRanges,
      issues: List.unmodifiable(issues),
      subFilters: List.unmodifiable(subFilters),
      supportedSubFilters: supportedSubFilters,
      allSignaturesIntact: allSignaturesIntact,
      sha256Hex: null,
    );
  } finally {
    reader.close();
  }
}

Future<String> _sha256FileHex(File file) async {
  final bytes = await file.readAsBytes();
  return _bytesToHex(PdfCrypto.sha256(bytes));
}

void _printUsage() {
  stdout.writeln(
    'Uso: dart run tool/pdf_security_info.dart [--sha256] [--validate-signatures] [--deep-signatures] <arquivo.pdf>',
  );
}

void _printReport(
  String path,
  int fileSize,
  PdfSecurityInspectionResult result,
  bool validateSignatures,
) {
  stdout.writeln(path);
  stdout.writeln('Tamanho: $fileSize bytes');
  stdout.writeln('PDF: ${result.isPdf ? "sim" : "nao"}');
  stdout.writeln('Versao PDF: ${result.pdfVersion.toStringAsFixed(1)}');
  stdout.writeln('Encriptado: ${result.isEncrypted ? "sim" : "nao"}');
  stdout.writeln('Assinado: ${result.isSigned ? "sim" : "nao"}');
  stdout.writeln('Qtd. assinaturas: ${result.signatureCount}');
  stdout.writeln('startxref: ${result.startXref}');
  stdout.writeln('Tem %%EOF: ${result.hasEofMarker ? "sim" : "nao"}');
  stdout.writeln(
    'ByteRange valido: ${result.hasValidByteRanges ? "sim" : "nao"}',
  );

  if (result.subFilters.isNotEmpty) {
    stdout.writeln('SubFilters: ${result.subFilters.join(", ")}');
    stdout.writeln(
      'SubFilters suportados: ${result.supportedSubFilters ? "sim" : "nao"}',
    );
  }

  if (validateSignatures && result.isSigned) {
    final status = result.allSignaturesIntact == true ? 'ok' : 'falhou';
    stdout.writeln('Integridade das assinaturas: $status');
  }

  if (result.sha256Hex != null) {
    stdout.writeln('SHA-256: ${result.sha256Hex}');
  }

  stdout.writeln('Corrompido: ${result.isCorrupted ? "sim" : "nao"}');
  if (result.issues.isNotEmpty) {
    stdout.writeln('Issues:');
    for (final issue in result.issues) {
      stdout.writeln('  - $issue');
    }
  }
}

String _formatElapsed(Duration elapsed) {
  if (elapsed.inMilliseconds < 1000) {
    return '${elapsed.inMilliseconds} ms';
  }
  final seconds = elapsed.inMilliseconds / 1000.0;
  return '${seconds.toStringAsFixed(3)} s';
}

bool _isByteRangeValid(int fileLength, List<int> range) {
  if (range.length != 4) return false;
  final a = range[0];
  final b = range[1];
  final c = range[2];
  final d = range[3];
  if (a < 0 || b < 0 || c < 0 || d < 0) return false;
  if (a + b > c) return false;
  if (c + d > fileLength) return false;
  return true;
}

bool _isSupportedSubFilter(String value) {
  final normalized = value.trim().toLowerCase();
  return normalized == 'adbe.pkcs7.detached' ||
      normalized == 'etsi.cades.detached';
}

List<String> _extractSubFiltersFast(Uint8List bytes) {
  final text = String.fromCharCodes(bytes);
  return RegExp(r'/SubFilter\s*/([A-Za-z0-9.]+)')
      .allMatches(text)
      .map((m) => m.group(1))
      .whereType<String>()
      .toList(growable: false);
}

String _bytesToHex(Uint8List bytes) {
  final out = StringBuffer();
  for (final b in bytes) {
    out.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return out.toString();
}
