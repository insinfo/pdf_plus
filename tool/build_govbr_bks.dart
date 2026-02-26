import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pki.dart';

const String _defaultInputDir = r'test/assets/truststore/gov.br';
const String _defaultOutputFile = r'test/assets/truststore/gov.br/cadeia_govbr_unica.bks';
const String _defaultPassword = 'serprosigner';

void main(List<String> args) {
  var inputDir = _defaultInputDir;
  var outputFile = _defaultOutputFile;
  var password = _defaultPassword;

  for (var i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--input':
        inputDir = args[++i];
        break;
      case '--output':
        outputFile = args[++i];
        break;
      case '--password':
        password = args[++i];
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

  final dir = Directory(inputDir);
  if (!dir.existsSync()) {
    stderr.writeln('Diretorio nao encontrado: $inputDir');
    exitCode = 2;
    return;
  }

  final entries = <String, KeystoreEntry>{};
  final seenDerBlobs = <String>{};
  final ignoredFiles = <String>[];
  final loadedFiles = <String>[];

  for (final entity in dir.listSync(recursive: true)) {
    if (entity is! File) continue;
    final path = entity.path;
    final lower = path.toLowerCase();

    if (lower.endsWith('.p7b') || lower.endsWith('.p7c')) {
      ignoredFiles.add('$path (PKCS#7 .p7b/.p7c nao processado neste script)');
      continue;
    }

    if (!(lower.endsWith('.pem') ||
        lower.endsWith('.crt') ||
        lower.endsWith('.cer') ||
        lower.endsWith('.der'))) {
      continue;
    }

    final bytes = entity.readAsBytesSync();
    final ders = _extractDerCertificates(bytes);
    if (ders.isEmpty) {
      ignoredFiles.add('$path (nenhum certificado X.509 encontrado)');
      continue;
    }

    loadedFiles.add(path);
    for (final der in ders) {
      final derKey = base64Encode(der);
      if (!seenDerBlobs.add(derKey)) {
        continue;
      }

      X509Certificate cert;
      try {
        cert = X509Certificate.fromDer(der);
      } catch (_) {
        ignoredFiles.add('$path (blob DER invalido)');
        continue;
      }

      final baseAlias = _buildAlias(cert);
      final alias = _uniqueAlias(baseAlias, entries);
      entries[alias] = BksTrustedCertEntry(
        alias: alias,
        timestamp: DateTime.now().millisecondsSinceEpoch,
        storeType: 'bks',
        certType: 'X.509',
        certData: Uint8List.fromList(der),
      );
    }
  }

  if (entries.isEmpty) {
    stderr.writeln('Nenhum certificado valido encontrado em: $inputDir');
    for (final item in ignoredFiles) {
      stderr.writeln('  - $item');
    }
    exitCode = 1;
    return;
  }

  final store = BksKeyStore('bks', entries, version: 2);
  final bksBytes = store.save(password);

  final out = File(outputFile);
  out.parent.createSync(recursive: true);
  out.writeAsBytesSync(bksBytes, flush: true);

  // Sanity-check reload.
  final reloaded = BksKeyStore.load(
    bksBytes,
    storePassword: password,
    tryDecryptKeys: false,
  );

  stdout.writeln('BKS gerado com sucesso.');
  stdout.writeln('Entrada:  $inputDir');
  stdout.writeln('Saida:    $outputFile');
  stdout.writeln('Senha:    $password');
  stdout.writeln('Arquivos lidos: ${loadedFiles.length}');
  stdout.writeln('Certificados unicos: ${entries.length}');
  stdout.writeln('Certificados recarregados: ${reloaded.certs.length}');

  if (ignoredFiles.isNotEmpty) {
    stdout.writeln('Arquivos/itens ignorados:');
    for (final item in ignoredFiles) {
      stdout.writeln('  - $item');
    }
  }
}

List<Uint8List> _extractDerCertificates(Uint8List bytes) {
  final text = _tryDecodeText(bytes);
  if (text != null && text.contains('-----BEGIN CERTIFICATE-----')) {
    final re = RegExp(
      r'-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----',
      multiLine: true,
    );
    final out = <Uint8List>[];
    for (final m in re.allMatches(text)) {
      final b64 = (m.group(1) ?? '').replaceAll(RegExp(r'\s+'), '');
      if (b64.isEmpty) continue;
      try {
        out.add(Uint8List.fromList(base64.decode(b64)));
      } catch (_) {
        // ignore malformed block
      }
    }
    return out;
  }

  // Try as a single DER certificate.
  try {
    X509Certificate.fromDer(bytes);
    return <Uint8List>[bytes];
  } catch (_) {
    return const <Uint8List>[];
  }
}

String? _tryDecodeText(Uint8List bytes) {
  try {
    return utf8.decode(bytes, allowMalformed: true);
  } catch (_) {
    return null;
  }
}

String _buildAlias(X509Certificate cert) {
  final cn = cert.subject.commonName ?? cert.subject.toString();
  final normalized = cn
      .toLowerCase()
      .replaceAll(RegExp(r'[^a-z0-9]+'), '_')
      .replaceAll(RegExp(r'_+'), '_')
      .replaceAll(RegExp(r'^_|_$'), '');
  final serial = cert.serialNumberHex.toLowerCase();
  final shortSerial = serial.length > 12 ? serial.substring(serial.length - 12) : serial;
  final prefix = normalized.isEmpty ? 'cert' : normalized;
  return '${prefix}_$shortSerial';
}

String _uniqueAlias(String base, Map<String, KeystoreEntry> entries) {
  if (!entries.containsKey(base)) return base;
  var i = 2;
  while (entries.containsKey('${base}_$i')) {
    i++;
  }
  return '${base}_$i';
}

void _printHelp() {
  stdout.writeln('Uso: dart run tool/build_govbr_bks.dart [opcoes]');
  stdout.writeln('  --input <dir>      Pasta de origem (padrao: $_defaultInputDir)');
  stdout.writeln('  --output <file>    Arquivo BKS de saida (padrao: $_defaultOutputFile)');
  stdout.writeln('  --password <pass>  Senha do BKS (padrao: $_defaultPassword)');
}
