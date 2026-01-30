import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';

void main(List<String> args) async {
  if (args.isEmpty) {
    stderr.writeln('Uso: dart tool/iti_report.dart <arquivo.pdf>');
    exitCode = 2;
    return;
  }

  final path = args.join(' ');
  final file = File(path);
  if (!file.existsSync()) {
    stderr.writeln('Arquivo não encontrado: $path');
    exitCode = 2;
    return;
  }

  final pdfBytes = file.readAsBytesSync();
  final roots = _loadTrustedRoots();

  final report = await PdfSignatureValidator().validateAllSignatures(
    pdfBytes,
    trustedRootsProvider: roots.isEmpty ? null : _InMemoryRootsProvider(roots),
    includeCertificates: true,
    includeSignatureFields: true,
  );

  final compliance = PdfItiComplianceReport.fromValidation(
    pdfBytes: pdfBytes,
    validationReport: report,
    metadata: PdfItiComplianceMetadata(
      name: 'Validar',
      validationDate: DateTime.now(),
      verifierVersion: '2.21.1.2',
      validatorVersion: '3.0.5.2',
      verificationSource: 'Offline',
    ),
    fileName: file.uri.pathSegments.isNotEmpty
        ? file.uri.pathSegments.last
        : file.path,
  );

  stdout.writeln(compliance.toText());
}

class _InMemoryRootsProvider implements TrustedRootsProvider {
  _InMemoryRootsProvider(this._roots);

  final List<Uint8List> _roots;

  @override
  Future<List<Uint8List>> getTrustedRootsDer() async => _roots;
}

List<Uint8List> _loadTrustedRoots() {
  final dir = Directory('test/assets/truststore');
  if (!dir.existsSync()) return <Uint8List>[];
  final roots = <Uint8List>[];
  for (final entity in dir.listSync(recursive: true)) {
    if (entity is! File) continue;
    final bytes = entity.readAsBytesSync();
    if (_looksLikePem(bytes)) {
      roots.addAll(_pemBlocksToDer(bytes));
      continue;
    }
    final lower = entity.path.toLowerCase();
    if (lower.endsWith('.crt') ||
        lower.endsWith('.cer') ||
        lower.endsWith('.der')) {
      roots.add(bytes);
    }
  }
  return roots;
}

bool _looksLikePem(Uint8List bytes) {
  final text = String.fromCharCodes(bytes);
  return text.contains('-----BEGIN CERTIFICATE-----');
}

List<Uint8List> _pemBlocksToDer(Uint8List bytes) {
  final text = String.fromCharCodes(bytes);
  final re = RegExp(
    '-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----',
    multiLine: true,
  );
  final out = <Uint8List>[];
  for (final m in re.allMatches(text)) {
    final body = (m.group(1) ?? '').replaceAll(RegExp(r'\s+'), '');
    if (body.isEmpty) continue;
    out.add(Uint8List.fromList(base64.decode(body)));
  }
  return out;
}
