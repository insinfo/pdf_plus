import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:pdf_plus/src/pki/pki_jks_utils.dart';

// dart tool/iti_report.dart test\assets\pdfs\sample_token_icpbrasil_assinado.pdf
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
  final lpaResult = await _loadLpa();

  final report = await PdfSignatureValidator().validateAllSignatures(
    pdfBytes,
    trustedRootsProvider: roots.isEmpty ? null : _InMemoryRootsProvider(roots),
    certificateFetcher: const PdfHttpFetcher(),
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
    lpa: lpaResult.lpa,
    lpaName: lpaResult.name,
    lpaOnline: lpaResult.online,
    paOnline: false,
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
    if (lower.endsWith('.jks')) {
      final result = parseJksCertificates(bytes, password: '12345678');
      roots.addAll(result.certificates);
      continue;
    }
    if (lower.endsWith('.crt') ||
        lower.endsWith('.cer') ||
        lower.endsWith('.der')) {
      roots.add(bytes);
    }
  }
  return roots;
}

Future<_LpaLoadResult> _loadLpa() async {
  final cades = await _tryLoadLpa(
    url: 'http://politicas.icpbrasil.gov.br/LPA_CAdES.der',
    filePath: 'test/assets/policy/engine/artifacts/LPA_CAdES.der',
  );
  final pades = await _tryLoadLpa(
    url: 'http://politicas.icpbrasil.gov.br/LPA_PAdES.der',
    filePath: 'test/assets/policy/engine/artifacts/LPA_PAdES.der',
  );

  final policies = <PdfLpaPolicyInfo>[];
  if (cades.lpa != null) {
    policies.addAll(cades.lpa!.policies);
  }
  if (pades.lpa != null) {
    final existing = policies.map((p) => p.policyOid).toSet();
    for (final policy in pades.lpa!.policies) {
      if (existing.add(policy.policyOid)) {
        policies.add(policy);
      }
    }
  }

  final mergedLpa = policies.isEmpty
      ? null
      : PdfLpa(
          policies: policies,
          version: cades.lpa?.version ?? pades.lpa?.version,
          nextUpdate: cades.lpa?.nextUpdate ?? pades.lpa?.nextUpdate,
        );

  final name = cades.lpa != null
      ? 'LPA CAdES v2'
      : (pades.lpa != null ? 'LPA PAdES' : 'LPA CAdES v2');
  final online = cades.online || pades.online;

  return _LpaLoadResult(lpa: mergedLpa, online: online, name: name);
}

Future<_LpaLoadResult> _tryLoadLpa({
  required String url,
  required String filePath,
}) async {
  try {
    final client = HttpClient();
    final req = await client.getUrl(Uri.parse(url));
    final res = await req.close();
    if (res.statusCode >= 200 && res.statusCode < 300) {
      final bytes = await res.fold<List<int>>(<int>[], (p, e) => p..addAll(e));
      if (bytes.isNotEmpty) {
        final parsed = PdfLpa.parse(Uint8List.fromList(bytes));
        if (parsed.policies.isNotEmpty) {
          return _LpaLoadResult(
            lpa: parsed,
            online: true,
            name: url,
          );
        }
        return _LpaLoadResult(
          lpa: parsed,
          online: true,
          name: url,
        );
      }
    }
  } catch (_) {}

  final lpaFile = File(filePath);
  if (lpaFile.existsSync()) {
    final bytes = lpaFile.readAsBytesSync();
    return _LpaLoadResult(
      lpa: PdfLpa.parse(bytes),
      online: false,
      name: filePath,
    );
  }

  return const _LpaLoadResult(lpa: null, online: false, name: '');
}

class _LpaLoadResult {
  const _LpaLoadResult({
    required this.lpa,
    required this.online,
    required this.name,
  });

  final PdfLpa? lpa;
  final bool online;
  final String name;
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
