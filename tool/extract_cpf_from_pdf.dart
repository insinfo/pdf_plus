import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';

const _oidCpf = '2.16.76.1.3.1';
const _oidCpfResponsavel = '2.16.76.1.3.4';

Future<void> main(List<String> args) async {
  final defaultPaths = <String>[
    r'C:\MyDartProjects\pdf_plus\test\assets\pdfs\sample_govbr_signature_assinado.pdf',
    r'C:\MyDartProjects\pdf_plus\test\assets\pdfs\sample_token_icpbrasil_assinado.pdf',
  ];

  final paths = args.isNotEmpty ? args : defaultPaths;
  for (final path in paths) {
    await _processPdf(path);
  }
}

Future<void> _processPdf(String filePath) async {
  final file = File(filePath);
  if (!file.existsSync()) {
    // ignore: avoid_print
    print('Arquivo não encontrado: $filePath');
    return;
  }

  // ignore: avoid_print
  print('\n==> $filePath');
  final Uint8List bytes = file.readAsBytesSync();
  final PdfSignatureValidator validator = PdfSignatureValidator();
  final report = await validator.validateAllSignatures(
    bytes,
    fetchCrls: false,
    includeCertificates: true,
    includeSignatureFields: true,
  );

  // ignore: avoid_print
  print('Assinaturas encontradas: ${report.signatures.length}');
  for (int i = 0; i < report.signatures.length; i++) {
    final sig = report.signatures[i];
    final fieldName = sig.signatureField?.fieldName ?? 'Signature';
    // ignore: avoid_print
    print('\nAssinatura #$i: $fieldName');

    final certs = sig.certificates ?? const <PdfSignatureCertificateInfo>[];
    if (certs.isEmpty) {
      // ignore: avoid_print
      print('  Nenhum certificado encontrado.');
      continue;
    }

    for (int j = 0; j < certs.length; j++) {
      final cert = certs[j];
      // ignore: avoid_print
      print('  Cert #$j subject: ${cert.subject ?? '(null)'}');

      final ids = cert.icpBrasilIds;
      if (ids != null) {
        if (ids.cpf != null) {
          // ignore: avoid_print
          print('  CPF (ICP-Brasil): ${ids.cpf}');
        }
        if (ids.responsavelCpf != null) {
          // ignore: avoid_print
          print('  CPF responsável: ${ids.responsavelCpf}');
        }
      }

      final otherNames = cert.otherNames;
      if (otherNames.isEmpty) {
        // ignore: avoid_print
        print('  otherName: (nenhum)');
        continue;
      }

      for (final entry in otherNames) {
        final oid = entry.oid;
        final raw = entry.value;
        final digits = _onlyDigits(raw);
        final cpf = _extractCpfFromOidValue(oid, digits);

        if (cpf != null) {
          // ignore: avoid_print
          print('  CPF (OID $oid): $cpf');
        } else {
          // ignore: avoid_print
          print('  otherName $oid: $raw');
        }
      }
    }
  }
}

String _onlyDigits(String input) => input.replaceAll(RegExp(r'\D'), '');

String? _extractCpfFromOidValue(String oid, String digits) {
  if (oid == _oidCpf) {
    if (digits.length >= 19) {
      return digits.substring(8, 19);
    }
    if (digits.length == 11) {
      return digits;
    }
  }
  if (oid == _oidCpfResponsavel && digits.length >= 11) {
    return digits.substring(digits.length - 11);
  }
  return null;
}

