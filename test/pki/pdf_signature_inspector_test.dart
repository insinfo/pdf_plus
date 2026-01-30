import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

import 'pki_asset_loader.dart';

void main() {
  test('inspector summary for 2 ass leonardo e mauricio', () async {
    final File file = File('test/assets/pdfs/2 ass leonardo e mauricio.pdf');
    expect(file.existsSync(), isTrue, reason: 'Arquivo não encontrado: ${file.path}');

    final Uint8List bytes = file.readAsBytesSync();

    final report = await PdfSignatureInspector().inspect(
      bytes,
      fetchCrls: false,
      trustedRootsProvider: AssetTrustedRootsProvider(
        AssetTrustedRootsProvider.loadDefaultRoots(),
      ),
    );

    expect(report.signatures.length, 2);
    expect(report.allDocumentsIntact, isTrue);

    final commonNames = report.signatures
        .map((s) => s.signer?.commonName)
        .whereType<String>()
        .toList(growable: false);

    expect(commonNames.length, 2);
    expect(commonNames, contains('LEONARDO CALHEIROS OLIVEIRA'));
    expect(commonNames, contains('MAURICIO SOARES DOS ANJOS:02094890732'));

    final cpfList = report.signatures
        .map((s) => s.signer?.cpf)
        .whereType<String>()
        .toList(growable: false);

    expect(cpfList, contains('02094890732'));
    if (cpfList.length > 1) {
      expect(cpfList, contains('09498269793'));
    }

    final dobList = report.signatures
        .map((s) => s.signer?.dateOfBirth)
        .whereType<DateTime>()
        .toList(growable: false);
    if (dobList.isNotEmpty) {
      expect(dobList, contains(DateTime(1982, 10, 25)));
      expect(dobList, contains(DateTime(1971, 3, 12)));
    }

    final byField = <String, PdfSignatureSummary>{
      for (final s in report.signatures) s.fieldName: s,
    };

    final sig1 = byField['Signature1']!;
    final sig2 = byField['Signature2']!;

    expect(sig1.signingTime, isNotNull);
    expect(sig2.signingTime, isNotNull);

    final t1 = sig1.signingTime!;
    expect(t1.year, 2025);
    expect(t1.month, 12);
    expect(t1.day, 29);
    expect(t1.hour, 17);
    expect(t1.minute, 5);
    expect(t1.second, 15);

    final t2 = sig2.signingTime!;
    expect(t2.year, 2025);
    expect(t2.month, 12);
    expect(t2.day, 29);
    expect(t2.hour, 13);
    expect(t2.minute, 58);
    expect(t2.second, 22);

    expect(sig1.policyPresent, isFalse);
    expect(sig2.policyPresent, isTrue);
    expect(sig1.policyDigestOk, isNull);
    expect(sig2.policyDigestOk, isNull);

    expect(sig1.cmsSignatureValid, isTrue);
    expect(sig1.byteRangeDigestOk, isTrue);
    expect(sig1.documentIntact, isTrue);
    expect(sig2.cmsSignatureValid, isTrue);
    expect(sig2.byteRangeDigestOk, isTrue);
    expect(sig2.documentIntact, isTrue);

    expect(sig1.chainTrusted, isTrue);
    expect(sig2.chainTrusted, isTrue);

    expect(sig1.docMdp, isNotNull);
    expect(sig2.docMdp, isNotNull);

    expect(sig1.signer?.subject, isNotNull);
    expect(sig1.signer?.issuer, isNotNull);
    expect(sig1.signer?.serialNumberHex, isNotNull);
    expect(sig1.signer?.serialNumberDecimal, isNotNull);
    expect(sig1.signer?.certNotBefore, isNotNull);
    expect(sig1.signer?.certNotAfter, isNotNull);
    expect(sig1.signer!.certNotBefore!.isBefore(sig1.signer!.certNotAfter!),
        isTrue);

    expect(sig2.signer?.subject, isNotNull);
    expect(sig2.signer?.issuer, isNotNull);
    expect(sig2.signer?.serialNumberHex, isNotNull);
    expect(sig2.signer?.serialNumberDecimal, isNotNull);
    expect(sig2.signer?.certNotBefore, isNotNull);
    expect(sig2.signer?.certNotAfter, isNotNull);
    expect(sig2.signer!.certNotBefore!.isBefore(sig2.signer!.certNotAfter!),
        isTrue);
  });
}
