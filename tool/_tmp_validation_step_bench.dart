import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pki.dart';
import 'package:pdf_plus/signing.dart';

Future<void> main() async {
  final pdf = Uint8List.fromList(
    File('test/assets/pdfs/documento assinado erro.pdf').readAsBytesSync(),
  );
  final bksIcp = Uint8List.fromList(
    File('test/assets/truststore/icp_brasil/cadeiasicpbrasil.bks')
        .readAsBytesSync(),
  );
  final bksGov = Uint8List.fromList(
    File('test/assets/truststore/gov.br/cadeia_govbr_unica.bks')
        .readAsBytesSync(),
  );

  final sw = Stopwatch();
  sw.start();
  final icpStore = BksKeyStore.load(
    bksIcp,
    storePassword: 'serprosigner',
    tryDecryptKeys: false,
  );
  final govStore = BksKeyStore.load(
    bksGov,
    storePassword: 'serprosigner',
    tryDecryptKeys: false,
  );
  sw.stop();
  print('load bks ms=${sw.elapsedMilliseconds}');

  final icpRoots = icpStore.getAllCertificates();
  final govRoots = govStore.getAllCertificates();

  final sources = <PdfTrustedRootsSource>[
    PdfTrustedRootsSource(
      id: 'icp',
      provider: PdfInMemoryTrustedRootsProvider(icpRoots),
    ),
    PdfTrustedRootsSource(
      id: 'gov',
      provider: PdfInMemoryTrustedRootsProvider(govRoots),
    ),
  ];

  sw
    ..reset()
    ..start();
  final index = await PdfTrustedRootsIndex.build(sources);
  sw.stop();
  print('build index ms=${sw.elapsedMilliseconds}');

  final selector = PdfSmartTrustedRootsSelector(index);
  final smart = PdfSmartSignatureValidator();
  final validator = PdfSignatureValidator();

  sw
    ..reset()
    ..start();
  final smartResult = await smart.validateAllSignatures(
    pdf,
    rootsSelector: selector,
    includeCertificates: true,
    includeSignatureFields: true,
  );
  sw.stop();
  print(
    'smart validate once ms=${sw.elapsedMilliseconds} '
    'selected=${smartResult.rootsSelection.selectedSourceIds}',
  );

  sw
    ..reset()
    ..start();
  final reportIcp = await validator.validateAllSignatures(
    pdf,
    trustedRootsProvider: PdfInMemoryTrustedRootsProvider(icpRoots),
    includeCertificates: false,
    includeSignatureFields: false,
  );
  sw.stop();
  print(
    'extra validate icp ms=${sw.elapsedMilliseconds} '
    'sigs=${reportIcp.signatures.length}',
  );

  sw
    ..reset()
    ..start();
  final reportGov = await validator.validateAllSignatures(
    pdf,
    trustedRootsProvider: PdfInMemoryTrustedRootsProvider(govRoots),
    includeCertificates: false,
    includeSignatureFields: false,
  );
  sw.stop();
  print(
    'extra validate gov ms=${sw.elapsedMilliseconds} '
    'sigs=${reportGov.signatures.length}',
  );
}
