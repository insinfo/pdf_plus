import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pki.dart';
import 'package:pdf_plus/signing.dart';
import 'package:test/test.dart';

import 'pki_asset_loader.dart';

/// Memorando 507/2026, assinado em 27/10/2026 com e-CPF ICP-Brasil da
/// AC OAB G4, cuja cadeia é AC OAB G4 → AC Certisign G8 → Raiz Brasileira v12.
/// O validar.iti.gov.br aprova; com os truststores anteriores à hierarquia
/// v12 a cadeia saía como desconhecida. O PDF só traz o certificado do
/// signatário, então a confiança depende inteira dos truststores locais.
const String _pdf =
    'test/assets/pdfs/Memo 507-26  encaminha minuta do Decreto regulamentando TAC.pdf';

class _Raizes implements TrustedRootsProvider {
  _Raizes(this._raizes);

  final List<Uint8List> _raizes;

  @override
  Future<List<Uint8List>> getTrustedRootsDer() async => _raizes;
}

Future<PdfSignatureInfoReport> _validar(List<Uint8List> raizes) async {
  final report = await PdfSignatureValidator().validateAllSignatures(
    File(_pdf).readAsBytesSync(),
    trustedRootsProvider: _Raizes(raizes),
    includeCertificates: true,
  );
  expect(report.signatures, hasLength(1));
  return report.signatures.single;
}

void _esperarValida(PdfSignatureInfoReport assinatura, String fonte) {
  expect(assinatura.cmsValid, isTrue);
  expect(assinatura.digestValid, isTrue);
  expect(assinatura.intact, isTrue);
  expect(assinatura.signerCertificate?.subject,
      contains('INGRID ANTUNES AMARAL'));
  expect(assinatura.chainTrusted, isTrue,
      reason: 'AC OAB G4 → AC Certisign G8 → Raiz v12 precisa estar em $fonte');
}

void main() {
  group('Memorando 507/2026 - cadeia sob a Raiz Brasileira v12', () {
    test('confiavel com cadeiasicpbrasil.bks', () async {
      final bks = BksKeyStore.load(
        File('test/assets/truststore/icp_brasil/cadeiasicpbrasil.bks')
            .readAsBytesSync(),
        storePassword: 'serprosigner',
        tryDecryptKeys: false,
      );
      _esperarValida(
        await _validar(<Uint8List>[
          for (final entrada in bks.certs.values) entrada.certData,
        ]),
        'cadeiasicpbrasil.bks',
      );
    });

    test('confiavel com keystore_ICP_Brasil.jks', () async {
      final jks = JksKeyStore.load(
        File('test/assets/truststore/keystore_icp_brasil/keystore_ICP_Brasil.jks')
            .readAsBytesSync(),
        storePassword: '12345678',
      );
      _esperarValida(
        await _validar(<Uint8List>[
          for (final entrada in jks.certs.values) entrada.certData,
        ]),
        'keystore_ICP_Brasil.jks',
      );
    });

    test('confiavel com a pasta cadeia_icp_brasil', () async {
      final raizes = TruststoreAssetsLoader(
        basePath: 'test/assets/truststore/cadeia_icp_brasil',
      ).loadTrustedRoots();
      _esperarValida(await _validar(raizes), 'cadeia_icp_brasil');
    });

    test('sem a hierarquia v12 a cadeia nao fecha', () async {
      // Só a raiz v5: prova que o teste depende de fato das ACs novas.
      final raizes = TruststoreAssetsLoader(
        basePath: 'test/assets/truststore/cadeia_icp_brasil',
      ).loadTrustedRoots().where((der) {
        final subject = X509Certificate.fromDer(der).subject.toString();
        return !subject.contains('v12') && !subject.contains('G8') &&
            !subject.contains('OAB G4');
      }).toList();
      final assinatura = await _validar(raizes);
      expect(assinatura.cmsValid, isTrue);
      expect(assinatura.chainTrusted, isNot(isTrue));
    });
  });
}
