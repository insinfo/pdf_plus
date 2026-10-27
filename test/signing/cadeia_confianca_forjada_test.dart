import 'dart:typed_data';

import 'package:pdf_plus/crypto.dart' as crypto;
import 'package:pdf_plus/pdf.dart' as core;
import 'package:pdf_plus/pki.dart' as pki;
import 'package:pdf_plus/signing.dart' as pdf;
import 'package:test/test.dart';

/// Ataques à cadeia de confiança que o validador aceitava até a 4.0.1.
///
/// A confiança só pode vir de um caminho em que cada certificado é assinado
/// pela chave do seguinte, cada emissor é uma AC (basicConstraints cA) e o
/// caminho termina numa das raízes. Nome igual ou parecido, certificado
/// autoassinado fora das raízes e certificado de usuário final usado como AC
/// não bastam.
typedef _Chave = crypto.AsymmetricKeyPair<crypto.PublicKey, crypto.PrivateKey>;

_Chave _novaChave() =>
    pki.PkiUtils.generateRsaKeyPair(bitStrength: 1024, certainty: 16);

int _serial = 10;

pki.X509Certificate _usuario(
  _Chave chave,
  _Chave chaveDoEmissor,
  String titular,
  String emissor,
) =>
    pki.PkiBuilder.createUserCertificate(
      keyPair: chave,
      issuerKeyPair: chaveDoEmissor,
      subjectDn: titular,
      issuerDn: emissor,
      serialNumber: _serial++,
      validityDays: 365,
    );

Future<pdf.PdfSignatureInfoReport> _assinarEValidar({
  required _Chave chave,
  required pki.X509Certificate certificado,
  required List<pki.X509Certificate> cadeia,
  required List<pki.X509Certificate> raizes,
}) async {
  final doc = core.PdfDocument();
  core.PdfPage(doc);
  doc.addSignatureFieldTopLeft(
    pageNumber: 1,
    left: 50,
    top: 120,
    width: 200,
    height: 60,
    fieldName: 'Assinatura',
  );
  final loaded =
      pdf.PdfLoadedDocument.fromBytes(Uint8List.fromList(await doc.save()));
  await loaded.addSignature(
    pdf.PdfSignatureRequest(
      pageNumber: 1,
      fieldName: 'Assinatura',
      signer: pdf.PdfSignatureSigner.pem(
        privateKeyPem: pki.PkiPemUtils.rsaPrivateKeyToPem(
          chave.privateKey as pki.RSAPrivateKey,
        ),
        certificate: certificado,
        chain: cadeia,
      ),
      bounds: pdf.PdfSignatureBounds.topLeft(
        left: 50,
        top: 120,
        width: 200,
        height: 60,
      ),
    ),
  );
  final assinado = await loaded.save();
  loaded.dispose();

  final report = await pdf.PdfSignatureValidator().validateAllSignatures(
    assinado,
    trustedRootsPem: <String>[for (final r in raizes) r.toPem()],
  );
  return report.signatures.single;
}

void main() {
  late _Chave chaveRaiz;
  late _Chave chaveAc;
  late pki.X509Certificate raiz;
  late pki.X509Certificate ac;

  setUpAll(() {
    chaveRaiz = _novaChave();
    chaveAc = _novaChave();
    raiz = pki.PkiBuilder.createRootCertificate(
      keyPair: chaveRaiz,
      dn: 'CN=Raiz de Teste',
      validityYears: 2,
    );
    ac = pki.PkiBuilder.createIntermediateCertificate(
      keyPair: chaveAc,
      issuerKeyPair: chaveRaiz,
      subjectDn: 'CN=AC de Teste',
      issuerDn: 'CN=Raiz de Teste',
      serialNumber: 2,
      validityYears: 2,
    );
  });

  group('Cadeia de confianca', () {
    test('usuario emitido pela AC chega a raiz', () async {
      final chave = _novaChave();
      final assinatura = await _assinarEValidar(
        chave: chave,
        certificado:
            _usuario(chave, chaveAc, 'CN=Usuario Legitimo', 'CN=AC de Teste'),
        cadeia: <pki.X509Certificate>[ac],
        raizes: <pki.X509Certificate>[raiz],
      );
      expect(assinatura.cmsValid, isTrue);
      expect(assinatura.chainTrusted, isTrue);
    });

    test('certificado de usuario final nao pode servir de AC', () async {
      // Um e-CPF legítimo usado para emitir um certificado em nome de outro.
      final chaveDoUsuario = _novaChave();
      final usuario = _usuario(
          chaveDoUsuario, chaveAc, 'CN=Usuario Comum', 'CN=AC de Teste');
      final chaveFalsa = _novaChave();
      final assinatura = await _assinarEValidar(
        chave: chaveFalsa,
        certificado: _usuario(
            chaveFalsa, chaveDoUsuario, 'CN=Outra Pessoa', 'CN=Usuario Comum'),
        cadeia: <pki.X509Certificate>[usuario, ac],
        raizes: <pki.X509Certificate>[raiz],
      );
      expect(assinatura.cmsValid, isTrue);
      expect(assinatura.chainTrusted, isFalse,
          reason: 'o emissor não tem basicConstraints cA');
    });

    test('nome da AC real com outra chave nao e confiavel', () async {
      // Diz ter sido emitido pela AC de Teste, mas quem assinou foi outra
      // chave. A AC verdadeira está entre as raízes.
      final chaveAtacante = _novaChave();
      final chaveFalsa = _novaChave();
      final assinatura = await _assinarEValidar(
        chave: chaveFalsa,
        certificado: _usuario(
            chaveFalsa, chaveAtacante, 'CN=Outra Pessoa', 'CN=AC de Teste'),
        cadeia: const <pki.X509Certificate>[],
        raizes: <pki.X509Certificate>[raiz, ac],
      );
      expect(assinatura.cmsValid, isTrue);
      expect(assinatura.chainTrusted, isFalse,
          reason: 'a assinatura do certificado não confere com a chave da AC');
    });

    test('raiz autoassinada propria no PDF nao e confiavel', () async {
      final chaveRaizFalsa = _novaChave();
      final raizFalsa = pki.PkiBuilder.createRootCertificate(
        keyPair: chaveRaizFalsa,
        dn: 'CN=Raiz Propria',
        validityYears: 2,
      );
      final chaveFalsa = _novaChave();
      final assinatura = await _assinarEValidar(
        chave: chaveFalsa,
        certificado: _usuario(
            chaveFalsa, chaveRaizFalsa, 'CN=Outra Pessoa', 'CN=Raiz Propria'),
        cadeia: <pki.X509Certificate>[raizFalsa],
        raizes: <pki.X509Certificate>[raiz],
      );
      expect(assinatura.cmsValid, isTrue);
      expect(assinatura.chainTrusted, isFalse,
          reason: 'autoassinado fora das raízes não é âncora');
    });
  });
}
