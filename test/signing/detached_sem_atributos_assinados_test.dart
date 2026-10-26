import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart' as pdf;
import 'package:test/test.dart';

/// Assinatura `/adbe.pkcs7.detached` **sem atributos assinados** (RFC 5652
/// §5.4).
///
/// Sem `signedAttrs`, a assinatura cobre diretamente o resumo do conteúdo — os
/// bytes do ByteRange —, sem `messageDigest` e sem conteúdo encapsulado. O
/// validador só tratava o caso com atributos (compara com `messageDigest`) e o
/// `/adbe.pkcs7.sha1` (conteúdo encapsulado). Neste terceiro caso não tinha
/// dado para conferir a assinatura e acusava "Atributo messageDigest não
/// encontrado no CMS", reprovando um PDF que o Validar ITI aprova.
///
/// O edital PE 121/2026 (e-CPF A3 ICP-Brasil, SHA-1 + `rsaEncryption`) foi
/// recusado no upload do SALI em 26/10/2026. Conferido com OpenSSL: o
/// DigestInfo recuperado da assinatura é o SHA-1 `142dd987…16a9`, igual ao
/// SHA-1 das faixas do ByteRange.
void main() {
  const caminho = 'test/assets/pdfs/'
      'PE 121.2026 Edital para 16.11.2026_assinado_23102026055524.pdf';

  test('assinatura detached sem atributos assinados e valida e integra',
      () async {
    final arquivo = File(caminho);
    expect(arquivo.existsSync(), isTrue, reason: 'arquivo não encontrado');

    final relatorio = await pdf.PdfSignatureValidator()
        .validateAllSignatures(arquivo.readAsBytesSync());

    expect(relatorio.signatures, hasLength(1));
    final assinatura = relatorio.signatures.single;
    expect(assinatura.cmsValid, isTrue,
        reason: 'a assinatura RSA cobre o SHA-1 das faixas do ByteRange');
    expect(assinatura.digestValid, isTrue,
        reason: 'sem messageDigest, a integridade vem da própria assinatura');
    expect(assinatura.intact, isTrue);
  });

  test('alterar um byte dentro do ByteRange reprova (sem falso integro)',
      () async {
    final bytes = File(caminho).readAsBytesSync();
    final adulterado = Uint8List.fromList(bytes);
    adulterado[10000] ^= 0xFF;

    final relatorio =
        await pdf.PdfSignatureValidator().validateAllSignatures(adulterado);

    expect(relatorio.signatures, isNotEmpty);
    final assinatura = relatorio.signatures.first;
    expect(assinatura.cmsValid, isFalse);
    expect(assinatura.digestValid, isFalse);
  });
}
