import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/pure_ecdsa.dart';
import 'package:pdf_plus/src/crypto/signature_adapter.dart';
import 'package:test/test.dart';

Uint8List _hex(String value) {
  final out = Uint8List(value.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(value.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// Uma assinatura ECDSA na forma RAW (`r || s`) cujo `r` começa em `0x30`
/// parece uma SEQUENCE DER — acontece em uma a cada 256 assinaturas.
///
/// A detecção olhava só o primeiro byte, então esses casos eram tratados como
/// DER, a decodificação falhava e a verificação devolvia `false` para uma
/// assinatura perfeitamente válida. O vetor abaixo é um caso real desses,
/// fixado aqui para o teste ser determinístico: procurar um por força bruta
/// custa algumas centenas de assinaturas.
void main() {
  // Par P-256 gerado por openssl; a mensagem é 'vetor 182'.
  final spki = _hex(
    '3059301306072a8648ce3d020106082a8648ce3d03010703420004'
    '51c39e7a41b15946a9d20b94258b5199373b8d3ae586b20912538224765a8386'
    'a276b0f76452bdb06baeab89d574d66c295da936d32f0c6a02e090fc2ac70f9e',
  );
  final raw = _hex(
    '307eda82beeb760143a5c38524266144ac45900e6c9afc67b38130d9b02c72af'
    'a5b33c9502755166a855efa36bbbf837ac918c83138b06bc0e782dd1d01d954b',
  );
  final der = _hex(
    '30450220307eda82beeb760143a5c38524266144ac45900e6c9afc67b38130d9'
    'b02c72af022100a5b33c9502755166a855efa36bbbf837ac918c83138b06bc0e'
    '782dd1d01d954b',
  );
  final data = Uint8List.fromList(utf8.encode('vetor 182'));

  group('assinatura ECDSA RAW que parece DER', () {
    test('o vetor é mesmo ambíguo', () {
      expect(raw.length, 64, reason: 'RAW de P-256 tem 64 bytes');
      expect(raw.first, 0x30, reason: 'é o que confundia a detecção');
    });

    test('verify aceita a forma RAW', () {
      expect(
        PureEcDsa.verify(
          namedCurve: 'P-256',
          hashAlgorithm: 'SHA-256',
          spkiPublicKey: spki,
          data: data,
          signature: raw,
        ),
        isTrue,
      );
    });

    test('verify aceita a forma DER equivalente', () {
      expect(
        PureEcDsa.verify(
          namedCurve: 'P-256',
          hashAlgorithm: 'SHA-256',
          spkiPublicKey: spki,
          data: data,
          signature: der,
        ),
        isTrue,
      );
    });

    test('as duas formas descrevem a mesma assinatura', () {
      expect(SignatureAdapter.ecdsaDerToRaw(der, namedCurve: 'P-256'), raw);
      expect(SignatureAdapter.ecdsaRawToDer(raw, namedCurve: 'P-256'), der);
    });

    test('mensagem diferente continua sendo recusada', () {
      expect(
        PureEcDsa.verify(
          namedCurve: 'P-256',
          hashAlgorithm: 'SHA-256',
          spkiPublicKey: spki,
          data: Uint8List.fromList(utf8.encode('outra mensagem')),
          signature: raw,
        ),
        isFalse,
      );
    });

    test('64 bytes que não formam DER válido não são lidos como DER', () {
      // Mesmo começando em 0x30, o conteúdo não fecha como SEQUENCE.
      final ambiguous = Uint8List.fromList(raw);
      expect(
        SignatureAdapter.ecdsaRawToDer(ambiguous, namedCurve: 'P-256'),
        der,
        reason: 'precisa ser tratado como RAW, não devolvido como se fosse DER',
      );
    });
  });
}
