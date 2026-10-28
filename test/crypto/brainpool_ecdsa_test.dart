import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/pure_ecdsa.dart';
import 'package:pdf_plus/src/crypto/signature_adapter.dart';
import 'package:test/test.dart';

/// Curvas Brainpool (RFC 5639) na verificação ECDSA.
///
/// Até a 4.0.2 o `_EcCurve.byName` mandava as Brainpool para as curvas NIST
/// de mesmo tamanho, o OID da brainpoolP384r1 virava `P-384` e a
/// brainpoolP512r1 tinha coordenada de 66 bytes (a da P-521): toda assinatura
/// Brainpool era conferida na curva errada e reprovada. Os vetores foram
/// gerados e conferidos com o OpenSSL (`openssl dgst -sign`/`-verify`).
class _Vetor {
  const _Vetor({
    required this.curva,
    required this.hash,
    required this.coordenada,
    required this.spki,
    required this.assinaturaDer,
  });

  final String curva;
  final String hash;
  final int coordenada;
  final String spki;
  final String assinaturaDer;
}

const String _dado = 'documento assinado com curva Brainpool';

const List<_Vetor> _vetores = <_Vetor>[
  _Vetor(
    curva: 'BRAINPOOLP256R1',
    hash: 'SHA-256',
    coordenada: 32,
    spki: 'MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABGwV0TnYH2Q/Iyu6awaKpuHkWV18d2jA7lNcSJBqE+uEJoVq3a6nkNoKL95eQMpzuCpxKvZDvVZQt3hK+JUJZE0=',
    assinaturaDer: 'MEUCIQChWwt4kHlAa3F25L3yTtYfai1eh5UnQUOqnaT1j2io+gIgVnUz4v1T571YzHeUUwCS+ySHGO8Fj06P+wq1N/eu7po=',
  ),
  _Vetor(
    curva: 'BRAINPOOLP384R1',
    hash: 'SHA-384',
    coordenada: 48,
    spki: 'MHowFAYHKoZIzj0CAQYJKyQDAwIIAQELA2IABFPVIcnWhJooBYxw/iurN5HFPb6x9Ln4RkDC03uqW2zAEb8vhtebANJwcJA2AADZ0zWgW4NKEi0J9M8CBj6lWWP6+cc+pOpVpqgkTbDyCl+ueOOtYf6O4UXsHZe2iJBvVw==',
    assinaturaDer: 'MGQCMBpRk73zVMlhGREQpH9QfJx0dIj4eo6RPawe5l4EcI26c+/dl0ityYtBkerLz4pPmgIwY29mxUuN2ztGxlIn92p9HSdAnVe+Wjvz5tRxstoGCTkB7M3iTJB1Mg6SyyO2sCn9',
  ),
  _Vetor(
    curva: 'BRAINPOOLP512R1',
    hash: 'SHA-512',
    coordenada: 64,
    spki: 'MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEOuVWHokTMU2SZQMf4fSxWKAwaiEGu5+sbfkLgFF3aLutS1EFR3KIgPt6xT3cntW8cFhKJH/R5TkdLeboeJEjvm5Scnw60qGxe9zxK60dQho6tM9Gmtxxg0Xd9p6IGKOnMPKdVMi4x/59Yn8wkyi8A4NvkEjiShTbS5eJJI1psK8=',
    assinaturaDer: 'MIGEAj9iEkyTGXtWHo0Jr/yOiq9rg3BJfxQaFZtiBTtfPjqrkr0KrapvJdDofqfGJwR4kb+ug3kfwOlczlVc9/DApiICQQCjOGqkdX8A1CFP0xfUROti6OMWzFwY0hwfK6lAYx1N0CTLz2NswNAewwYpvpnihdszD8Cqi92B6zp7W2IEuo9R',
  ),
];

void main() {
  final dado = Uint8List.fromList(utf8.encode(_dado));

  for (final v in _vetores) {
    group(v.curva, () {
      final spki = Uint8List.fromList(base64.decode(v.spki));
      final assinatura = Uint8List.fromList(base64.decode(v.assinaturaDer));

      test('assinatura do OpenSSL confere', () {
        expect(
          PureEcDsa.verify(
            namedCurve: v.curva,
            hashAlgorithm: v.hash,
            spkiPublicKey: spki,
            data: dado,
            signature: assinatura,
          ),
          isTrue,
        );
      });

      test('dado alterado e recusado', () {
        final alterado = Uint8List.fromList(dado)..[0] ^= 0x01;
        expect(
          PureEcDsa.verify(
            namedCurve: v.curva,
            hashAlgorithm: v.hash,
            spkiPublicKey: spki,
            data: alterado,
            signature: assinatura,
          ),
          isFalse,
        );
      });

      test('tamanho da coordenada e da forma RAW', () {
        expect(SignatureAdapter.curveCoordinateLength(v.curva), v.coordenada);
        final raw =
            SignatureAdapter.ecdsaDerToRaw(assinatura, namedCurve: v.curva);
        expect(raw.length, v.coordenada * 2);
        expect(
          PureEcDsa.verify(
            namedCurve: v.curva,
            hashAlgorithm: v.hash,
            spkiPublicKey: spki,
            data: dado,
            signature: SignatureAdapter.ecdsaRawToDer(raw,
                namedCurve: v.curva),
          ),
          isTrue,
          reason: 'DER -> RAW -> DER preserva a assinatura',
        );
      });
    });
  }
}
