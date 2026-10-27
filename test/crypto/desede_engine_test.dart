import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/export.dart';
import 'package:pdf_plus/src/utils/convert/hex/hex.dart';
import 'package:test/test.dart';

/// 3DES-CBC (EDE). Até a 4.0.1 o `DESedeEngine` gerava as subchaves sempre no
/// sentido de cifrar, e toda decifração saía errada — a chave selada do BKS e
/// a chave privada do JCEKS não abriam.
///
/// O vetor é a chave selada da amostra `v2BKS` do Bouncy Castle, decifrada
/// pelo OpenSSL (pacote `cryptography` do Python): `02 · "RAW" · "AES" · …`
/// mais um byte de padding PKCS#7.
final Uint8List _chave = _hex('866105412ee9da70ecd5d613a1c528e6f479f1eb07311443');
final Uint8List _iv = _hex('54348112980b2b4f');
final Uint8List _cifrado = _hex(
    '0fad93fcab6d0024b1138c3bf42bd0b9ac89757aba72be9bf6d1ba9c6e084aeb');
final Uint8List _claro = _hex(
    '020003524157000341455300000010a757318978cfe45020350c70e5fe238501');

Uint8List _hex(String texto) => Uint8List.fromList(hex.decode(texto));

Uint8List _cbc(bool cifrar, Uint8List chave, Uint8List entrada) {
  final cbc = CBCBlockCipher(DESedeEngine())
    ..init(cifrar, ParametersWithIV<KeyParameter>(KeyParameter(chave), _iv));
  final saida = Uint8List(entrada.length);
  for (var i = 0; i < entrada.length; i += cbc.blockSize) {
    cbc.processBlock(entrada, i, saida, i);
  }
  return saida;
}

void main() {
  group('DESedeEngine', () {
    test('decifra o vetor de referencia do OpenSSL', () {
      expect(hex.encode(_cbc(false, _chave, _cifrado)), hex.encode(_claro));
    });

    test('cifra o vetor de referencia do OpenSSL', () {
      expect(hex.encode(_cbc(true, _chave, _claro)), hex.encode(_cifrado));
    });

    test('ida e volta com chave de dois componentes', () {
      final chave = _chave.sublist(0, 16);
      final cifrado = _cbc(true, chave, _claro);
      expect(_cbc(false, chave, cifrado), _claro,
          reason: 'K3 = K1 na variante de 16 bytes');
    });
  });
}
