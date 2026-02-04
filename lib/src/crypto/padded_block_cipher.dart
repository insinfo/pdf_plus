import 'dart:typed_data';

import 'base.dart';
import 'pkcs7_padding.dart';
import 'cbc_block_cipher.dart';

class PaddedBlockCipherImpl {
  PaddedBlockCipherImpl(this._padding, this._cipher);

  final PKCS7Padding _padding;
  final BlockCipher _cipher;

  Uint8List process(Uint8List data) {
    if (_cipher is! CBCBlockCipher) {
      throw StateError('PaddedBlockCipherImpl requer CBCBlockCipher.');
    }
    final cbc = _cipher;
    if (cbc.forEncryption) {
      return _encrypt(data, cbc);
    }
    return _decrypt(data, cbc);
  }

  Uint8List _encrypt(Uint8List data, CBCBlockCipher cipher) {
    final blockSize = cipher.blockSize;
    final padLen = blockSize - (data.length % blockSize);
    final out = Uint8List(data.length + padLen);
    out.setRange(0, data.length, data);
    _padding.addPadding(out, data.length);

    final result = Uint8List(out.length);
    for (int i = 0; i < out.length; i += blockSize) {
      cipher.processBlock(out, i, result, i);
    }
    return result;
  }

  Uint8List _decrypt(Uint8List data, CBCBlockCipher cipher) {
    final blockSize = cipher.blockSize;
    if (data.length % blockSize != 0) {
      throw StateError('Invalid ciphertext length.');
    }
    final tmp = Uint8List(data.length);
    for (int i = 0; i < data.length; i += blockSize) {
      cipher.processBlock(data, i, tmp, i);
    }
    final padLen = _padding.padCount(tmp);
    return tmp.sublist(0, tmp.length - padLen);
  }
}
