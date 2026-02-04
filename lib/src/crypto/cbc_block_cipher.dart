import 'dart:typed_data';

import 'base.dart';

class CBCBlockCipher implements BlockCipher {
  CBCBlockCipher(this._cipher);

  final BlockCipher _cipher;
  late Uint8List _iv;
  late Uint8List _cbcV;
  bool _forEncryption = false;

  bool get forEncryption => _forEncryption;

  @override
  String get algorithmName => '${_cipher.algorithmName}/CBC';

  @override
  int get blockSize => _cipher.blockSize;

  @override
  void init(bool forEncryption, CipherParameters params) {
    if (params is! ParametersWithIV) {
      throw ArgumentError('CBC requer ParametersWithIV.');
    }
    _forEncryption = forEncryption;
    _iv = Uint8List.fromList(params.iv);
    _cbcV = Uint8List.fromList(_iv);
    _cipher.init(forEncryption, params.parameters);
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if (_forEncryption) {
      final block = Uint8List(blockSize);
      for (int i = 0; i < blockSize; i++) {
        block[i] = inp[inpOff + i] ^ _cbcV[i];
      }
      _cipher.processBlock(block, 0, out, outOff);
      _cbcV = out.sublist(outOff, outOff + blockSize);
      return blockSize;
    } else {
      final temp = Uint8List(blockSize);
      _cipher.processBlock(inp, inpOff, temp, 0);
      for (int i = 0; i < blockSize; i++) {
        out[outOff + i] = temp[i] ^ _cbcV[i];
      }
      _cbcV = inp.sublist(inpOff, inpOff + blockSize);
      return blockSize;
    }
  }

  @override
  void reset() {
    _cbcV = Uint8List.fromList(_iv);
    _cipher.reset();
  }
}
