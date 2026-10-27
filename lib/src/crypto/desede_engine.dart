import 'dart:typed_data';

import 'base.dart';
import 'des.dart';

class DESedeEngine implements BlockCipher {
  static const int _blockSize = 8;

  late List<int> _k1;
  late List<int> _k2;
  late List<int> _k3;
  bool _forEncryption = false;

  @override
  String get algorithmName => 'DESede';

  @override
  int get blockSize => _blockSize;

  @override
  void init(bool forEncryption, CipherParameters params) {
    if (params is! KeyParameter) {
      throw ArgumentError('DESede requer KeyParameter.');
    }
    final key = params.key;
    if (key.length != 16 && key.length != 24) {
      throw ArgumentError('Chave DESede deve ter 16 ou 24 bytes.');
    }
    _forEncryption = forEncryption;
    final k1 = key.sublist(0, 8);
    final k2 = key.sublist(8, 16);
    final k3 = key.length == 24 ? key.sublist(16, 24) : k1;

    // EDE: the middle stage runs in the opposite direction. The subkeys must
    // follow the requested direction, as in Bouncy Castle's DESedeEngine;
    // fixing them to (encrypt, decrypt, encrypt) made every decryption wrong.
    _k1 = DESEngine.generateWorkingKey(forEncryption, k1);
    _k2 = DESEngine.generateWorkingKey(!forEncryption, k2);
    _k3 = DESEngine.generateWorkingKey(forEncryption, k3);
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if (inpOff + _blockSize > inp.length) {
      throw ArgumentError('Input muito curto para DESede.');
    }
    final temp = Uint8List(_blockSize);
    if (_forEncryption) {
      _processDes(inp, inpOff, temp, 0, _k1);
      _processDes(temp, 0, temp, 0, _k2);
      _processDes(temp, 0, out, outOff, _k3);
    } else {
      _processDes(inp, inpOff, temp, 0, _k3);
      _processDes(temp, 0, temp, 0, _k2);
      _processDes(temp, 0, out, outOff, _k1);
    }
    return _blockSize;
  }

  @override
  void reset() {}

  void _processDes(
    Uint8List inp,
    int inpOff,
    Uint8List out,
    int outOff,
    List<int> workingKey,
  ) {
    DESEngine.processBlockWithKey(inp, inpOff, out, outOff, workingKey);
  }
}
