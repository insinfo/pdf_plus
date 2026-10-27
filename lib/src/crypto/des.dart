import 'dart:typed_data';

import 'base.dart';

/// DES, ported from Bouncy Castle's `DESEngine` (table-driven, SP boxes).
///
/// Everything stays inside 32 bits: every left shift is masked with
/// `0xFFFFFFFF`, so the result is the same on the VM (64-bit ints) and when
/// compiled to JavaScript (32-bit bitwise operations). The previous engine
/// permuted bit by bit on 64-bit ints and gave wrong output in the browser.
class DESEngine implements BlockCipher {
  static const int _blockSize = 8;
  late List<int> _workingKey;
  @override
  String get algorithmName => 'DES';

  @override
  int get blockSize => _blockSize;

  @override
  void init(bool forEncryption, CipherParameters params) {
    if (params is! KeyParameter) {
      throw ArgumentError('DES requer KeyParameter.');
    }
    _workingKey = generateWorkingKey(forEncryption, params.key);
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if (inpOff + _blockSize > inp.length) {
      throw ArgumentError('Input muito curto para DES.');
    }
    processBlockWithKey(inp, inpOff, out, outOff, _workingKey);
    return _blockSize;
  }

  @override
  void reset() {}

  /// The 32 round-key words of Bouncy Castle's `generateWorkingKey`.
  static List<int> generateWorkingKey(bool encrypting, Uint8List key) {
    if (key.length < 8) {
      throw ArgumentError('Chave DES deve ter 8 bytes.');
    }
    final newKey = Uint32List(32);
    final pc1m = List<bool>.filled(56, false);
    final pcr = List<bool>.filled(56, false);

    for (int j = 0; j < 56; j++) {
      final l = _pc1[j];
      pc1m[j] = (key[l >> 3] & _bytebit[l & 7]) != 0;
    }

    for (int i = 0; i < 16; i++) {
      final m = encrypting ? i << 1 : (15 - i) << 1;
      final n = m + 1;
      int km = 0;
      int kn = 0;

      for (int j = 0; j < 28; j++) {
        final l = j + _totrot[i];
        pcr[j] = l < 28 ? pc1m[l] : pc1m[l - 28];
      }
      for (int j = 28; j < 56; j++) {
        final l = j + _totrot[i];
        pcr[j] = l < 56 ? pc1m[l] : pc1m[l - 28];
      }
      for (int j = 0; j < 24; j++) {
        if (pcr[_pc2[j]]) km |= _bigbyte[j];
        if (pcr[_pc2[j + 24]]) kn |= _bigbyte[j];
      }
      newKey[m] = km;
      newKey[n] = kn;
    }

    for (int i = 0; i != 32; i += 2) {
      final i1 = newKey[i];
      final i2 = newKey[i + 1];
      newKey[i] = (((i1 & 0x00fc0000) << 6) |
              ((i1 & 0x00000fc0) << 10) |
              ((i2 & 0x00fc0000) >> 10) |
              ((i2 & 0x00000fc0) >> 6)) &
          0xFFFFFFFF;
      newKey[i + 1] = (((i1 & 0x0003f000) << 12) |
              ((i1 & 0x0000003f) << 16) |
              ((i2 & 0x0003f000) >> 4) |
              (i2 & 0x0000003f)) &
          0xFFFFFFFF;
    }
    return newKey;
  }

  /// Bouncy Castle's `desFunc`.
  static void processBlockWithKey(
    Uint8List inp,
    int inpOff,
    Uint8List out,
    int outOff,
    List<int> wKey,
  ) {
    int left = _readUint32(inp, inpOff);
    int right = _readUint32(inp, inpOff + 4);
    int work;

    work = ((left >> 4) ^ right) & 0x0f0f0f0f;
    right ^= work;
    left ^= (work << 4) & 0xFFFFFFFF;
    work = ((left >> 16) ^ right) & 0x0000ffff;
    right ^= work;
    left ^= (work << 16) & 0xFFFFFFFF;
    work = ((right >> 2) ^ left) & 0x33333333;
    left ^= work;
    right ^= (work << 2) & 0xFFFFFFFF;
    work = ((right >> 8) ^ left) & 0x00ff00ff;
    left ^= work;
    right ^= (work << 8) & 0xFFFFFFFF;
    right = ((right << 1) | (right >> 31)) & 0xFFFFFFFF;
    work = (left ^ right) & 0xaaaaaaaa;
    left ^= work;
    right ^= work;
    left = ((left << 1) | (left >> 31)) & 0xFFFFFFFF;

    for (int round = 0; round < 8; round++) {
      int fval;

      work = ((right << 28) | (right >> 4)) & 0xFFFFFFFF;
      work ^= wKey[round * 4 + 0];
      fval = _sp7[work & 0x3f];
      fval |= _sp5[(work >> 8) & 0x3f];
      fval |= _sp3[(work >> 16) & 0x3f];
      fval |= _sp1[(work >> 24) & 0x3f];
      work = right ^ wKey[round * 4 + 1];
      fval |= _sp8[work & 0x3f];
      fval |= _sp6[(work >> 8) & 0x3f];
      fval |= _sp4[(work >> 16) & 0x3f];
      fval |= _sp2[(work >> 24) & 0x3f];
      left ^= fval;
      work = ((left << 28) | (left >> 4)) & 0xFFFFFFFF;
      work ^= wKey[round * 4 + 2];
      fval = _sp7[work & 0x3f];
      fval |= _sp5[(work >> 8) & 0x3f];
      fval |= _sp3[(work >> 16) & 0x3f];
      fval |= _sp1[(work >> 24) & 0x3f];
      work = left ^ wKey[round * 4 + 3];
      fval |= _sp8[work & 0x3f];
      fval |= _sp6[(work >> 8) & 0x3f];
      fval |= _sp4[(work >> 16) & 0x3f];
      fval |= _sp2[(work >> 24) & 0x3f];
      right ^= fval;
    }

    right = ((right << 31) | (right >> 1)) & 0xFFFFFFFF;
    work = (left ^ right) & 0xaaaaaaaa;
    left ^= work;
    right ^= work;
    left = ((left << 31) | (left >> 1)) & 0xFFFFFFFF;
    work = ((left >> 8) ^ right) & 0x00ff00ff;
    right ^= work;
    left ^= (work << 8) & 0xFFFFFFFF;
    work = ((left >> 2) ^ right) & 0x33333333;
    right ^= work;
    left ^= (work << 2) & 0xFFFFFFFF;
    work = ((right >> 16) ^ left) & 0x0000ffff;
    left ^= work;
    right ^= (work << 16) & 0xFFFFFFFF;
    work = ((right >> 4) ^ left) & 0x0f0f0f0f;
    left ^= work;
    right ^= (work << 4) & 0xFFFFFFFF;

    _writeUint32(right, out, outOff);
    _writeUint32(left, out, outOff + 4);
  }
}

int _readUint32(Uint8List b, int off) =>
    ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) &
    0xFFFFFFFF;

void _writeUint32(int v, Uint8List out, int off) {
  out[off] = (v >> 24) & 0xFF;
  out[off + 1] = (v >> 16) & 0xFF;
  out[off + 2] = (v >> 8) & 0xFF;
  out[off + 3] = v & 0xFF;
}

final Uint8List _bytebit = Uint8List.fromList(<int>[
  128,
  64,
  32,
  16,
  8,
  4,
  2,
  1,
]);

final Uint32List _bigbyte = Uint32List.fromList(<int>[
  0x00800000,
  0x00400000,
  0x00200000,
  0x00100000,
  0x00080000,
  0x00040000,
  0x00020000,
  0x00010000,
  0x00008000,
  0x00004000,
  0x00002000,
  0x00001000,
  0x00000800,
  0x00000400,
  0x00000200,
  0x00000100,
  0x00000080,
  0x00000040,
  0x00000020,
  0x00000010,
  0x00000008,
  0x00000004,
  0x00000002,
  0x00000001,
]);

final Uint8List _pc1 = Uint8List.fromList(<int>[
  56,
  48,
  40,
  32,
  24,
  16,
  8,
  0,
  57,
  49,
  41,
  33,
  25,
  17,
  9,
  1,
  58,
  50,
  42,
  34,
  26,
  18,
  10,
  2,
  59,
  51,
  43,
  35,
  62,
  54,
  46,
  38,
  30,
  22,
  14,
  6,
  61,
  53,
  45,
  37,
  29,
  21,
  13,
  5,
  60,
  52,
  44,
  36,
  28,
  20,
  12,
  4,
  27,
  19,
  11,
  3,
]);

final Uint8List _totrot = Uint8List.fromList(<int>[
  1,
  2,
  4,
  6,
  8,
  10,
  12,
  14,
  15,
  17,
  19,
  21,
  23,
  25,
  27,
  28,
]);

final Uint8List _pc2 = Uint8List.fromList(<int>[
  13,
  16,
  10,
  23,
  0,
  4,
  2,
  27,
  14,
  5,
  20,
  9,
  22,
  18,
  11,
  3,
  25,
  7,
  15,
  6,
  26,
  19,
  12,
  1,
  40,
  51,
  30,
  36,
  46,
  54,
  29,
  39,
  50,
  44,
  32,
  47,
  43,
  48,
  38,
  55,
  33,
  52,
  45,
  41,
  49,
  35,
  28,
  31,
]);

final Uint32List _sp1 = Uint32List.fromList(<int>[
  0x01010400,
  0x00000000,
  0x00010000,
  0x01010404,
  0x01010004,
  0x00010404,
  0x00000004,
  0x00010000,
  0x00000400,
  0x01010400,
  0x01010404,
  0x00000400,
  0x01000404,
  0x01010004,
  0x01000000,
  0x00000004,
  0x00000404,
  0x01000400,
  0x01000400,
  0x00010400,
  0x00010400,
  0x01010000,
  0x01010000,
  0x01000404,
  0x00010004,
  0x01000004,
  0x01000004,
  0x00010004,
  0x00000000,
  0x00000404,
  0x00010404,
  0x01000000,
  0x00010000,
  0x01010404,
  0x00000004,
  0x01010000,
  0x01010400,
  0x01000000,
  0x01000000,
  0x00000400,
  0x01010004,
  0x00010000,
  0x00010400,
  0x01000004,
  0x00000400,
  0x00000004,
  0x01000404,
  0x00010404,
  0x01010404,
  0x00010004,
  0x01010000,
  0x01000404,
  0x01000004,
  0x00000404,
  0x00010404,
  0x01010400,
  0x00000404,
  0x01000400,
  0x01000400,
  0x00000000,
  0x00010004,
  0x00010400,
  0x00000000,
  0x01010004,
]);

final Uint32List _sp2 = Uint32List.fromList(<int>[
  0x80108020,
  0x80008000,
  0x00008000,
  0x00108020,
  0x00100000,
  0x00000020,
  0x80100020,
  0x80008020,
  0x80000020,
  0x80108020,
  0x80108000,
  0x80000000,
  0x80008000,
  0x00100000,
  0x00000020,
  0x80100020,
  0x00108000,
  0x00100020,
  0x80008020,
  0x00000000,
  0x80000000,
  0x00008000,
  0x00108020,
  0x80100000,
  0x00100020,
  0x80000020,
  0x00000000,
  0x00108000,
  0x00008020,
  0x80108000,
  0x80100000,
  0x00008020,
  0x00000000,
  0x00108020,
  0x80100020,
  0x00100000,
  0x80008020,
  0x80100000,
  0x80108000,
  0x00008000,
  0x80100000,
  0x80008000,
  0x00000020,
  0x80108020,
  0x00108020,
  0x00000020,
  0x00008000,
  0x80000000,
  0x00008020,
  0x80108000,
  0x00100000,
  0x80000020,
  0x00100020,
  0x80008020,
  0x80000020,
  0x00100020,
  0x00108000,
  0x00000000,
  0x80008000,
  0x00008020,
  0x80000000,
  0x80100020,
  0x80108020,
  0x00108000,
]);

final Uint32List _sp3 = Uint32List.fromList(<int>[
  0x00000208,
  0x08020200,
  0x00000000,
  0x08020008,
  0x08000200,
  0x00000000,
  0x00020208,
  0x08000200,
  0x00020008,
  0x08000008,
  0x08000008,
  0x00020000,
  0x08020208,
  0x00020008,
  0x08020000,
  0x00000208,
  0x08000000,
  0x00000008,
  0x08020200,
  0x00000200,
  0x00020200,
  0x08020000,
  0x08020008,
  0x00020208,
  0x08000208,
  0x00020200,
  0x00020000,
  0x08000208,
  0x00000008,
  0x08020208,
  0x00000200,
  0x08000000,
  0x08020200,
  0x08000000,
  0x00020008,
  0x00000208,
  0x00020000,
  0x08020200,
  0x08000200,
  0x00000000,
  0x00000200,
  0x00020008,
  0x08020208,
  0x08000200,
  0x08000008,
  0x00000200,
  0x00000000,
  0x08020008,
  0x08000208,
  0x00020000,
  0x08000000,
  0x08020208,
  0x00000008,
  0x00020208,
  0x00020200,
  0x08000008,
  0x08020000,
  0x08000208,
  0x00000208,
  0x08020000,
  0x00020208,
  0x00000008,
  0x08020008,
  0x00020200,
]);

final Uint32List _sp4 = Uint32List.fromList(<int>[
  0x00802001,
  0x00002081,
  0x00002081,
  0x00000080,
  0x00802080,
  0x00800081,
  0x00800001,
  0x00002001,
  0x00000000,
  0x00802000,
  0x00802000,
  0x00802081,
  0x00000081,
  0x00000000,
  0x00800080,
  0x00800001,
  0x00000001,
  0x00002000,
  0x00800000,
  0x00802001,
  0x00000080,
  0x00800000,
  0x00002001,
  0x00002080,
  0x00800081,
  0x00000001,
  0x00002080,
  0x00800080,
  0x00002000,
  0x00802080,
  0x00802081,
  0x00000081,
  0x00800080,
  0x00800001,
  0x00802000,
  0x00802081,
  0x00000081,
  0x00000000,
  0x00000000,
  0x00802000,
  0x00002080,
  0x00800080,
  0x00800081,
  0x00000001,
  0x00802001,
  0x00002081,
  0x00002081,
  0x00000080,
  0x00802081,
  0x00000081,
  0x00000001,
  0x00002000,
  0x00800001,
  0x00002001,
  0x00802080,
  0x00800081,
  0x00002001,
  0x00002080,
  0x00800000,
  0x00802001,
  0x00000080,
  0x00800000,
  0x00002000,
  0x00802080,
]);

final Uint32List _sp5 = Uint32List.fromList(<int>[
  0x00000100,
  0x02080100,
  0x02080000,
  0x42000100,
  0x00080000,
  0x00000100,
  0x40000000,
  0x02080000,
  0x40080100,
  0x00080000,
  0x02000100,
  0x40080100,
  0x42000100,
  0x42080000,
  0x00080100,
  0x40000000,
  0x02000000,
  0x40080000,
  0x40080000,
  0x00000000,
  0x40000100,
  0x42080100,
  0x42080100,
  0x02000100,
  0x42080000,
  0x40000100,
  0x00000000,
  0x42000000,
  0x02080100,
  0x02000000,
  0x42000000,
  0x00080100,
  0x00080000,
  0x42000100,
  0x00000100,
  0x02000000,
  0x40000000,
  0x02080000,
  0x42000100,
  0x40080100,
  0x02000100,
  0x40000000,
  0x42080000,
  0x02080100,
  0x40080100,
  0x00000100,
  0x02000000,
  0x42080000,
  0x42080100,
  0x00080100,
  0x42000000,
  0x42080100,
  0x02080000,
  0x00000000,
  0x40080000,
  0x42000000,
  0x00080100,
  0x02000100,
  0x40000100,
  0x00080000,
  0x00000000,
  0x40080000,
  0x02080100,
  0x40000100,
]);

final Uint32List _sp6 = Uint32List.fromList(<int>[
  0x20000010,
  0x20400000,
  0x00004000,
  0x20404010,
  0x20400000,
  0x00000010,
  0x20404010,
  0x00400000,
  0x20004000,
  0x00404010,
  0x00400000,
  0x20000010,
  0x00400010,
  0x20004000,
  0x20000000,
  0x00004010,
  0x00000000,
  0x00400010,
  0x20004010,
  0x00004000,
  0x00404000,
  0x20004010,
  0x00000010,
  0x20400010,
  0x20400010,
  0x00000000,
  0x00404010,
  0x20404000,
  0x00004010,
  0x00404000,
  0x20404000,
  0x20000000,
  0x20004000,
  0x00000010,
  0x20400010,
  0x00404000,
  0x20404010,
  0x00400000,
  0x00004010,
  0x20000010,
  0x00400000,
  0x20004000,
  0x20000000,
  0x00004010,
  0x20000010,
  0x20404010,
  0x00404000,
  0x20400000,
  0x00404010,
  0x20404000,
  0x00000000,
  0x20400010,
  0x00000010,
  0x00004000,
  0x20400000,
  0x00404010,
  0x00004000,
  0x00400010,
  0x20004010,
  0x00000000,
  0x20404000,
  0x20000000,
  0x00400010,
  0x20004010,
]);

final Uint32List _sp7 = Uint32List.fromList(<int>[
  0x00200000,
  0x04200002,
  0x04000802,
  0x00000000,
  0x00000800,
  0x04000802,
  0x00200802,
  0x04200800,
  0x04200802,
  0x00200000,
  0x00000000,
  0x04000002,
  0x00000002,
  0x04000000,
  0x04200002,
  0x00000802,
  0x04000800,
  0x00200802,
  0x00200002,
  0x04000800,
  0x04000002,
  0x04200000,
  0x04200800,
  0x00200002,
  0x04200000,
  0x00000800,
  0x00000802,
  0x04200802,
  0x00200800,
  0x00000002,
  0x04000000,
  0x00200800,
  0x04000000,
  0x00200800,
  0x00200000,
  0x04000802,
  0x04000802,
  0x04200002,
  0x04200002,
  0x00000002,
  0x00200002,
  0x04000000,
  0x04000800,
  0x00200000,
  0x04200800,
  0x00000802,
  0x00200802,
  0x04200800,
  0x00000802,
  0x04000002,
  0x04200802,
  0x04200000,
  0x00200800,
  0x00000000,
  0x00000002,
  0x04200802,
  0x00000000,
  0x00200802,
  0x04200000,
  0x00000800,
  0x04000002,
  0x04000800,
  0x00000800,
  0x00200002,
]);

final Uint32List _sp8 = Uint32List.fromList(<int>[
  0x10001040,
  0x00001000,
  0x00040000,
  0x10041040,
  0x10000000,
  0x10001040,
  0x00000040,
  0x10000000,
  0x00040040,
  0x10040000,
  0x10041040,
  0x00041000,
  0x10041000,
  0x00041040,
  0x00001000,
  0x00000040,
  0x10040000,
  0x10000040,
  0x10001000,
  0x00001040,
  0x00041000,
  0x00040040,
  0x10040040,
  0x10041000,
  0x00001040,
  0x00000000,
  0x00000000,
  0x10040040,
  0x10000040,
  0x10001000,
  0x00041040,
  0x00040000,
  0x00041040,
  0x00040000,
  0x10041000,
  0x00001000,
  0x00000040,
  0x10040040,
  0x00001000,
  0x00041040,
  0x10001000,
  0x00000040,
  0x10000040,
  0x10040000,
  0x10040040,
  0x10000000,
  0x00040000,
  0x10001040,
  0x00000000,
  0x10041040,
  0x00040040,
  0x10000040,
  0x10040000,
  0x10001000,
  0x10001040,
  0x00000000,
  0x10041040,
  0x00041000,
  0x00041000,
  0x00001040,
  0x00001040,
  0x00040040,
  0x10000000,
  0x10041000,
]);
