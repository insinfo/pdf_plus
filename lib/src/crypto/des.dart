import 'dart:typed_data';

import 'base.dart';

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

  static List<int> generateWorkingKey(bool encrypting, Uint8List key) {
    if (key.length < 8) {
      throw ArgumentError('Chave DES deve ter 8 bytes.');
    }
    final key64 = _bytesToInt64(key, 0);
    final permuted = _permute(key64, _pc1, 64);
    int c = (permuted >> 28) & 0x0FFFFFFF;
    int d = permuted & 0x0FFFFFFF;
    final subKeys = List<int>.filled(16, 0);
    for (int i = 0; i < 16; i++) {
      c = _rotl28(c, _rotations[i]);
      d = _rotl28(d, _rotations[i]);
      final cd = (c << 28) | d;
      subKeys[i] = _permute(cd, _pc2, 56);
    }
    if (!encrypting) {
      return subKeys.reversed.toList(growable: false);
    }
    return subKeys;
  }

  static void processBlockWithKey(
    Uint8List inp,
    int inpOff,
    Uint8List out,
    int outOff,
    List<int> workingKey,
  ) {
    final block = _bytesToInt64(inp, inpOff);
    final processed = _desFunc(block, workingKey);
    _int64ToBytes(processed, out, outOff);
  }

  static int _desFunc(int block, List<int> subKeys) {
    final ip = _permute(block, _ip, 64);
    int l = (ip >> 32) & 0xFFFFFFFF;
    int r = ip & 0xFFFFFFFF;
    for (int i = 0; i < 16; i++) {
      final temp = r;
      final f = _feistel(r, subKeys[i]);
      r = (l ^ f) & 0xFFFFFFFF;
      l = temp;
    }
    final preOutput = ((r & 0xFFFFFFFF) << 32) | (l & 0xFFFFFFFF);
    return _permute(preOutput, _fp, 64);
  }
}

int _feistel(int r, int subKey) {
  final e = _permute(r, _e, 32);
  final x = e ^ subKey;
  int output = 0;
  for (int i = 0; i < 8; i++) {
    final sixBits = (x >> (42 - 6 * i)) & 0x3F;
    final row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01);
    final col = (sixBits >> 1) & 0x0F;
    final sVal = _sBoxes[i][row * 16 + col];
    output = (output << 4) | sVal;
  }
  return _permute(output, _p, 32);
}

int _rotl28(int x, int n) {
  return ((x << n) | (x >> (28 - n))) & 0x0FFFFFFF;
}

int _bytesToInt64(Uint8List b, int off) {
  int v = 0;
  for (int i = 0; i < 8; i++) {
    v = (v << 8) | (b[off + i] & 0xFF);
  }
  return v;
}

void _int64ToBytes(int v, Uint8List out, int off) {
  for (int i = 7; i >= 0; i--) {
    out[off + i] = v & 0xFF;
    v >>= 8;
  }
}

int _permute(int input, List<int> table, int inputBits) {
  int output = 0;
  for (int i = 0; i < table.length; i++) {
    final pos = table[i];
    final bit = (input >> (inputBits - pos)) & 0x01;
    output = (output << 1) | bit;
  }
  return output;
}

const List<int> _rotations = <int>[
  1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
];

const List<int> _pc1 = <int>[
  57, 49, 41, 33, 25, 17, 9,
  1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27,
  19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,
  7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29,
  21, 13, 5, 28, 20, 12, 4,
];

const List<int> _pc2 = <int>[
  14, 17, 11, 24, 1, 5,
  3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8,
  16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32,
];

const List<int> _ip = <int>[
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7,
];

const List<int> _fp = <int>[
  40, 8, 48, 16, 56, 24, 64, 32,
  39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30,
  37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28,
  35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26,
  33, 1, 41, 9, 49, 17, 57, 25,
];

const List<int> _e = <int>[
  32, 1, 2, 3, 4, 5,
  4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13,
  12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21,
  20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29,
  28, 29, 30, 31, 32, 1,
];

const List<int> _p = <int>[
  16, 7, 20, 21,
  29, 12, 28, 17,
  1, 15, 23, 26,
  5, 18, 31, 10,
  2, 8, 24, 14,
  32, 27, 3, 9,
  19, 13, 30, 6,
  22, 11, 4, 25,
];

const List<List<int>> _sBoxes = <List<int>>[
  <int>[
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
  ],
  <int>[
    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
  ],
  <int>[
    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
  ],
  <int>[
    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
  ],
  <int>[
    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
  ],
  <int>[
    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
  ],
  <int>[
    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
  ],
  <int>[
    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
  ],
];
