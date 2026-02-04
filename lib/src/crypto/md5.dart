import 'dart:typed_data';

import 'base.dart';

class MD5Digest extends Digest {
  static const int _blockSize = 64;

  final Uint32List _state = Uint32List(4);
  final Uint8List _buffer = Uint8List(_blockSize);
  int _bufferPos = 0;
  int _totalLength = 0;

  MD5Digest() {
    reset();
  }

  @override
  String get algorithmName => 'MD5';

  @override
  int get digestSize => 16;

  @override
  int get byteLength => _blockSize;

  @override
  void reset() {
    _state[0] = 0x67452301;
    _state[1] = 0xefcdab89;
    _state[2] = 0x98badcfe;
    _state[3] = 0x10325476;
    _bufferPos = 0;
    _totalLength = 0;
  }

  @override
  void updateByte(int inp) {
    _buffer[_bufferPos++] = inp & 0xFF;
    _totalLength++;
    if (_bufferPos == _blockSize) {
      _processBlock(_buffer);
      _bufferPos = 0;
    }
  }

  @override
  void update(Uint8List inp, int inpOff, int len) {
    var offset = inpOff;
    var remaining = len;
    while (remaining > 0) {
      final toCopy = (_blockSize - _bufferPos) < remaining
          ? (_blockSize - _bufferPos)
          : remaining;
      _buffer.setRange(_bufferPos, _bufferPos + toCopy, inp, offset);
      _bufferPos += toCopy;
      offset += toCopy;
      remaining -= toCopy;
      _totalLength += toCopy;
      if (_bufferPos == _blockSize) {
        _processBlock(_buffer);
        _bufferPos = 0;
      }
    }
  }

  @override
  int doFinal(Uint8List out, int outOff) {
    final bitLength = _totalLength * 8;

    updateByte(0x80);
    while (_bufferPos != 56) {
      if (_bufferPos > 56) {
        while (_bufferPos < _blockSize) {
          updateByte(0x00);
        }
      } else {
        updateByte(0x00);
      }
    }

    final lengthBytes = ByteData(8);
    lengthBytes.setUint32(0, bitLength & 0xFFFFFFFF, Endian.little);
    lengthBytes.setUint32(
        4, (bitLength >> 32) & 0xFFFFFFFF, Endian.little);
    update(lengthBytes.buffer.asUint8List(), 0, 8);

    final output = ByteData(16);
    output.setUint32(0, _state[0], Endian.little);
    output.setUint32(4, _state[1], Endian.little);
    output.setUint32(8, _state[2], Endian.little);
    output.setUint32(12, _state[3], Endian.little);

    out.setRange(outOff, outOff + 16, output.buffer.asUint8List());
    reset();
    return 16;
  }

  void _processBlock(Uint8List block) {
    final x = Uint32List(16);
    final bd = ByteData.sublistView(block);
    for (int i = 0; i < 16; i++) {
      x[i] = bd.getUint32(i * 4, Endian.little);
    }

    int a = _state[0];
    int b = _state[1];
    int c = _state[2];
    int d = _state[3];

    for (int i = 0; i < 64; i++) {
      int f;
      int g;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }

      final temp = d;
      d = c;
      c = b;
      final sum = (a + f + _k[i] + x[g]) & 0xFFFFFFFF;
      b = (b + _rotl32(sum, _s[i])) & 0xFFFFFFFF;
      a = temp;
    }

    _state[0] = (_state[0] + a) & 0xFFFFFFFF;
    _state[1] = (_state[1] + b) & 0xFFFFFFFF;
    _state[2] = (_state[2] + c) & 0xFFFFFFFF;
    _state[3] = (_state[3] + d) & 0xFFFFFFFF;
  }
}

int _rotl32(int x, int n) => ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF;

const List<int> _s = <int>[
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const List<int> _k = <int>[
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];
