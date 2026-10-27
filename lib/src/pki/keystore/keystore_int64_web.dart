import 'dart:typed_data';

const int _twoTo32 = 0x100000000;

/// Signed big-endian int64 at [offset], from two uint32 reads.
int keystoreReadInt64(ByteData data, int offset) {
  final hi = data.getUint32(offset);
  final lo = data.getUint32(offset + 4);
  if (hi & 0x80000000 == 0) return hi * _twoTo32 + lo;
  return -(((~hi) & 0xFFFFFFFF) * _twoTo32 + ((~lo) & 0xFFFFFFFF) + 1);
}

/// [value] as 8 big-endian bytes. Division instead of `>> 32`, which
/// truncates to 32 bits in JavaScript; exact for |value| < 2^53.
Uint8List keystoreInt64ToBytesBigEndian(int value) {
  final hi = (value / _twoTo32).floor();
  final lo = value - hi * _twoTo32;
  return (ByteData(8)
        ..setUint32(0, hi & 0xFFFFFFFF)
        ..setUint32(4, lo))
      .buffer
      .asUint8List();
}
