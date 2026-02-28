import 'dart:typed_data';

Uint8List keystoreInt64ToBytesBigEndian(int value) {
  final bd = ByteData(8);
  final hi = ((value >> 32) & 0xFFFFFFFF);
  final lo = (value & 0xFFFFFFFF);
  bd.setUint32(0, hi, Endian.big);
  bd.setUint32(4, lo, Endian.big);
  return bd.buffer.asUint8List();
}
