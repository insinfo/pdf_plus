import 'dart:typed_data';

import 'sha1.dart';

Uint8List hmacSha1(Uint8List key, Uint8List data) {
  const blockSize = 64;
  Uint8List k = key;
  if (k.length > blockSize) {
    k = Uint8List.fromList(sha1.convert(k).bytes);
  }
  if (k.length < blockSize) {
    final padded = Uint8List(blockSize);
    padded.setRange(0, k.length, k);
    k = padded;
  }

  final oKeyPad = Uint8List(blockSize);
  final iKeyPad = Uint8List(blockSize);
  for (int i = 0; i < blockSize; i++) {
    final b = k[i];
    oKeyPad[i] = b ^ 0x5c;
    iKeyPad[i] = b ^ 0x36;
  }

  final innerInput = Uint8List(iKeyPad.length + data.length);
  innerInput.setRange(0, iKeyPad.length, iKeyPad);
  innerInput.setRange(iKeyPad.length, innerInput.length, data);
  final inner = sha1.convert(innerInput).bytes;

  final outerInput = Uint8List(oKeyPad.length + inner.length);
  outerInput.setRange(0, oKeyPad.length, oKeyPad);
  outerInput.setRange(oKeyPad.length, outerInput.length, inner);
  final outer = sha1.convert(outerInput).bytes;
  return Uint8List.fromList(outer);
}
