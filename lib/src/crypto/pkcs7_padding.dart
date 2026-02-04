import 'dart:typed_data';

class PKCS7Padding {
  int addPadding(Uint8List data, int offset) {
    final padLen = data.length - offset;
    for (int i = offset; i < data.length; i++) {
      data[i] = padLen;
    }
    return padLen;
  }

  int padCount(Uint8List data) {
    if (data.isEmpty) {
      throw StateError('Invalid PKCS7 padding (empty data).');
    }
    final padLen = data.last;
    if (padLen <= 0 || padLen > data.length) {
      throw StateError('Invalid PKCS7 padding (length).');
    }
    for (int i = data.length - padLen; i < data.length; i++) {
      if (data[i] != padLen) {
        throw StateError('Invalid PKCS7 padding (bytes).');
      }
    }
    return padLen;
  }
}
