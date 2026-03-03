import 'dart:typed_data';

import 'base64_impl.dart' if (dart.library.html) 'base64_web.dart' as impl;

String base64EncodeBytes(Uint8List bytes) {
  return impl.base64EncodeBytesImpl(bytes);
}

Uint8List base64DecodeToBytes(String value) {
  return impl.base64DecodeToBytesImpl(value);
}

String base64EncodeUtf8(String value) {
  return impl.base64EncodeUtf8Impl(value);
}

String base64DecodeUtf8(String value) {
  return impl.base64DecodeUtf8Impl(value);
}
