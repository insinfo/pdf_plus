import 'dart:typed_data';

import 'pkcs12_decoder.dart';
import 'pkcs12_types.dart';

export 'pkcs12_types.dart';

final Pkcs12Decoder defaultPkcs12Decoder = createDefaultPkcs12Decoder();

Future<Pkcs12Bundle> decodePkcs12(
  Uint8List bytes, {
  required String password,
  Pkcs12Decoder? decoder,
}) {
  final effectiveDecoder = decoder ?? defaultPkcs12Decoder;
  return effectiveDecoder.decode(bytes, password: password);
}
