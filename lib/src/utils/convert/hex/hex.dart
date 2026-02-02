import 'dart:convert';

import 'decoder.dart';
import 'encoder.dart';

export 'decoder.dart' hide hexDecoder;
export 'encoder.dart' hide hexEncoder;

/// The canonical instance of [HexCodec].
const hex = HexCodec._();

/// A codec that converts byte arrays to and from hexadecimal strings, following
/// [the Base16 spec](https://tools.ietf.org/html/rfc4648#section-8).
///
/// This should be used via the [hex] field.
class HexCodec extends Codec<List<int>, String> {
  @override
  HexEncoder get encoder => hexEncoder;
  @override
  HexDecoder get decoder => hexDecoder;

  const HexCodec._();
}
