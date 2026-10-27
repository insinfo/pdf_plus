import 'dart:typed_data';

export 'keystore_int64.dart';

/// Java `DataOutput.writeUTF` body ("modified UTF-8"): U+0000 is `C0 80` and
/// each UTF-16 code unit, surrogates included, is encoded on its own.
Uint8List keystoreModifiedUtf8Encode(String s) {
  final out = <int>[];
  for (final c in s.codeUnits) {
    if (c != 0 && c <= 0x7F) {
      out.add(c);
    } else if (c <= 0x7FF) {
      out
        ..add(0xC0 | ((c >> 6) & 0x1F))
        ..add(0x80 | (c & 0x3F));
    } else {
      out
        ..add(0xE0 | ((c >> 12) & 0x0F))
        ..add(0x80 | ((c >> 6) & 0x3F))
        ..add(0x80 | (c & 0x3F));
    }
  }
  return Uint8List.fromList(out);
}

/// Inverse of [keystoreModifiedUtf8Encode] (Java `DataInput.readUTF` body).
String keystoreModifiedUtf8Decode(Uint8List bytes) {
  final units = <int>[];
  var i = 0;
  while (i < bytes.length) {
    final b = bytes[i];
    if (b < 0x80) {
      units.add(b);
      i += 1;
    } else if ((b & 0xE0) == 0xC0 && i + 1 < bytes.length) {
      units.add(((b & 0x1F) << 6) | (bytes[i + 1] & 0x3F));
      i += 2;
    } else if ((b & 0xF0) == 0xE0 && i + 2 < bytes.length) {
      units.add(((b & 0x0F) << 12) |
          ((bytes[i + 1] & 0x3F) << 6) |
          (bytes[i + 2] & 0x3F));
      i += 3;
    } else {
      throw FormatException('Invalid modified UTF-8 byte 0x'
          '${b.toRadixString(16)} at $i');
    }
  }
  return String.fromCharCodes(units);
}
