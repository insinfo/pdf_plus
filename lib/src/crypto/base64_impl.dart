import 'dart:convert';
import 'dart:typed_data';

const int _pad = 61;

final Uint8List _encodeTable = Uint8List.fromList(
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.codeUnits,
);

final Uint8List _decodeTable = _buildDecodeTable();

String base64EncodeBytesImpl(Uint8List bytes) {
  final len = bytes.length;
  if (len == 0) return '';

  final outLen = ((len + 2) ~/ 3) * 4;
  final out = Uint8List(outLen);

  var i = 0;
  var j = 0;
  final remainder = len % 3;
  final mainLen = len - remainder;

  while (i < mainLen) {
    final b1 = bytes[i++];
    final b2 = bytes[i++];
    final b3 = bytes[i++];

    out[j++] = _encodeTable[b1 >> 2];
    out[j++] = _encodeTable[((b1 & 0x03) << 4) | (b2 >> 4)];
    out[j++] = _encodeTable[((b2 & 0x0f) << 2) | (b3 >> 6)];
    out[j++] = _encodeTable[b3 & 0x3f];
  }

  if (remainder == 1) {
    final b1 = bytes[i];
    out[j++] = _encodeTable[b1 >> 2];
    out[j++] = _encodeTable[(b1 & 0x03) << 4];
    out[j++] = _pad;
    out[j++] = _pad;
  } else if (remainder == 2) {
    final b1 = bytes[i++];
    final b2 = bytes[i];
    out[j++] = _encodeTable[b1 >> 2];
    out[j++] = _encodeTable[((b1 & 0x03) << 4) | (b2 >> 4)];
    out[j++] = _encodeTable[(b2 & 0x0f) << 2];
    out[j++] = _pad;
  }

  return String.fromCharCodes(out);
}

Uint8List base64DecodeToBytesImpl(String value) {
  if (value.isEmpty) return Uint8List(0);

  final length = value.length;
  var hasWhitespace = false;
  for (var i = 0; i < length; i++) {
    final char = value.codeUnitAt(i);
    if (_isWhitespace(char)) {
      hasWhitespace = true;
      break;
    }
  }

  if (!hasWhitespace) {
    return _decodeNoWhitespace(value);
  }

  final chars = _normalizedBase64CodeUnits(value);
  return _decodeNormalized(chars);
}

String base64EncodeUtf8Impl(String value) {
  final bytes = Uint8List.fromList(utf8.encode(value));
  return base64EncodeBytesImpl(bytes);
}

String base64DecodeUtf8Impl(String value) {
  final bytes = base64DecodeToBytesImpl(value);
  return utf8.decode(bytes);
}

Uint8List _buildDecodeTable() {
  final table = Uint8List(256)..fillRange(0, 256, 255);
  for (var i = 0; i < _encodeTable.length; i++) {
    table[_encodeTable[i]] = i;
  }
  table[_pad] = 0;
  return table;
}

Uint8List _normalizedBase64CodeUnits(String value) {
  final raw = value.codeUnits;
  if (raw.isEmpty) return Uint8List(0);

  var hasWhitespace = false;
  for (var i = 0; i < raw.length; i++) {
    if (_isWhitespace(raw[i])) {
      hasWhitespace = true;
      break;
    }
  }

  if (!hasWhitespace) {
    return Uint8List.fromList(raw);
  }

  var kept = 0;
  for (var i = 0; i < raw.length; i++) {
    if (!_isWhitespace(raw[i])) kept++;
  }

  final out = Uint8List(kept);
  var j = 0;
  for (var i = 0; i < raw.length; i++) {
    final c = raw[i];
    if (!_isWhitespace(c)) {
      out[j++] = c;
    }
  }
  return out;
}

Uint8List _decodeNoWhitespace(String value) {
  final totalLen = value.length;
  if (totalLen == 0) return Uint8List(0);
  if (totalLen % 4 != 0) {
    throw const FormatException('Invalid Base64 length');
  }

  var outputLen = (totalLen ~/ 4) * 3;
  if (value.codeUnitAt(totalLen - 1) == _pad) outputLen--;
  if (value.codeUnitAt(totalLen - 2) == _pad) outputLen--;

  final out = Uint8List(outputLen);
  final table = _decodeTable;

  var i = 0;
  var j = 0;
  final lastBlockStart = totalLen - 4;
  while (i < lastBlockStart) {
    final a = value.codeUnitAt(i++);
    final b = value.codeUnitAt(i++);
    final c = value.codeUnitAt(i++);
    final d = value.codeUnitAt(i++);

    final c1 = _decodeValueWithTable(a, table);
    final c2 = _decodeValueWithTable(b, table);
    final c3 = _decodeValueWithTable(c, table);
    final c4 = _decodeValueWithTable(d, table);

    out[j++] = (c1 << 2) | (c2 >> 4);
    out[j++] = ((c2 & 0x0f) << 4) | (c3 >> 2);
    out[j++] = ((c3 & 0x03) << 6) | c4;
  }

  final a = value.codeUnitAt(i++);
  final b = value.codeUnitAt(i++);
  final c = value.codeUnitAt(i++);
  final d = value.codeUnitAt(i++);

  final c1 = _decodeValueWithTable(a, table);
  final c2 = _decodeValueWithTable(b, table);

  if (c == _pad) {
    if (d != _pad) {
      throw const FormatException('Invalid Base64 padding');
    }
    out[j++] = (c1 << 2) | (c2 >> 4);
  } else if (d == _pad) {
    final c3 = _decodeValueWithTable(c, table);
    out[j++] = (c1 << 2) | (c2 >> 4);
    if (j < out.length) {
      out[j++] = ((c2 & 0x0f) << 4) | (c3 >> 2);
    }
  } else {
    final c3 = _decodeValueWithTable(c, table);
    final c4 = _decodeValueWithTable(d, table);
    out[j++] = (c1 << 2) | (c2 >> 4);
    if (j < out.length) {
      out[j++] = ((c2 & 0x0f) << 4) | (c3 >> 2);
    }
    if (j < out.length) {
      out[j++] = ((c3 & 0x03) << 6) | c4;
    }
  }

  return out;
}

Uint8List _decodeNormalized(Uint8List chars) {
  final totalLen = chars.length;
  if (totalLen == 0) return Uint8List(0);

  if (totalLen % 4 != 0) {
    throw const FormatException('Invalid Base64 length');
  }

  var outputLen = (totalLen ~/ 4) * 3;
  if (chars[totalLen - 1] == _pad) outputLen--;
  if (chars[totalLen - 2] == _pad) outputLen--;

  final out = Uint8List(outputLen);
  final table = _decodeTable;
  var i = 0;
  var j = 0;
  final lastBlockStart = totalLen - 4;

  while (i < lastBlockStart) {
    final c1 = _decodeValueWithTable(chars[i++], table);
    final c2 = _decodeValueWithTable(chars[i++], table);
    final c3 = _decodeValueWithTable(chars[i++], table);
    final c4 = _decodeValueWithTable(chars[i++], table);

    out[j++] = (c1 << 2) | (c2 >> 4);
    out[j++] = ((c2 & 0x0f) << 4) | (c3 >> 2);
    out[j++] = ((c3 & 0x03) << 6) | c4;
  }

  final a = chars[i++];
  final b = chars[i++];
  final c = chars[i++];
  final d = chars[i++];

  final c1 = _decodeValueWithTable(a, table);
  final c2 = _decodeValueWithTable(b, table);

  if (c == _pad) {
    if (d != _pad) {
      throw const FormatException('Invalid Base64 padding');
    }
    out[j++] = (c1 << 2) | (c2 >> 4);
  } else if (d == _pad) {
    final c3 = _decodeValueWithTable(c, table);
    out[j++] = (c1 << 2) | (c2 >> 4);
    if (j < out.length) {
      out[j++] = ((c2 & 0x0f) << 4) | (c3 >> 2);
    }
  } else {
    final c3 = _decodeValueWithTable(c, table);
    final c4 = _decodeValueWithTable(d, table);
    out[j++] = (c1 << 2) | (c2 >> 4);
    if (j < out.length) {
      out[j++] = ((c2 & 0x0f) << 4) | (c3 >> 2);
    }
    if (j < out.length) {
      out[j++] = ((c3 & 0x03) << 6) | c4;
    }
  }

  return out;
}

bool _isWhitespace(int c) {
  return c == 0x20 || c == 0x0a || c == 0x0d || c == 0x09;
}

int _decodeValueWithTable(int c, Uint8List table) {
  if (c < 0 || c > 255) {
    throw const FormatException('Invalid Base64 character');
  }
  final value = table[c];
  if (value == 255) {
    throw const FormatException('Invalid Base64 character');
  }
  return value;
}
