import 'dart:typed_data';

const List<int> endStreamToken = <int>[
  0x65, 0x6E, 0x64, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6D // endstream
];

String decodePdfString(Uint8List bytes) {
  if (bytes.length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF) {
    final codeUnits = <int>[];
    for (int i = 2; i + 1 < bytes.length; i += 2) {
      codeUnits.add((bytes[i] << 8) | bytes[i + 1]);
    }
    return String.fromCharCodes(codeUnits);
  }
  return String.fromCharCodes(bytes);
}

({String value, int nextIndex}) readName(Uint8List bytes, int i, int end) {
  final buffer = StringBuffer();
  buffer.writeCharCode(bytes[i]);
  i++;
  while (i < end) {
    final b = bytes[i];
    if (isWhitespace(b) ||
        b == 0x3C ||
        b == 0x3E ||
        b == 0x2F ||
        b == 0x28 ||
        b == 0x29 ||
        b == 0x5B ||
        b == 0x5D ||
        b == 0x7B ||
        b == 0x7D ||
        b == 0x25) {
      break;
    }
    if (b == 0x23 /* # */ && i + 2 < end) {
      final h1 = bytes[i + 1];
      final h2 = bytes[i + 2];
      if (isHexDigit(h1) && isHexDigit(h2)) {
        final v = (hexValue(h1) << 4) | hexValue(h2);
        buffer.writeCharCode(v);
        i += 3;
        continue;
      }
    }
    buffer.writeCharCode(b);
    i++;
  }
  return (value: buffer.toString(), nextIndex: i);
}

bool matchToken(Uint8List bytes, int index, List<int> token) {
  if (index + token.length > bytes.length) return false;
  for (int i = 0; i < token.length; i++) {
    if (bytes[index + i] != token[i]) return false;
  }
  return true;
}

({Uint8List? id, int nextIndex}) readIdArray(
  Uint8List bytes,
  int start,
  int end,
) {
  int i = start;
  if (bytes[i] != 0x5B) return (id: null, nextIndex: i);
  i++;
  i = skipPdfWsAndComments(bytes, i, end);
  if (i >= end || bytes[i] != 0x3C) return (id: null, nextIndex: i);
  final id1 = readHexString(bytes, i, end);
  i = id1.nextIndex;
  return (id: id1.bytes, nextIndex: i);
}

({Uint8List bytes, int nextIndex}) readHexString(
  Uint8List bytes,
  int start,
  int end,
) {
  int i = start;
  if (bytes[i] != 0x3C) {
    throw StateError('Hex string inválida');
  }
  i++;
  final hex = <int>[];
  while (i < end && bytes[i] != 0x3E) {
    final b = bytes[i];
    if (isWhitespace(b)) {
      i++;
      continue;
    }
    hex.add(b);
    i++;
  }
  if (i >= end) throw StateError('Hex string inválida');
  i++;
  return (bytes: hexToBytes(hex), nextIndex: i);
}

Uint8List hexToBytes(List<int> hexBytes) {
  final out = Uint8List((hexBytes.length + 1) ~/ 2);
  int oi = 0;
  for (int i = 0; i < hexBytes.length; i += 2) {
    final hi = hexBytes[i];
    final lo = (i + 1 < hexBytes.length) ? hexBytes[i + 1] : 0x30;
    out[oi++] = (hexValue(hi) << 4) | hexValue(lo);
  }
  return out;
}

int hexValue(int b) {
  if (b >= 0x30 && b <= 0x39) return b - 0x30;
  if (b >= 0x41 && b <= 0x46) return b - 0x41 + 10;
  if (b >= 0x61 && b <= 0x66) return b - 0x61 + 10;
  return 0;
}

({Uint8List bytes, int nextIndex}) readLiteralString(
  Uint8List bytes,
  int start,
  int end,
) {
  int i = start;
  if (bytes[i] != 0x28) {
    return (bytes: Uint8List(0), nextIndex: i);
  }
  i++;
  final out = <int>[];
  int depth = 1;
  while (i < end && depth > 0) {
    final b = bytes[i];
    if (b == 0x5C /* \\ */) {
      if (i + 1 >= end) break;
      final n = bytes[i + 1];
      if (n == 0x6E) {
        out.add(0x0A);
        i += 2;
        continue;
      }
      if (n == 0x72) {
        out.add(0x0D);
        i += 2;
        continue;
      }
      if (n == 0x74) {
        out.add(0x09);
        i += 2;
        continue;
      }
      if (n == 0x62) {
        out.add(0x08);
        i += 2;
        continue;
      }
      if (n == 0x66) {
        out.add(0x0C);
        i += 2;
        continue;
      }
      if (n == 0x28 || n == 0x29 || n == 0x5C) {
        out.add(n);
        i += 2;
        continue;
      }
      // octal sequence
      if (n >= 0x30 && n <= 0x37) {
        int val = n - 0x30;
        int count = 1;
        int j = i + 2;
        while (j < end && count < 3) {
          final o = bytes[j];
          if (o < 0x30 || o > 0x37) break;
          val = (val << 3) | (o - 0x30);
          j++;
          count++;
        }
        out.add(val & 0xFF);
        i = j;
        continue;
      }
      i += 2;
      continue;
    }
    if (b == 0x28) {
      depth++;
      out.add(b);
      i++;
      continue;
    }
    if (b == 0x29) {
      depth--;
      if (depth > 0) out.add(b);
      i++;
      continue;
    }
    out.add(b);
    i++;
  }
  return (bytes: Uint8List.fromList(out), nextIndex: i);
}

int lastIndexOfSequence(
  Uint8List bytes,
  List<int> pattern,
  int start,
  int end,
) {
  if (pattern.isEmpty) return -1;
  final int max = end - pattern.length;
  for (int i = max; i >= start; i--) {
    var ok = true;
    for (int j = 0; j < pattern.length; j++) {
      if (bytes[i + j] != pattern[j]) {
        ok = false;
        break;
      }
    }
    if (ok) return i;
  }
  return -1;
}

int indexOfSequence(
  Uint8List bytes,
  List<int> pattern,
  int start,
  int end,
) {
  return indexOfSequenceBmh(bytes, pattern, start, end);
}

int indexOfSequenceBmh(
  Uint8List bytes,
  List<int> pattern,
  int start,
  int end,
) {
  if (pattern.isEmpty) return -1;
  final m = pattern.length;
  final last = m - 1;
  final limit = end - m;
  if (limit < start) return -1;

  final skip = List<int>.filled(256, m);
  for (int i = 0; i < last; i++) {
    skip[pattern[i] & 0xFF] = last - i;
  }

  int i = start;
  while (i <= limit) {
    int j = last;
    while (j >= 0 && bytes[i + j] == pattern[j]) {
      j--;
    }
    if (j < 0) return i;
    i += skip[bytes[i + last] & 0xFF];
  }
  return -1;
}

int skipPdfWsAndComments(Uint8List bytes, int i, int end) {
  if (i < end) {
    final b = bytes[i];
    if (!isWhitespace(b) && b != 0x25) {
      return i;
    }
  }
  while (i < end) {
    final b = bytes[i];
    if (isWhitespace(b)) {
      i++;
      continue;
    }
    if (b == 0x25 /* % */) {
      i++;
      while (i < end) {
        final c = bytes[i];
        if (c == 0x0A || c == 0x0D) break;
        i++;
      }
      continue;
    }
    break;
  }
  return i;
}

({int value, int nextIndex}) readIntFast(Uint8List bytes, int start, int end) {
  int i = start;
  if (i < end && bytes[i] == 0x2B) i++;

  int value = 0;
  bool hasDigits = false;

  while (i < end) {
    final b = bytes[i];
    if (b >= 0x30 && b <= 0x39) {
      if (value > 900719925474099) {
        i++;
        continue;
      }
      value = (value * 10) + (b - 0x30);
      hasDigits = true;
      i++;
    } else {
      break;
    }
  }

  if (!hasDigits) return (value: -1, nextIndex: start);
  return (value: value, nextIndex: i);
}

bool matchBytes(Uint8List bytes, int offset, List<int> target) {
  if (offset + target.length > bytes.length) return false;
  for (int i = 0; i < target.length; i++) {
    if (bytes[offset + i] != target[i]) return false;
  }
  return true;
}

int skipTokenRaw(Uint8List bytes, int i, int end) {
  i = skipPdfWsAndComments(bytes, i, end);
  if (i >= end) return i;

  final b = bytes[i];

  if (b == 0x2F) {
    i++;
    while (i < end) {
      final c = bytes[i];
      if (isWhitespace(c) ||
          c == 0x2F ||
          c == 0x3C ||
          c == 0x3E ||
          c == 0x28 ||
          c == 0x29 ||
          c == 0x5B ||
          c == 0x5D ||
          c == 0x25) {
        break;
      }
      i++;
    }
    return i;
  }

  if (b == 0x28) {
    int depth = 1;
    i++;
    while (i < end && depth > 0) {
      final c = bytes[i];
      if (c == 0x5C) {
        i += 2;
        continue;
      }
      if (c == 0x28) depth++;
      if (c == 0x29) depth--;
      i++;
    }
    return i;
  }

  if (b == 0x3C && i + 1 < end && bytes[i + 1] == 0x3C) {
    int depth = 1;
    i += 2;
    while (i + 1 < end && depth > 0) {
      if (bytes[i] == 0x3C && bytes[i + 1] == 0x3C) {
        depth++;
        i += 2;
        continue;
      }
      if (bytes[i] == 0x3E && bytes[i + 1] == 0x3E) {
        depth--;
        i += 2;
        continue;
      }
      i++;
    }
    return i;
  }

  if (b == 0x3C) {
    i++;
    while (i < end && bytes[i] != 0x3E) i++;
    if (i < end) i++;
    return i;
  }

  if (b == 0x5B) {
    int depth = 1;
    i++;
    while (i < end && depth > 0) {
      if (bytes[i] == 0x5B) depth++;
      if (bytes[i] == 0x5D) depth--;
      i++;
    }
    return i;
  }

  while (i < end) {
    final c = bytes[i];
    if (isWhitespace(c) ||
        c == 0x2F ||
        c == 0x28 ||
        c == 0x3C ||
        c == 0x5B ||
        c == 0x25) break;
    i++;
  }
  return i;
}

({int value, int nextIndex}) readInt(Uint8List bytes, int i, int end) {
  if (i >= end) {
    throw StateError('Fim inesperado ao ler inteiro');
  }
  var neg = false;
  if (bytes[i] == 0x2B /* + */) {
    i++;
  } else if (bytes[i] == 0x2D /* - */) {
    neg = true;
    i++;
  }
  var value = 0;
  var digits = 0;
  while (i < end) {
    final b = bytes[i];
    if (!isDigit(b)) break;
    value = (value * 10) + (b - 0x30);
    i++;
    digits++;
  }
  if (digits == 0) {
    throw StateError('Inteiro inválido');
  }
  return (value: neg ? -value : value, nextIndex: i);
}

bool isDigit(int b) => b >= 0x30 && b <= 0x39;

bool isHexDigit(int b) =>
  (b >= 0x30 && b <= 0x39) ||
  (b >= 0x41 && b <= 0x46) ||
  (b >= 0x61 && b <= 0x66);

bool isWhitespace(int b) =>
    b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0C || b == 0x0D || b == 0x20;

bool isDelimiter(Uint8List bytes, int index) {
  if (index >= bytes.length) return true;
  final b = bytes[index];
  return isWhitespace(b) ||
      b == 0x3C ||
      b == 0x3E ||
      b == 0x2F ||
      b == 0x28 ||
      b == 0x29;
}
