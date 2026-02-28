import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/asn1/asn1.dart';

String? asn1ObjectIdentifierToString(ASN1Object obj) {
  if (obj is! ASN1ObjectIdentifier) return null;
  final dynamic dyn = obj;
  try {
    final v = dyn.objectIdentifierAsString;
    if (v != null) return v.toString();
  } catch (_) {}
  try {
    final v = dyn.oidName;
    if (v != null) return v.toString();
  } catch (_) {}
  try {
    final s = obj.toString();
    const prefix = 'ObjectIdentifier(';
    if (s.startsWith(prefix) && s.endsWith(')')) {
      return s.substring(prefix.length, s.length - 1);
    }
    final m = RegExp(r'ObjectIdentifier\(([^)]+)\)').firstMatch(s);
    if (m != null) return m.group(1);
    return s;
  } catch (_) {
    return null;
  }
}

DateTime? parseAsn1TimeLoose(ASN1Object obj) {
  Uint8List? bytes;
  if (obj is ASN1GeneralizedTime || obj is ASN1UtcTime) {
    bytes = obj.valueBytes();
  } else {
    try {
      final dynamic dyn = obj;
      final b = dyn.valueBytes;
      if (b is Uint8List) bytes = b;
      if (b is List<int>) bytes = Uint8List.fromList(b);
    } catch (_) {}
  }
  if (bytes == null || bytes.isEmpty) {
    bytes = _readAsn1StringFromEncoded(obj);
  }
  if (bytes == null || bytes.isEmpty) return null;

  final text = String.fromCharCodes(bytes).trim();
  if (text.isEmpty) return null;
  try {
    if (text.endsWith('Z')) {
      final t = text.substring(0, text.length - 1);
      if (t.length == 12) {
        final year = int.parse(t.substring(0, 2));
        final fullYear = year >= 50 ? 1900 + year : 2000 + year;
        return DateTime.utc(
          fullYear,
          int.parse(t.substring(2, 4)),
          int.parse(t.substring(4, 6)),
          int.parse(t.substring(6, 8)),
          int.parse(t.substring(8, 10)),
          int.parse(t.substring(10, 12)),
        );
      }
      if (t.length == 14) {
        return DateTime.utc(
          int.parse(t.substring(0, 4)),
          int.parse(t.substring(4, 6)),
          int.parse(t.substring(6, 8)),
          int.parse(t.substring(8, 10)),
          int.parse(t.substring(10, 12)),
          int.parse(t.substring(12, 14)),
        );
      }
    }
    return DateTime.tryParse(text);
  } catch (_) {
    return null;
  }
}

Uint8List? _readAsn1StringFromEncoded(ASN1Object obj) {
  try {
    final encoded = obj.encodedBytes;
    if (encoded.length < 2) return null;
    var idx = 1;
    var length = 0;
    final lenByte = encoded[idx];
    idx += 1;
    if (lenByte & 0x80 == 0) {
      length = lenByte;
    } else {
      final count = lenByte & 0x7f;
      if (encoded.length < idx + count) return null;
      for (var i = 0; i < count; i++) {
        length = (length << 8) | encoded[idx + i];
      }
      idx += count;
    }
    if (encoded.length < idx + length) return null;
    return encoded.sublist(idx, idx + length);
  } catch (_) {
    return null;
  }
}
