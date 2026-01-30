import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

class JksParseResult {
  JksParseResult({required this.certificates, this.verified = false});

  final List<Uint8List> certificates;
  final bool verified;
}

JksParseResult parseJksCertificates(
  Uint8List bytes, {
  String password = '12345678',
  bool verifyIntegrity = false,
}) {
  final reader = _JksReader(bytes);
  final dataStart = reader.offset;

  final magic = reader.readInt32();
  if (magic != 0xFEEDFEED) {
    return JksParseResult(certificates: const <Uint8List>[]);
  }
  final version = reader.readInt32();
  if (version != 1 && version != 2) {
    return JksParseResult(certificates: const <Uint8List>[]);
  }

  final count = reader.readInt32();
  final certs = <Uint8List>[];

  for (int i = 0; i < count; i++) {
    final tag = reader.readInt32();
    final alias = reader.readUtf();
    reader.readInt64();

    if (tag == 1) {
      final keyLen = reader.readInt32();
      reader.readBytes(keyLen);
      final chainCount = reader.readInt32();
      for (int j = 0; j < chainCount; j++) {
        reader.readUtf();
        final certLen = reader.readInt32();
        final cert = reader.readBytes(certLen);
        certs.add(cert);
      }
    } else if (tag == 2) {
      reader.readUtf();
      final certLen = reader.readInt32();
      final cert = reader.readBytes(certLen);
      certs.add(cert);
    } else {
      // Unknown entry; attempt to continue
    }

    if (alias.isEmpty) {
      // keep analyzer happy for unused alias
    }
  }

  var verified = false;
  if (verifyIntegrity && reader.remaining >= 20) {
    final dataEnd = reader.offset;
    final data = bytes.sublist(dataStart, dataEnd);
    final expected = bytes.sublist(dataEnd, dataEnd + 20);
    final computed = _computeJksDigest(data, password);
    verified = _bytesEqual(expected, computed);
  }

  return JksParseResult(certificates: certs, verified: verified);
}

Uint8List _computeJksDigest(Uint8List data, String password) {
  final passwordBytes = _jksPasswordBytes(password);
  final magic = utf8.encode('Mighty Aphrodite');
  final input = Uint8List(passwordBytes.length + magic.length + data.length);
  var offset = 0;
  input.setRange(offset, offset + passwordBytes.length, passwordBytes);
  offset += passwordBytes.length;
  input.setRange(offset, offset + magic.length, magic);
  offset += magic.length;
  input.setRange(offset, offset + data.length, data);
  final digest = crypto.sha1.convert(input).bytes;
  return Uint8List.fromList(digest);
}

Uint8List _jksPasswordBytes(String password) {
  final units = password.codeUnits;
  final out = Uint8List(units.length * 2);
  for (int i = 0; i < units.length; i++) {
    final value = units[i];
    out[i * 2] = (value >> 8) & 0xFF;
    out[i * 2 + 1] = value & 0xFF;
  }
  return out;
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

class _JksReader {
  _JksReader(this._bytes);

  final Uint8List _bytes;
  int offset = 0;

  int get remaining => _bytes.length - offset;

  int readInt32() {
    final data = ByteData.sublistView(_bytes, offset, offset + 4);
    offset += 4;
    return data.getInt32(0, Endian.big);
  }

  int readInt64() {
    final data = ByteData.sublistView(_bytes, offset, offset + 8);
    offset += 8;
    return data.getInt64(0, Endian.big);
  }

  Uint8List readBytes(int length) {
    final out = _bytes.sublist(offset, offset + length);
    offset += length;
    return out;
  }

  String readUtf() {
    final lenData = ByteData.sublistView(_bytes, offset, offset + 2);
    final length = lenData.getUint16(0, Endian.big);
    offset += 2;
    final raw = readBytes(length);
    return utf8.decode(raw, allowMalformed: true);
  }
}
