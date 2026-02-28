import 'dart:convert';
import 'dart:typed_data';

import 'pure_ed25519.dart';
import 'utils.dart';

class OpenSshEd25519KeyPair {
  const OpenSshEd25519KeyPair({
    required this.pkcs8PrivateKey,
    required this.spkiPublicKey,
    required this.opensshPrivateKeyPem,
    required this.opensshPublicKey,
    required this.comment,
  });

  final Uint8List pkcs8PrivateKey;
  final Uint8List spkiPublicKey;
  final String opensshPrivateKeyPem;
  final String opensshPublicKey;
  final String comment;
}

class OpenSshEd25519Converter {
  static OpenSshEd25519KeyPair fromPkcs8Spki({
    required Uint8List pkcs8PrivateKey,
    Uint8List? spkiPublicKey,
    String comment = '',
  }) {
    final seed = PureEd25519.extractSeedFromPkcs8(pkcs8PrivateKey);
    final publicRaw = spkiPublicKey != null
        ? PureEd25519.extractPublicKeyFromSpki(spkiPublicKey)
        : PureEd25519.derivePublicKeyFromSeed(seed);
    final spki = spkiPublicKey ?? PureEd25519.buildSpkiFromPublicKey(publicRaw);
    final privatePem = encodeOpenSshPrivatePem(
      seed: seed,
      publicKey: publicRaw,
      comment: comment,
    );
    final publicLine = encodeOpenSshPublicKey(
      publicRaw,
      comment: comment,
    );
    return OpenSshEd25519KeyPair(
      pkcs8PrivateKey: pkcs8PrivateKey,
      spkiPublicKey: spki,
      opensshPrivateKeyPem: privatePem,
      opensshPublicKey: publicLine,
      comment: comment,
    );
  }

  static OpenSshEd25519KeyPair fromOpenSshPrivatePem(String pem) {
    final bytes = _decodePem(pem, 'OPENSSH PRIVATE KEY');
    final decoded = decodeOpenSshPrivate(bytes);
    final pkcs8 = PureEd25519.buildPkcs8FromSeed(decoded.seed);
    final spki = PureEd25519.buildSpkiFromPublicKey(decoded.publicKey);
    final publicLine = encodeOpenSshPublicKey(
      decoded.publicKey,
      comment: decoded.comment,
    );
    return OpenSshEd25519KeyPair(
      pkcs8PrivateKey: pkcs8,
      spkiPublicKey: spki,
      opensshPrivateKeyPem: pem,
      opensshPublicKey: publicLine,
      comment: decoded.comment,
    );
  }

  static String encodeOpenSshPublicKey(
    Uint8List publicKey, {
    String comment = '',
  }) {
    if (publicKey.length != 32) {
      throw ArgumentError('Chave publica Ed25519 deve ter 32 bytes');
    }
    final blob = _encodeSshString(utf8.encode('ssh-ed25519')) +
        _encodeSshString(publicKey);
    final base = base64.encode(blob);
    final suffix = comment.trim().isEmpty ? '' : ' ${comment.trim()}';
    return 'ssh-ed25519 $base$suffix';
  }

  static Uint8List decodeOpenSshPublicToSpki(String publicKeyLine) {
    final parsed = parseOpenSshPublicKey(publicKeyLine);
    return PureEd25519.buildSpkiFromPublicKey(parsed.publicKeyRaw);
  }

  static ({Uint8List publicKeyRaw, String comment}) parseOpenSshPublicKey(
    String line,
  ) {
    final trimmed = line.trim();
    final parts = trimmed.split(RegExp(r'\s+'));
    if (parts.length < 2 || parts.first != 'ssh-ed25519') {
      throw ArgumentError('Linha de chave publica OpenSSH invalida');
    }
    final blob = base64.decode(parts[1]);
    var off = 0;
    final keyType = _readSshString(blob, off);
    off = keyType.nextOffset;
    if (utf8.decode(keyType.value) != 'ssh-ed25519') {
      throw ArgumentError('Tipo de chave OpenSSH nao suportado');
    }
    final pub = _readSshString(blob, off);
    if (pub.value.length != 32) {
      throw ArgumentError('Chave publica Ed25519 invalida');
    }
    final comment = parts.length > 2 ? parts.sublist(2).join(' ') : '';
    return (publicKeyRaw: Uint8List.fromList(pub.value), comment: comment);
  }

  static String encodeOpenSshPrivatePem({
    required Uint8List seed,
    required Uint8List publicKey,
    String comment = '',
  }) {
    final keyBytes = encodeOpenSshPrivateBytes(
      seed: seed,
      publicKey: publicKey,
      comment: comment,
    );
    return _encodePem('OPENSSH PRIVATE KEY', keyBytes);
  }

  static Uint8List encodeOpenSshPrivateBytes({
    required Uint8List seed,
    required Uint8List publicKey,
    String comment = '',
  }) {
    if (seed.length != 32) {
      throw ArgumentError('Seed Ed25519 deve ter 32 bytes');
    }
    if (publicKey.length != 32) {
      throw ArgumentError('Chave publica Ed25519 deve ter 32 bytes');
    }

    final pubBlob = _encodeSshString(utf8.encode('ssh-ed25519')) +
        _encodeSshString(publicKey);
    final priv64 = Uint8List(64)
      ..setRange(0, 32, seed)
      ..setRange(32, 64, publicKey);

    const check = 0xA1B2C3D4;
    final privateSection = BytesBuilder()
      ..add(_u32(check))
      ..add(_u32(check))
      ..add(_encodeSshString(utf8.encode('ssh-ed25519')))
      ..add(_encodeSshString(publicKey))
      ..add(_encodeSshString(priv64))
      ..add(_encodeSshString(utf8.encode(comment)));
    final privBeforePad = privateSection.toBytes();
    final padLen = (8 - (privBeforePad.length % 8)) % 8;
    final privPadded = BytesBuilder()..add(privBeforePad);
    for (var i = 1; i <= padLen; i++) {
      privPadded.addByte(i);
    }

    final out = BytesBuilder()
      ..add(utf8.encode('openssh-key-v1\u0000'))
      ..add(_encodeSshString(utf8.encode('none')))
      ..add(_encodeSshString(utf8.encode('none')))
      ..add(_encodeSshString(Uint8List(0)))
      ..add(_u32(1))
      ..add(_encodeSshString(pubBlob))
      ..add(_encodeSshString(privPadded.toBytes()));
    return out.toBytes();
  }

  static ({Uint8List seed, Uint8List publicKey, String comment})
      decodeOpenSshPrivate(Uint8List bytes) {
    final magic = utf8.encode('openssh-key-v1\u0000');
    if (bytes.length < magic.length ||
        !constantTimeAreEqual(
          Uint8List.fromList(bytes.sublist(0, magic.length)),
          Uint8List.fromList(magic),
        )) {
      throw ArgumentError('Formato OpenSSH private key invalido');
    }
    var off = magic.length;

    final cipher = _readSshString(bytes, off);
    off = cipher.nextOffset;
    final kdf = _readSshString(bytes, off);
    off = kdf.nextOffset;
    final kdfOpts = _readSshString(bytes, off);
    off = kdfOpts.nextOffset;
    final nKeys = _readU32(bytes, off);
    off += 4;

    if (utf8.decode(cipher.value) != 'none' ||
        utf8.decode(kdf.value) != 'none' ||
        kdfOpts.value.isNotEmpty ||
        nKeys != 1) {
      throw UnsupportedError('Somente OpenSSH sem criptografia (none/none)');
    }

    final publicBlob = _readSshString(bytes, off);
    off = publicBlob.nextOffset;
    final privateBlob = _readSshString(bytes, off);
    off = privateBlob.nextOffset;
    if (off != bytes.length) {
      throw ArgumentError('Bytes extras em OpenSSH private key');
    }

    var p = 0;
    final check1 = _readU32(privateBlob.value, p);
    p += 4;
    final check2 = _readU32(privateBlob.value, p);
    p += 4;
    if (check1 != check2) {
      throw ArgumentError('Checkints OpenSSH invalidos');
    }

    final type = _readSshString(privateBlob.value, p);
    p = type.nextOffset;
    if (utf8.decode(type.value) != 'ssh-ed25519') {
      throw UnsupportedError('Tipo OpenSSH nao suportado');
    }
    final pub = _readSshString(privateBlob.value, p);
    p = pub.nextOffset;
    final priv = _readSshString(privateBlob.value, p);
    p = priv.nextOffset;
    final comment = _readSshString(privateBlob.value, p);
    p = comment.nextOffset;

    if (pub.value.length != 32 || priv.value.length != 64) {
      throw ArgumentError('Material Ed25519 invalido em OpenSSH');
    }
    final seed = Uint8List.fromList(priv.value.sublist(0, 32));
    final pubFromPriv = Uint8List.fromList(priv.value.sublist(32, 64));
    if (!constantTimeAreEqual(pub.value, pubFromPriv)) {
      throw ArgumentError('Chave publica inconsistente no OpenSSH private key');
    }

    final pad = privateBlob.value.sublist(p);
    for (var i = 0; i < pad.length; i++) {
      if (pad[i] != (i + 1)) {
        throw ArgumentError('Padding OpenSSH invalido');
      }
    }

    final pubFromHeader = _parsePublicBlob(publicBlob.value);
    if (!constantTimeAreEqual(pub.value, pubFromHeader)) {
      throw ArgumentError('Chave publica header/private mismatch');
    }

    final cmt = utf8.decode(comment.value, allowMalformed: true);
    return (seed: seed, publicKey: Uint8List.fromList(pub.value), comment: cmt);
  }
}

class _SshReadResult {
  _SshReadResult(this.value, this.nextOffset);
  final Uint8List value;
  final int nextOffset;
}

Uint8List _u32(int value) {
  return Uint8List.fromList(<int>[
    (value >> 24) & 0xff,
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ]);
}

int _readU32(Uint8List bytes, int offset) {
  if (offset + 4 > bytes.length) {
    throw ArgumentError('u32 fora dos limites');
  }
  return (bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3];
}

Uint8List _encodeSshString(List<int> value) {
  final out = BytesBuilder();
  out.add(_u32(value.length));
  out.add(value);
  return out.toBytes();
}

_SshReadResult _readSshString(Uint8List bytes, int offset) {
  final len = _readU32(bytes, offset);
  final start = offset + 4;
  final end = start + len;
  if (end > bytes.length) {
    throw ArgumentError('string SSH fora dos limites');
  }
  return _SshReadResult(Uint8List.fromList(bytes.sublist(start, end)), end);
}

Uint8List _parsePublicBlob(Uint8List blob) {
  var off = 0;
  final t = _readSshString(blob, off);
  off = t.nextOffset;
  if (utf8.decode(t.value) != 'ssh-ed25519') {
    throw ArgumentError('Blob publico OpenSSH invalido');
  }
  final p = _readSshString(blob, off);
  off = p.nextOffset;
  if (off != blob.length || p.value.length != 32) {
    throw ArgumentError('Blob publico OpenSSH invalido');
  }
  return p.value;
}

String _encodePem(String label, Uint8List der) {
  final b64 = base64.encode(der);
  final sb = StringBuffer();
  sb.writeln('-----BEGIN $label-----');
  for (var i = 0; i < b64.length; i += 70) {
    final end = (i + 70 < b64.length) ? i + 70 : b64.length;
    sb.writeln(b64.substring(i, end));
  }
  sb.writeln('-----END $label-----');
  return sb.toString();
}

Uint8List _decodePem(String pem, String label) {
  final re = RegExp(
    '-----BEGIN ${RegExp.escape(label)}-----([\\s\\S]*?)-----END ${RegExp.escape(label)}-----',
    multiLine: true,
  );
  final m = re.firstMatch(pem);
  if (m == null) {
    throw ArgumentError('PEM $label nao encontrado');
  }
  final b64 = (m.group(1) ?? '').replaceAll(RegExp(r'\s+'), '');
  if (b64.isEmpty) {
    throw ArgumentError('PEM $label vazio');
  }
  return Uint8List.fromList(base64.decode(b64));
}
