import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/asn1/asn1.dart';
import 'package:pdf_plus/src/crypto/hash.dart';
import 'package:pdf_plus/src/crypto/sha1.dart' as crypto_sha1;
import 'package:pdf_plus/src/crypto/sha256.dart' as crypto_sha256;
import 'pkcs12_types.dart';

Pkcs12Decoder createDefaultPkcs12Decoder() => DefaultPkcs12Decoder();

class DefaultPkcs12Decoder implements Pkcs12Decoder {
  @override
  Future<Pkcs12Bundle> decode(
    List<int> bytes, {
    required String password,
  }) async {
    final der = Uint8List.fromList(bytes);
    final pfx = ASN1Parser(der).nextObject() as ASN1Sequence;
    if (pfx.elements.length < 2) {
      throw ArgumentError('Invalid PKCS12: incomplete structure.');
    }

    _verifyMacIfPresent(
      pfx,
      password,
      _extractAuthSafeForMac(pfx.elements[1]),
    );

    final authSafe = _readContentInfo(pfx.elements[1], password);
    final authSafeSeq = ASN1Parser(authSafe).nextObject() as ASN1Sequence;

    final privateKeys = <Uint8List>[];
    final certificates = <Uint8List>[];

    for (final contentInfo in authSafeSeq.elements) {
      final contentBytes = _readContentInfo(contentInfo, password);
      if (contentBytes.isEmpty) continue;
      final bags = ASN1Parser(contentBytes).nextObject() as ASN1Sequence;
      for (final bag in bags.elements) {
        if (bag is! ASN1Sequence || bag.elements.isEmpty) continue;
        final bagOid = _oidFromObject(bag.elements[0]);
        if (bagOid == _oidKeyBag) {
          final keyBytes = _readExplicitOctet(bag.elements[1]);
          privateKeys.add(keyBytes);
        } else if (bagOid == _oidPkcs8ShroudedKeyBag) {
          final enc = _readExplicitOctet(bag.elements[1]);
          final decrypted = _decryptEncryptedPrivateKeyInfo(
            enc,
            password,
          );
          privateKeys.add(decrypted);
        } else if (bagOid == _oidCertBag) {
          final certBytes = _extractCertFromBag(bag.elements[1]);
          if (certBytes != null) {
            certificates.add(certBytes);
          }
        }
      }
    }

    if (privateKeys.isEmpty) {
      throw StateError('PKCS12 missing private key.');
    }
    if (certificates.isEmpty) {
      throw StateError('PKCS12 missing certificates.');
    }

    final privateKeyPem = _wrapPem('PRIVATE KEY', privateKeys.first);
    final certPem = _wrapPem('CERTIFICATE', certificates.first);
    final chainPem = certificates.length > 1
        ? certificates.sublist(1).map((c) => _wrapPem('CERTIFICATE', c)).toList()
        : const <String>[];

    return Pkcs12Bundle(
      privateKeyPem: privateKeyPem,
      certificatePem: certPem,
      chainPem: chainPem,
    );
  }
}

Uint8List _readContentInfo(ASN1Object obj, String password) {
  final seq = obj as ASN1Sequence;
  if (seq.elements.length < 2) return Uint8List(0);
  final contentType = _oidFromObject(seq.elements[0]);
  final content = seq.elements[1];

  if (contentType == _oidData) {
    final octet = _readExplicitOctet(content);
    return octet;
  }
  if (contentType == _oidEncryptedData) {
    final data = _readExplicitOctet(content);
    final encryptedData = ASN1Parser(data).nextObject() as ASN1Sequence;
    final encryptedContentInfo = encryptedData.elements[1] as ASN1Sequence;
    final encryptedBytes =
        _readExplicitOctet(encryptedContentInfo.elements[2]);
    final alg = encryptedContentInfo.elements[1] as ASN1Sequence;
    return _decryptWithAlgorithm(alg, encryptedBytes, password);
  }

  throw UnsupportedError('Unsupported ContentInfo: $contentType');
}

Uint8List _extractAuthSafeForMac(ASN1Object obj) {
  final seq = obj as ASN1Sequence;
  if (seq.elements.length < 2) return Uint8List(0);
  final contentType = _oidFromObject(seq.elements[0]);
  final content = seq.elements[1];

  if (contentType == _oidData) {
    return _readExplicitOctet(content);
  }
  if (contentType == _oidEncryptedData) {
    final data = _readExplicitOctet(content);
    final encryptedData = ASN1Parser(data).nextObject() as ASN1Sequence;
    final encryptedContentInfo = encryptedData.elements[1] as ASN1Sequence;
    return _readExplicitOctet(encryptedContentInfo.elements[2]);
  }
  return Uint8List(0);
}

void _verifyMacIfPresent(
  ASN1Sequence pfx,
  String password,
  Uint8List authSafeContent,
) {
  if (pfx.elements.length < 3) return;
  final macData = pfx.elements[2] as ASN1Sequence;
  final digestInfo = macData.elements[0] as ASN1Sequence;
  final macSalt = (macData.elements[1] as ASN1OctetString).valueBytes();
  final iterations = macData.elements.length > 2
      ? (macData.elements[2] as ASN1Integer).intValue
      : 1;

  final alg = digestInfo.elements[0] as ASN1Sequence;
  final expected = (digestInfo.elements[1] as ASN1OctetString).valueBytes();
  final hash = _hashForMac(alg);

  final key = _pkcs12Kdf(
    hash,
    _pkcs12PasswordBytes(password),
    macSalt,
    iterations,
    3,
    hash.convert([]).bytes.length,
  );

  final actual = _hmac(hash, key, authSafeContent);
  if (!_constantTimeEquals(expected, actual)) {
    throw StateError(
      'Invalid PKCS12 MAC (wrong password or corrupted file).',
    );
  }
}

Uint8List _decryptEncryptedPrivateKeyInfo(
  Uint8List bytes,
  String password,
) {
  final seq = ASN1Parser(bytes).nextObject() as ASN1Sequence;
  if (seq.elements.length < 2) {
    throw ArgumentError('Invalid EncryptedPrivateKeyInfo.');
  }
  final alg = seq.elements[0] as ASN1Sequence;
  final encrypted = seq.elements[1] as ASN1OctetString;
  return _decryptWithAlgorithm(alg, encrypted.valueBytes(), password);
}

Uint8List _decryptWithAlgorithm(
  ASN1Sequence alg,
  Uint8List encrypted,
  String password,
) {
  final oid = _oidFromObject(alg.elements[0]);
  if (oid == _oidPbes2) {
    return _decryptPbes2(alg, encrypted, password);
  }
  if (oid == _oidPbeSha3Des ||
      oid == _oidPbeSha2Des ||
      oid == _oidPbeShaRc2_128 ||
      oid == _oidPbeShaRc2_40) {
    return _decryptPkcs12Pbe(alg, encrypted, password, oid);
  }
  throw UnsupportedError('Unsupported PBE algorithm: $oid');
}

Uint8List _decryptPbes2(
  ASN1Sequence alg,
  Uint8List encrypted,
  String password,
) {
  final params = alg.elements[1] as ASN1Sequence;
  final kdfSeq = params.elements[0] as ASN1Sequence;
  final encSeq = params.elements[1] as ASN1Sequence;

  final kdfOid = _oidFromObject(kdfSeq.elements[0]);
  if (kdfOid != _oidPbkdf2) {
    throw UnsupportedError('Unsupported KDF: $kdfOid');
  }

  final kdfParams = kdfSeq.elements[1] as ASN1Sequence;
  final salt = (kdfParams.elements[0] as ASN1OctetString).valueBytes();
  final iter = (kdfParams.elements[1] as ASN1Integer).intValue;
  int? keyLength;
  ASN1Sequence? prfSeq;
  if (kdfParams.elements.length >= 3) {
    if (kdfParams.elements[2] is ASN1Integer) {
      keyLength = (kdfParams.elements[2] as ASN1Integer).intValue;
      if (kdfParams.elements.length >= 4) {
        prfSeq = kdfParams.elements[3] as ASN1Sequence;
      }
    } else if (kdfParams.elements[2] is ASN1Sequence) {
      prfSeq = kdfParams.elements[2] as ASN1Sequence;
    }
  }

  final encOid = _oidFromObject(encSeq.elements[0]);
  final iv = (encSeq.elements[1] as ASN1OctetString).valueBytes();
  final spec = _cipherForOid(encOid);
  final keySize = keyLength ?? spec.keySize;

  final prf = _hashForPrf(prfSeq);
  final key = _pbkdf2(
    utf8.encode(password),
    salt,
    iter,
    keySize,
    prf,
  );

  return _decryptCbc(spec.cipher, key, iv, encrypted);
}

Uint8List _decryptPkcs12Pbe(
  ASN1Sequence alg,
  Uint8List encrypted,
  String password,
  String oid,
) {
  final params = alg.elements[1] as ASN1Sequence;
  final salt = (params.elements[0] as ASN1OctetString).valueBytes();
  final iter = (params.elements[1] as ASN1Integer).intValue;
  final pwdBytes = _pkcs12PasswordBytes(password);

  if (oid == _oidPbeSha3Des || oid == _oidPbeSha2Des) {
    final keyLen = oid == _oidPbeSha2Des ? 16 : 24;
    final key = _pkcs12Kdf(
      crypto_sha1.sha1,
      pwdBytes,
      salt,
      iter,
      1,
      keyLen,
    );
    final iv = _pkcs12Kdf(
      crypto_sha1.sha1,
      pwdBytes,
      salt,
      iter,
      2,
      8,
    );
    final cipher = _TripleDesCipher();
    return _decryptCbc(cipher, key, iv, encrypted);
  }

  if (oid == _oidPbeShaRc2_128 || oid == _oidPbeShaRc2_40) {
    final effectiveBits = oid == _oidPbeShaRc2_40 ? 40 : 128;
    final keyLen = effectiveBits == 40 ? 5 : 16;
    final key = _pkcs12Kdf(
      crypto_sha1.sha1,
      pwdBytes,
      salt,
      iter,
      1,
      keyLen,
    );
    final iv = _pkcs12Kdf(
      crypto_sha1.sha1,
      pwdBytes,
      salt,
      iter,
      2,
      8,
    );
    final cipher = _Rc2Cipher(key, effectiveBits);
    return _decryptCbc(cipher, key, iv, encrypted);
  }

  throw UnsupportedError('Unsupported PKCS12 PBE: $oid');
}

Uint8List _readExplicitOctet(ASN1Object obj) {
  if (obj is ASN1OctetString) {
    return obj.valueBytes();
  }
  final content = obj.valueBytes();
  if (content.isEmpty) return content;
  try {
    final inner = ASN1Parser(content, relaxedParsing: true).nextObject();
    if (inner is ASN1OctetString) return inner.valueBytes();
  } catch (_) {
    // Ignore parse errors and return raw content.
  }
  return content;
}

Uint8List? _extractCertFromBag(ASN1Object bagValue) {
  final bag = ASN1Parser(_readExplicitOctet(bagValue)).nextObject();
  if (bag is! ASN1Sequence || bag.elements.length < 2) return null;
  final certType = _oidFromObject(bag.elements[0]);
  if (certType != _oidX509Cert) return null;
  return _readExplicitOctet(bag.elements[1]);
}

String _oidFromObject(ASN1Object obj) {
  if (obj is ASN1ObjectIdentifier) {
    return obj.identifier ?? '';
  }
  return '';
}

String _wrapPem(String label, Uint8List der) {
  final b64 = base64.encode(der);
  final lines = <String>[];
  for (var i = 0; i < b64.length; i += 64) {
    lines.add(b64.substring(i, i + 64 > b64.length ? b64.length : i + 64));
  }
  return '-----BEGIN $label-----\n'
      '${lines.join('\n')}\n'
      '-----END $label-----';
}

Hash _hashForPrf(ASN1Sequence? prfSeq) {
  if (prfSeq == null) {
    return crypto_sha1.sha1;
  }
  final oid = _oidFromObject(prfSeq.elements[0]);
  if (oid == _oidHmacSha256) {
    return crypto_sha256.sha256;
  }
  return crypto_sha1.sha1;
}

Hash _hashForMac(ASN1Sequence alg) {
  final oid = _oidFromObject(alg.elements[0]);
  if (oid == _oidSha256) {
    return crypto_sha256.sha256;
  }
  return crypto_sha1.sha1;
}

Uint8List _pkcs12PasswordBytes(String password) {
  if (password.isEmpty) {
    return Uint8List(2);
  }
  final units = password.codeUnits;
  final out = Uint8List((units.length + 1) * 2);
  for (var i = 0; i < units.length; i++) {
    out[i * 2] = (units[i] >> 8) & 0xff;
    out[i * 2 + 1] = units[i] & 0xff;
  }
  return out;
}

Uint8List _pkcs12Kdf(
  Hash hash,
  Uint8List password,
  Uint8List salt,
  int iterations,
  int id,
  int n,
) {
  final u = hash.convert([]).bytes.length;
  final v = hash.blockSize;

  final d = Uint8List(v);
  for (var i = 0; i < v; i++) {
    d[i] = id;
  }

  final s = _repeatToLength(salt, v);
  final p = _repeatToLength(password, v);
  final iBuf = Uint8List(s.length + p.length)
    ..setRange(0, s.length, s)
    ..setRange(s.length, s.length + p.length, p);

  final c = (n / u).ceil();
  final out = Uint8List(n);
  var offset = 0;

  for (var i = 0; i < c; i++) {
    var a = hash.convert(Uint8List.fromList([...d, ...iBuf])).bytes;
    for (var j = 1; j < iterations; j++) {
      a = hash.convert(a).bytes;
    }

    final b = Uint8List(v);
    for (var j = 0; j < v; j++) {
      b[j] = a[j % a.length];
    }

    for (var j = 0; j < iBuf.length; j += v) {
      _adjust(iBuf, j, b);
    }

    final toCopy = (offset + a.length > n) ? n - offset : a.length;
    out.setRange(offset, offset + toCopy, a);
    offset += toCopy;
  }

  return out;
}

Uint8List _repeatToLength(Uint8List input, int blockSize) {
  if (input.isEmpty) return Uint8List(0);
  final len = ((input.length + blockSize - 1) ~/ blockSize) * blockSize;
  final out = Uint8List(len);
  for (var i = 0; i < len; i++) {
    out[i] = input[i % input.length];
  }
  return out;
}

void _adjust(Uint8List buf, int offset, Uint8List b) {
  var carry = 1;
  for (var i = b.length - 1; i >= 0; i--) {
    final sum = buf[offset + i] + b[i] + carry;
    buf[offset + i] = sum & 0xff;
    carry = sum >> 8;
  }
}

bool _constantTimeEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

Uint8List _pbkdf2(
  List<int> password,
  Uint8List salt,
  int iterations,
  int length,
  Hash hash,
) {
  final hLen = hash.convert([]).bytes.length;
  final blocks = (length / hLen).ceil();
  final out = Uint8List(length);
  var offset = 0;
  for (var i = 1; i <= blocks; i++) {
    final t = _f(password, salt, iterations, i, hash);
    final toCopy = (offset + t.length > length) ? length - offset : t.length;
    out.setRange(offset, offset + toCopy, t);
    offset += toCopy;
  }
  return out;
}

Uint8List _f(
  List<int> password,
  Uint8List salt,
  int iterations,
  int blockIndex,
  Hash hash,
) {
  final intLen = 4;
  final block = Uint8List(salt.length + intLen)
    ..setRange(0, salt.length, salt)
    ..setRange(
        salt.length, salt.length + intLen, _int32Be(blockIndex));

  var u = _hmac(hash, password, block);
  final t = Uint8List.fromList(u);
  for (var i = 1; i < iterations; i++) {
    u = _hmac(hash, password, u);
    for (var j = 0; j < t.length; j++) {
      t[j] ^= u[j];
    }
  }
  return t;
}

Uint8List _hmac(Hash hash, List<int> key, List<int> data) {
  final blockSize = hash.blockSize;
  var k = Uint8List.fromList(key);
  if (k.length > blockSize) {
    k = Uint8List.fromList(hash.convert(k).bytes);
  }
  if (k.length < blockSize) {
    final tmp = Uint8List(blockSize);
    tmp.setRange(0, k.length, k);
    k = tmp;
  }

  final oKeyPad = Uint8List(blockSize);
  final iKeyPad = Uint8List(blockSize);
  for (var i = 0; i < blockSize; i++) {
    oKeyPad[i] = k[i] ^ 0x5c;
    iKeyPad[i] = k[i] ^ 0x36;
  }

  final inner = hash.convert(Uint8List.fromList([...iKeyPad, ...data])).bytes;
  final outer =
      hash.convert(Uint8List.fromList([...oKeyPad, ...inner])).bytes;
  return Uint8List.fromList(outer);
}

Uint8List _decryptCbc(
  _BlockCipher cipher,
  Uint8List key,
  Uint8List iv,
  Uint8List data,
) {
  if (data.length % cipher.blockSize != 0) {
    throw ArgumentError('Invalid data length for CBC.');
  }
  final out = Uint8List(data.length);
  var prev = Uint8List.fromList(iv);
  for (var i = 0; i < data.length; i += cipher.blockSize) {
    final block = data.sublist(i, i + cipher.blockSize);
    final dec = cipher.decryptBlock(key, block);
    for (var j = 0; j < cipher.blockSize; j++) {
      out[i + j] = dec[j] ^ prev[j];
    }
    prev = block;
  }
  return _pkcs7Unpad(out, cipher.blockSize);
}

Uint8List _pkcs7Unpad(Uint8List data, int blockSize) {
  if (data.isEmpty) return data;
  final pad = data.last;
  if (pad == 0 || pad > blockSize) {
    throw StateError('Invalid PKCS7 padding.');
  }
  for (var i = data.length - pad; i < data.length; i++) {
    if (data[i] != pad) {
      throw StateError('Invalid PKCS7 padding.');
    }
  }
  return data.sublist(0, data.length - pad);
}

Uint8List _int32Be(int value) {
  final bd = ByteData(4);
  bd.setUint32(0, value, Endian.big);
  return bd.buffer.asUint8List();
}

_CipherSpec _cipherForOid(String oid) {
  if (oid == _oidAes128Cbc) return _CipherSpec(_AesCipher(16), 16);
  if (oid == _oidAes192Cbc) return _CipherSpec(_AesCipher(24), 24);
  if (oid == _oidAes256Cbc) return _CipherSpec(_AesCipher(32), 32);
  throw UnsupportedError('Unsupported cipher: $oid');
}

class _CipherSpec {
  _CipherSpec(this.cipher, this.keySize);
  final _BlockCipher cipher;
  final int keySize;
}

abstract class _BlockCipher {
  int get blockSize;
  Uint8List decryptBlock(Uint8List key, Uint8List block);
}

class _AesCipher implements _BlockCipher {
  _AesCipher(this._keySize);

  final int _keySize;

  @override
  int get blockSize => 16;

  @override
  Uint8List decryptBlock(Uint8List key, Uint8List block) {
    final w = _expandKey(key, _keySize);
    final state = Uint8List.fromList(block);

    _addRoundKey(state, w, _nrForKey(_keySize));
    for (var round = _nrForKey(_keySize) - 1; round >= 1; round--) {
      _invShiftRows(state);
      _invSubBytes(state);
      _addRoundKey(state, w, round);
      _invMixColumns(state);
    }
    _invShiftRows(state);
    _invSubBytes(state);
    _addRoundKey(state, w, 0);

    return state;
  }

  int _nrForKey(int keySize) {
    if (keySize == 16) return 10;
    if (keySize == 24) return 12;
    return 14;
  }

  List<int> _expandKey(Uint8List key, int keySize) {
    final nk = keySize ~/ 4;
    final nr = _nrForKey(keySize);
    final w = List<int>.filled(4 * (nr + 1) * 4, 0);
    for (var i = 0; i < keySize; i++) {
      w[i] = key[i];
    }
    var i = nk;
    while (i < 4 * (nr + 1)) {
      var temp = w.sublist((i - 1) * 4, (i - 1) * 4 + 4);
      if (i % nk == 0) {
        temp = _subWord(_rotWord(temp));
        temp[0] ^= _rcon[i ~/ nk];
      } else if (nk > 6 && i % nk == 4) {
        temp = _subWord(temp);
      }
      for (var j = 0; j < 4; j++) {
        w[i * 4 + j] = w[(i - nk) * 4 + j] ^ temp[j];
      }
      i++;
    }
    return w;
  }

  List<int> _subWord(List<int> word) =>
      word.map((b) => _sBox[b]).toList();

  List<int> _rotWord(List<int> word) =>
      [word[1], word[2], word[3], word[0]];

  void _addRoundKey(Uint8List state, List<int> w, int round) {
    final start = round * 16;
    for (var i = 0; i < 16; i++) {
      state[i] ^= w[start + i];
    }
  }

  void _invSubBytes(Uint8List state) {
    for (var i = 0; i < 16; i++) {
      state[i] = _invSBox[state[i]];
    }
  }

  void _invShiftRows(Uint8List state) {
    final t = Uint8List.fromList(state);
    state[0] = t[0];
    state[1] = t[13];
    state[2] = t[10];
    state[3] = t[7];
    state[4] = t[4];
    state[5] = t[1];
    state[6] = t[14];
    state[7] = t[11];
    state[8] = t[8];
    state[9] = t[5];
    state[10] = t[2];
    state[11] = t[15];
    state[12] = t[12];
    state[13] = t[9];
    state[14] = t[6];
    state[15] = t[3];
  }

  void _invMixColumns(Uint8List state) {
    for (var i = 0; i < 4; i++) {
      final a0 = state[i * 4];
      final a1 = state[i * 4 + 1];
      final a2 = state[i * 4 + 2];
      final a3 = state[i * 4 + 3];
      state[i * 4] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9);
      state[i * 4 + 1] =
          _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13);
      state[i * 4 + 2] =
          _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11);
      state[i * 4 + 3] =
          _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14);
    }
  }

  int _gmul(int a, int b) {
    var p = 0;
    var hiBitSet;
    var aa = a;
    var bb = b;
    for (var i = 0; i < 8; i++) {
      if ((bb & 1) != 0) {
        p ^= aa;
      }
      hiBitSet = aa & 0x80;
      aa = (aa << 1) & 0xFF;
      if (hiBitSet != 0) {
        aa ^= 0x1b;
      }
      bb >>= 1;
    }
    return p & 0xFF;
  }
}

class _TripleDesCipher implements _BlockCipher {
  @override
  int get blockSize => 8;

  @override
  Uint8List decryptBlock(Uint8List key, Uint8List block) {
    final keys = _split3DesKeys(key);
    final des1 = _DesCipher(keys.$1);
    final des2 = _DesCipher(keys.$2);
    final des3 = _DesCipher(keys.$3);

    final step1 = des3.decrypt(block);
    final step2 = des2.encrypt(step1);
    return des1.decrypt(step2);
  }
}

class _DesCipher {
  _DesCipher(this._key);

  final Uint8List _key;

  Uint8List encrypt(Uint8List block) => _process(block, _subKeys);

  Uint8List decrypt(Uint8List block) => _process(block, _subKeys.reversed);

  late final List<int> _subKeys = _createSubKeys(_key);

  Uint8List _process(Uint8List block, Iterable<int> subKeys) {
    var data = _bytesToInt(block);
    data = _permute(data, _desIp, 64);
    var l = (data >> 32) & 0xffffffff;
    var r = data & 0xffffffff;

    for (final k in subKeys) {
      final temp = r;
      r = l ^ _feistel(r, k);
      l = temp;
    }

    final preOutput = ((r & 0xffffffff) << 32) | (l & 0xffffffff);
    final output = _permute(preOutput, _desFp, 64);
    return _intToBytes(output, 8);
  }

  int _feistel(int r, int k) {
    final e = _permute(r, _desE, 32);
    final x = e ^ k;
    var out = 0;
    for (var i = 0; i < 8; i++) {
      final sixBits = (x >> (42 - (i * 6))) & 0x3f;
      final row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01);
      final col = (sixBits >> 1) & 0x0f;
      final sVal = _desSBox[i][row][col];
      out = (out << 4) | sVal;
    }
    return _permute(out, _desP, 32);
  }

  List<int> _createSubKeys(Uint8List key) {
    var keyInt = _bytesToInt(key);
    keyInt = _permute(keyInt, _desPc1, 64);
    var c = (keyInt >> 28) & 0x0fffffff;
    var d = keyInt & 0x0fffffff;

    final keys = <int>[];
    for (var i = 0; i < 16; i++) {
      c = _rotl28(c, _desShifts[i]);
      d = _rotl28(d, _desShifts[i]);
      final cd = (c << 28) | d;
      keys.add(_permute(cd, _desPc2, 56));
    }
    return keys;
  }

  int _rotl28(int val, int shift) {
    final mask = 0x0fffffff;
    return ((val << shift) & mask) | ((val & mask) >> (28 - shift));
  }
}

class _Rc2Cipher implements _BlockCipher {
  _Rc2Cipher(this._key, this._effectiveBits);

  final Uint8List _key;
  final int _effectiveBits;

  @override
  int get blockSize => 8;

  @override
  Uint8List decryptBlock(Uint8List key, Uint8List block) {
    final k = _expandKey(key.isEmpty ? _key : key, _effectiveBits);

    var r0 = block[0] | (block[1] << 8);
    var r1 = block[2] | (block[3] << 8);
    var r2 = block[4] | (block[5] << 8);
    var r3 = block[6] | (block[7] << 8);

    var j = 63;
    for (var i = 15; i >= 0; i--) {
      if (i == 4 || i == 10) {
        r3 = (r3 - k[r2 & 63]) & 0xffff;
        r2 = (r2 - k[r1 & 63]) & 0xffff;
        r1 = (r1 - k[r0 & 63]) & 0xffff;
        r0 = (r0 - k[r3 & 63]) & 0xffff;
      }

      r3 = _ror16(r3, 5);
      r3 = (r3 -
              (k[j--] +
                  (r2 & ~r0) +
                  (r1 & r0))) &
          0xffff;

      r2 = _ror16(r2, 3);
      r2 = (r2 -
              (k[j--] +
                  (r1 & ~r3) +
                  (r0 & r3))) &
          0xffff;

      r1 = _ror16(r1, 2);
      r1 = (r1 -
              (k[j--] +
                  (r0 & ~r2) +
                  (r3 & r2))) &
          0xffff;

      r0 = _ror16(r0, 1);
      r0 = (r0 -
              (k[j--] +
                  (r3 & ~r1) +
                  (r2 & r1))) &
          0xffff;
    }

    return Uint8List.fromList([
      r0 & 0xff,
      (r0 >> 8) & 0xff,
      r1 & 0xff,
      (r1 >> 8) & 0xff,
      r2 & 0xff,
      (r2 >> 8) & 0xff,
      r3 & 0xff,
      (r3 >> 8) & 0xff,
    ]);
  }

  List<int> _expandKey(Uint8List key, int effectiveBits) {
    final t = key.length;
    final t1 = effectiveBits;
    final t8 = (t1 + 7) ~/ 8;
    final tm = 0xff >> ((t8 * 8) - t1);

    final l = Uint8List(128);
    l.setRange(0, key.length, key);
    for (var i = t; i < 128; i++) {
      l[i] = _rc2PiTable[(l[i - 1] + l[i - t]) & 0xff];
    }
    l[128 - t8] = _rc2PiTable[l[128 - t8] & tm];
    for (var i = 127 - t8; i >= 0; i--) {
      l[i] = _rc2PiTable[l[i + 1] ^ l[i + t8]];
    }

    final k = List<int>.filled(64, 0);
    for (var i = 0; i < 64; i++) {
      k[i] = l[i * 2] | (l[i * 2 + 1] << 8);
    }
    return k;
  }

  int _ror16(int val, int shift) {
    return ((val >> shift) | (val << (16 - shift))) & 0xffff;
  }
}

(Uint8List, Uint8List, Uint8List) _split3DesKeys(Uint8List key) {
  if (key.length == 16) {
    final k1 = key.sublist(0, 8);
    final k2 = key.sublist(8, 16);
    return (k1, k2, k1);
  }
  if (key.length == 24) {
    return (
      key.sublist(0, 8),
      key.sublist(8, 16),
      key.sublist(16, 24),
    );
  }
  throw ArgumentError('Invalid 3DES key.');
}

int _permute(int input, List<int> table, int inBits) {
  var out = 0;
  for (var i = 0; i < table.length; i++) {
    final pos = inBits - table[i];
    final bit = (input >> pos) & 0x01;
    out = (out << 1) | bit;
  }
  return out;
}

int _bytesToInt(Uint8List bytes) {
  var out = 0;
  for (var i = 0; i < bytes.length; i++) {
    out = (out << 8) | bytes[i];
  }
  return out;
}

Uint8List _intToBytes(int value, int length) {
  final out = Uint8List(length);
  for (var i = length - 1; i >= 0; i--) {
    out[i] = value & 0xff;
    value >>= 8;
  }
  return out;
}

const _oidData = '1.2.840.113549.1.7.1';
const _oidEncryptedData = '1.2.840.113549.1.7.6';
const _oidKeyBag = '1.2.840.113549.1.12.10.1.1';
const _oidPkcs8ShroudedKeyBag = '1.2.840.113549.1.12.10.1.2';
const _oidCertBag = '1.2.840.113549.1.12.10.1.3';
const _oidX509Cert = '1.2.840.113549.1.9.22.1';
const _oidSha256 = '2.16.840.1.101.3.4.2.1';
const _oidPbes2 = '1.2.840.113549.1.5.13';
const _oidPbkdf2 = '1.2.840.113549.1.5.12';
const _oidHmacSha256 = '1.2.840.113549.2.9';
const _oidAes128Cbc = '2.16.840.1.101.3.4.1.2';
const _oidAes192Cbc = '2.16.840.1.101.3.4.1.22';
const _oidAes256Cbc = '2.16.840.1.101.3.4.1.42';
const _oidPbeSha3Des = '1.2.840.113549.1.12.1.3';
const _oidPbeSha2Des = '1.2.840.113549.1.12.1.4';
const _oidPbeShaRc2_128 = '1.2.840.113549.1.12.1.5';
const _oidPbeShaRc2_40 = '1.2.840.113549.1.12.1.6';

const List<int> _rcon = <int>[
  0x00,
  0x01,
  0x02,
  0x04,
  0x08,
  0x10,
  0x20,
  0x40,
  0x80,
  0x1B,
  0x36,
];

const List<int> _sBox = <int>[
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
  0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
  0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
  0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
  0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
  0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
  0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
  0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const List<int> _invSBox = <int>[
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
  0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
  0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
  0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
  0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
  0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
  0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
  0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
  0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
  0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
  0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
  0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
  0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
  0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
  0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
  0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
  0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const List<int> _desIp = <int>[
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7,
];

const List<int> _desFp = <int>[
  40, 8, 48, 16, 56, 24, 64, 32,
  39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30,
  37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28,
  35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26,
  33, 1, 41, 9, 49, 17, 57, 25,
];

const List<int> _desE = <int>[
  32, 1, 2, 3, 4, 5,
  4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13,
  12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21,
  20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29,
  28, 29, 30, 31, 32, 1,
];

const List<int> _desP = <int>[
  16, 7, 20, 21, 29, 12, 28, 17,
  1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9,
  19, 13, 30, 6, 22, 11, 4, 25,
];

const List<int> _desPc1 = <int>[
  57, 49, 41, 33, 25, 17, 9,
  1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27,
  19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,
  7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29,
  21, 13, 5, 28, 20, 12, 4,
];

const List<int> _desPc2 = <int>[
  14, 17, 11, 24, 1, 5,
  3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8,
  16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32,
];

const List<int> _desShifts = <int>[
  1, 1, 2, 2, 2, 2, 2, 2,
  1, 2, 2, 2, 2, 2, 2, 1,
];

const List<List<List<int>>> _desSBox = <List<List<int>>>[
  [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  ],
  [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  ],
  [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  ],
  [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  ],
  [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  ],
  [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  ],
  [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  ],
  [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
  ],
];

const List<int> _rc2PiTable = <int>[
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed,
  0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
  0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13,
  0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b,
  0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
  0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1,
  0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57,
  0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
  0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7,
  0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
  0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
  0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
  0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae,
  0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
  0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0,
  0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77,
  0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
];
