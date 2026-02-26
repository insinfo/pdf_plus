import 'dart:typed_data';

import 'asn1/asn1.dart';
import 'platform_crypto_common.dart';

class PureEd25519 {
  static Uint8List extractSeedFromPkcs8(Uint8List pkcs8PrivateKey) {
    final seed = _parseEd25519PrivatePkcs8(pkcs8PrivateKey);
    if (seed == null || seed.length != 32) {
      throw ArgumentError('PKCS#8 Ed25519 invalida');
    }
    return seed;
  }

  static Uint8List derivePublicKeyFromSeed(Uint8List seed) {
    if (seed.length != 32) {
      throw ArgumentError('Seed Ed25519 deve ter 32 bytes');
    }
    final h = digestByName('SHA-512', seed);
    final aBytes = Uint8List.fromList(h.sublist(0, 32));
    aBytes[0] &= 248;
    aBytes[31] &= 63;
    aBytes[31] |= 64;
    final a = _decodeLittle(aBytes) % _Ed25519Math.q;
    final aPoint = _Ed25519Math.scalarMul(_Ed25519Math.basePoint, a);
    return _Ed25519Math.encodePoint(aPoint);
  }

  static Uint8List buildPkcs8FromSeed(Uint8List seed) {
    if (seed.length != 32) {
      throw ArgumentError('Seed Ed25519 deve ter 32 bytes');
    }
    final alg = ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromComponentString('1.3.101.112'));
    final inner = ASN1OctetString(seed);
    final root = ASN1Sequence()
      ..add(ASN1Integer(BigInt.zero))
      ..add(alg)
      ..add(ASN1OctetString(inner.encodedBytes));
    return root.encodedBytes;
  }

  static Uint8List buildSpkiFromPublicKey(Uint8List publicKey) {
    if (publicKey.length != 32) {
      throw ArgumentError('Chave publica Ed25519 deve ter 32 bytes');
    }
    final alg = ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromComponentString('1.3.101.112'));
    final spki = ASN1Sequence()
      ..add(alg)
      ..add(ASN1BitString(publicKey));
    return spki.encodedBytes;
  }

  static Uint8List extractPublicKeyFromSpki(Uint8List spkiDer) {
    final pub = _parseEd25519PublicSpki(spkiDer);
    if (pub == null || pub.length != 32) {
      throw ArgumentError('SPKI Ed25519 invalida');
    }
    return pub;
  }

  static Uint8List sign({
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) {
    final seed = extractSeedFromPkcs8(pkcs8PrivateKey);

    final h = digestByName('SHA-512', seed);
    final aBytes = Uint8List.fromList(h.sublist(0, 32));
    aBytes[0] &= 248;
    aBytes[31] &= 63;
    aBytes[31] |= 64;
    final a = _decodeLittle(aBytes) % _Ed25519Math.q;
    final prefix = Uint8List.fromList(h.sublist(32, 64));

    final aPoint = _Ed25519Math.scalarMul(_Ed25519Math.basePoint, a);
    final aEncoded = _Ed25519Math.encodePoint(aPoint);

    final rInput = Uint8List(prefix.length + data.length);
    rInput.setRange(0, prefix.length, prefix);
    rInput.setRange(prefix.length, rInput.length, data);
    final r = _decodeLittle(digestByName('SHA-512', rInput)) % _Ed25519Math.q;

    final rPoint = _Ed25519Math.scalarMul(_Ed25519Math.basePoint, r);
    final rEncoded = _Ed25519Math.encodePoint(rPoint);

    final kInput = Uint8List(rEncoded.length + aEncoded.length + data.length);
    var off = 0;
    kInput.setRange(off, off + rEncoded.length, rEncoded);
    off += rEncoded.length;
    kInput.setRange(off, off + aEncoded.length, aEncoded);
    off += aEncoded.length;
    kInput.setRange(off, kInput.length, data);
    final k = _decodeLittle(digestByName('SHA-512', kInput)) % _Ed25519Math.q;

    final s = (r + k * a) % _Ed25519Math.q;
    final sBytes = _encodeLittle(s, 32);
    final signature = Uint8List(64);
    signature.setRange(0, 32, rEncoded);
    signature.setRange(32, 64, sBytes);
    return signature;
  }

  static bool verify({
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
  }) {
    if (signature.length != 64) return false;
    final aBytes = _parseEd25519PublicSpki(spkiPublicKey);
    if (aBytes == null || aBytes.length != 32) {
      return false;
    }

    final rBytes = signature.sublist(0, 32);
    final s = _decodeLittle(signature.sublist(32, 64));
    if (s >= _Ed25519Math.q) return false;

    final aPoint = _Ed25519Math.decodePoint(aBytes);
    final rPoint = _Ed25519Math.decodePoint(rBytes);
    if (aPoint == null || rPoint == null) return false;

    final kInput = Uint8List(rBytes.length + aBytes.length + data.length);
    var off = 0;
    kInput.setRange(off, off + rBytes.length, rBytes);
    off += rBytes.length;
    kInput.setRange(off, off + aBytes.length, aBytes);
    off += aBytes.length;
    kInput.setRange(off, kInput.length, data);
    final k = _decodeLittle(digestByName('SHA-512', kInput)) % _Ed25519Math.q;

    final left = _Ed25519Math.scalarMul(_Ed25519Math.basePoint, s);
    final right = _Ed25519Math.add(rPoint, _Ed25519Math.scalarMul(aPoint, k));
    return _bytesEqual(
      _Ed25519Math.encodePoint(left),
      _Ed25519Math.encodePoint(right),
    );
  }
}

class _EdPoint {
  const _EdPoint(this.x, this.y);

  final BigInt x;
  final BigInt y;
}

class _Ed25519Math {
  static final BigInt p = (BigInt.one << 255) - BigInt.from(19);
  static final BigInt q = (BigInt.one << 252) +
      BigInt.parse('27742317777372353535851937790883648493');
  static final BigInt d = _mod(
    -BigInt.from(121665) * _modInverse(BigInt.from(121666), p),
    p,
  );
  static final BigInt i = BigInt.from(2).modPow((p - BigInt.one) >> 2, p);

  static final _EdPoint basePoint = _EdPoint(
    BigInt.parse(
        '15112221349535400772501151409588531511454012693041857206046113283949847762202'),
    BigInt.parse(
        '46316835694926478169428394003475163141307993866256225615783033603165251855960'),
  );

  static _EdPoint add(_EdPoint p1, _EdPoint p2) {
    final x1 = p1.x;
    final y1 = p1.y;
    final x2 = p2.x;
    final y2 = p2.y;
    final xNum = _mod((x1 * y2) + (x2 * y1), p);
    final xDen = _mod(BigInt.one + (d * x1 * x2 * y1 * y2), p);
    final yNum = _mod((y1 * y2) + (x1 * x2), p);
    final yDen = _mod(BigInt.one - (d * x1 * x2 * y1 * y2), p);
    final x3 = _mod(xNum * _modInverse(xDen, p), p);
    final y3 = _mod(yNum * _modInverse(yDen, p), p);
    return _EdPoint(x3, y3);
  }

  static _EdPoint scalarMul(_EdPoint point, BigInt scalar) {
    var e = scalar;
    var result = _EdPoint(BigInt.zero, BigInt.one);
    var addend = point;
    while (e > BigInt.zero) {
      if ((e & BigInt.one) == BigInt.one) {
        result = add(result, addend);
      }
      addend = add(addend, addend);
      e >>= 1;
    }
    return result;
  }

  static Uint8List encodePoint(_EdPoint point) {
    final bytes = _encodeLittle(point.y, 32);
    final xOdd = (point.x & BigInt.one) == BigInt.one;
    if (xOdd) {
      bytes[31] |= 0x80;
    } else {
      bytes[31] &= 0x7f;
    }
    return bytes;
  }

  static _EdPoint? decodePoint(Uint8List bytes) {
    if (bytes.length != 32) return null;
    final copy = Uint8List.fromList(bytes);
    final sign = (copy[31] & 0x80) >> 7;
    copy[31] &= 0x7f;
    final y = _decodeLittle(copy);
    if (y >= p) return null;
    final x = _recoverX(y, sign);
    if (x == null) return null;
    final point = _EdPoint(x, y);
    final check = _mod(
      (y * y) - (x * x) - BigInt.one - (d * x * x * y * y),
      p,
    );
    if (check != BigInt.zero) return null;
    return point;
  }

  static BigInt? _recoverX(BigInt y, int sign) {
    final y2 = _mod(y * y, p);
    final xx = _mod(
      (y2 - BigInt.one) * _modInverse(_mod(d * y2 + BigInt.one, p), p),
      p,
    );
    var x = xx.modPow((p + BigInt.from(3)) >> 3, p);
    if (_mod(x * x - xx, p) != BigInt.zero) {
      x = _mod(x * i, p);
    }
    if (_mod(x * x - xx, p) != BigInt.zero) return null;
    final xOdd = (x & BigInt.one) == BigInt.one ? 1 : 0;
    if (xOdd != sign) {
      x = _mod(p - x, p);
    }
    return x;
  }
}

Uint8List? _parseEd25519PrivatePkcs8(Uint8List pkcs8Der) {
  try {
    final root = ASN1Parser(pkcs8Der).nextObject() as ASN1Sequence;
    final keyOctet = root.elements[2] as ASN1OctetString;
    final raw = keyOctet.contentBytes();
    if (raw.length == 32) return Uint8List.fromList(raw);
    final inner = ASN1Parser(raw).nextObject();
    if (inner is ASN1OctetString && inner.contentBytes().length == 32) {
      return Uint8List.fromList(inner.contentBytes());
    }
    return null;
  } catch (_) {
    return null;
  }
}

Uint8List? _parseEd25519PublicSpki(Uint8List spkiDer) {
  try {
    final root = ASN1Parser(spkiDer).nextObject() as ASN1Sequence;
    final bitString = root.elements[1] as ASN1BitString;
    final raw = Uint8List.fromList(bitString.contentBytes());
    if (raw.length != 32) return null;
    return raw;
  } catch (_) {
    return null;
  }
}

BigInt _decodeLittle(List<int> bytes) {
  var v = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    v = (v << 8) | BigInt.from(bytes[i]);
  }
  return v;
}

Uint8List _encodeLittle(BigInt value, int size) {
  var v = value;
  final out = Uint8List(size);
  for (var i = 0; i < size; i++) {
    out[i] = (v & BigInt.from(0xff)).toInt();
    v >>= 8;
  }
  return out;
}

BigInt _mod(BigInt x, BigInt m) {
  final r = x % m;
  return r >= BigInt.zero ? r : r + m;
}

BigInt _modInverse(BigInt a, BigInt m) {
  var t = BigInt.zero;
  var newT = BigInt.one;
  var r = m;
  var newR = _mod(a, m);
  while (newR != BigInt.zero) {
    final q = r ~/ newR;
    final tmpT = t - q * newT;
    t = newT;
    newT = tmpT;
    final tmpR = r - q * newR;
    r = newR;
    newR = tmpR;
  }
  if (r != BigInt.one) {
    throw ArgumentError('Elemento nao invertivel');
  }
  return _mod(t, m);
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var r = 0;
  for (var i = 0; i < a.length; i++) {
    r |= a[i] ^ b[i];
  }
  return r == 0;
}
