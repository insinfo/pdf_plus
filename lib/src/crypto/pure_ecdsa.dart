import 'dart:math' as math;
import 'dart:typed_data';

import 'asn1/asn1.dart';
import 'platform_crypto_common.dart';

class PureEcDsa {
  static Uint8List sign({
    required String namedCurve,
    required String hashAlgorithm,
    required Uint8List pkcs8PrivateKey,
    required Uint8List data,
  }) {
    final curve = _EcCurve.byName(namedCurve);
    final d = _parseEcPrivatePkcs8(pkcs8PrivateKey);
    if (d == null || d <= BigInt.zero || d >= curve.n) {
      throw ArgumentError('PKCS#8 EC private key invalida');
    }
    final hash = digestByName(hashAlgorithm, data);
    final e = _bitsToInt(hash, curve.n.bitLength);

    final rng = math.Random.secure();
    BigInt r = BigInt.zero;
    BigInt s = BigInt.zero;
    while (r == BigInt.zero || s == BigInt.zero) {
      final k = _randomScalar(rng, curve.n);
      final point = curve.mul(curve.g, k);
      r = point.x % curve.n;
      if (r == BigInt.zero) continue;
      final kinv = _modInverse(k, curve.n);
      s = (kinv * (e + (d * r))) % curve.n;
    }
    return _encodeEcdsaDer(r, s);
  }

  static bool verify({
    required String namedCurve,
    required String hashAlgorithm,
    required Uint8List spkiPublicKey,
    required Uint8List data,
    required Uint8List signature,
  }) {
    final curve = _EcCurve.byName(namedCurve);
    final q = _parseEcPublicSpki(spkiPublicKey);
    if (q == null || !curve.isOnCurve(q) || q.infinity) {
      return false;
    }

    final rs = _decodeEcdsaSignature(signature, curve);
    if (rs == null) return false;
    final r = rs.$1;
    final s = rs.$2;
    if (r <= BigInt.zero || r >= curve.n || s <= BigInt.zero || s >= curve.n) {
      return false;
    }

    final hash = digestByName(hashAlgorithm, data);
    final e = _bitsToInt(hash, curve.n.bitLength);
    final w = _modInverse(s, curve.n);
    final u1 = (e * w) % curve.n;
    final u2 = (r * w) % curve.n;
    final p = curve.add(curve.mul(curve.g, u1), curve.mul(q, u2));
    if (p.infinity) return false;
    final v = p.x % curve.n;
    return v == r;
  }
}

class _EcPoint {
  const _EcPoint(this.x, this.y, {this.infinity = false});

  final BigInt x;
  final BigInt y;
  final bool infinity;

  static final infinityPoint =
      _EcPoint(BigInt.zero, BigInt.zero, infinity: true);
}

class _EcCurve {
  _EcCurve({
    required this.p,
    required this.a,
    required this.b,
    required this.g,
    required this.n,
  });

  final BigInt p;
  final BigInt a;
  final BigInt b;
  final _EcPoint g;
  final BigInt n;

  static _EcCurve byName(String name) {
    switch (name.toUpperCase()) {
      case 'P-256':
      case 'SECP256R1':
      case 'PRIME256V1':
      case 'BRAINPOOLP256R1':
        return _p256;
      case 'P-384':
      case 'SECP384R1':
      case 'BRAINPOOLP384R1':
        return _p384;
      case 'P-521':
      case 'SECP521R1':
      case 'BRAINPOOLP512R1':
        return _p521;
      default:
        throw UnsupportedError('Curva EC nao suportada: $name');
    }
  }

  bool isOnCurve(_EcPoint point) {
    if (point.infinity) return true;
    final y2 = (point.y * point.y) % p;
    final x3 = (point.x * point.x * point.x) % p;
    final rhs = (x3 + (a * point.x) + b) % p;
    return _mod(y2 - rhs, p) == BigInt.zero;
  }

  _EcPoint add(_EcPoint p1, _EcPoint p2) {
    if (p1.infinity) return p2;
    if (p2.infinity) return p1;
    if (p1.x == p2.x) {
      if (_mod(p1.y + p2.y, p) == BigInt.zero) {
        return _EcPoint.infinityPoint;
      }
      return doublePoint(p1);
    }
    final lambda =
        ((_mod(p2.y - p1.y, p)) * _modInverse(_mod(p2.x - p1.x, p), p)) % p;
    final x3 = _mod((lambda * lambda) - p1.x - p2.x, p);
    final y3 = _mod((lambda * (p1.x - x3)) - p1.y, p);
    return _EcPoint(x3, y3);
  }

  _EcPoint doublePoint(_EcPoint point) {
    if (point.infinity || point.y == BigInt.zero) {
      return _EcPoint.infinityPoint;
    }
    final lambda = (((BigInt.from(3) * point.x * point.x) + a) *
            _modInverse(BigInt.two * point.y % p, p)) %
        p;
    final x3 = _mod((lambda * lambda) - (BigInt.two * point.x), p);
    final y3 = _mod((lambda * (point.x - x3)) - point.y, p);
    return _EcPoint(x3, y3);
  }

  _EcPoint mul(_EcPoint point, BigInt k) {
    var n = k;
    var addend = point;
    var result = _EcPoint.infinityPoint;
    while (n > BigInt.zero) {
      if ((n & BigInt.one) == BigInt.one) {
        result = add(result, addend);
      }
      addend = doublePoint(addend);
      n >>= 1;
    }
    return result;
  }
}

final _EcCurve _p256 = _EcCurve(
  p: _hexToBigInt(
      'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'),
  a: _hexToBigInt(
      'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC'),
  b: _hexToBigInt(
      '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B'),
  g: _EcPoint(_kP256Gx, _kP256Gy),
  n: _hexToBigInt(
      'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'),
);

final BigInt _kP256Gx = BigInt.parse(
    '6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296',
    radix: 16);
final BigInt _kP256Gy = BigInt.parse(
    '4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5',
    radix: 16);

final _EcCurve _p384 = _EcCurve(
  p: _hexToBigInt(
      'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF'),
  a: _hexToBigInt(
      'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC'),
  b: _hexToBigInt(
      'B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF'),
  g: _EcPoint(_kP384Gx, _kP384Gy),
  n: _hexToBigInt(
      'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973'),
);

final BigInt _kP384Gx = BigInt.parse(
    'AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7',
    radix: 16);
final BigInt _kP384Gy = BigInt.parse(
    '3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F',
    radix: 16);

final _EcCurve _p521 = _EcCurve(
  p: _hexToBigInt(
      '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'),
  a: _hexToBigInt(
      '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC'),
  b: _hexToBigInt(
      '0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00'),
  g: _EcPoint(_kP521Gx, _kP521Gy),
  n: _hexToBigInt(
      '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409'),
);

final BigInt _kP521Gx = BigInt.parse(
    '00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66',
    radix: 16);
final BigInt _kP521Gy = BigInt.parse(
    '011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650',
    radix: 16);

BigInt? _parseEcPrivatePkcs8(Uint8List pkcs8Der) {
  try {
    final root = ASN1Parser(pkcs8Der).nextObject() as ASN1Sequence;
    final keyOctet = root.elements[2] as ASN1OctetString;
    final inner = ASN1Parser(keyOctet.contentBytes()).nextObject();
    if (inner is ASN1Sequence) {
      final privateOctet = inner.elements[1] as ASN1OctetString;
      return _decodeUnsigned(privateOctet.contentBytes());
    }
    return _decodeUnsigned(keyOctet.contentBytes());
  } catch (_) {
    return null;
  }
}

_EcPoint? _parseEcPublicSpki(Uint8List spkiDer) {
  try {
    final root = ASN1Parser(spkiDer).nextObject() as ASN1Sequence;
    final bitString = root.elements[1] as ASN1BitString;
    final bytes = Uint8List.fromList(bitString.contentBytes());
    if (bytes.isEmpty || bytes.first != 0x04) return null;
    final coordLen = (bytes.length - 1) ~/ 2;
    if (bytes.length != 1 + coordLen * 2) return null;
    final x = _decodeUnsigned(bytes.sublist(1, 1 + coordLen));
    final y = _decodeUnsigned(bytes.sublist(1 + coordLen));
    return _EcPoint(x, y);
  } catch (_) {
    return null;
  }
}

BigInt _hexToBigInt(String hex) => BigInt.parse(hex, radix: 16);

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

BigInt _decodeUnsigned(List<int> bytes) {
  var v = BigInt.zero;
  for (final b in bytes) {
    v = (v << 8) | BigInt.from(b);
  }
  return v;
}

BigInt _bitsToInt(Uint8List hash, int orderBits) {
  var z = _decodeUnsigned(hash);
  final hashBits = hash.length * 8;
  if (hashBits > orderBits) {
    z >>= (hashBits - orderBits);
  }
  return z;
}

BigInt _randomScalar(math.Random rng, BigInt n) {
  final byteLen = (n.bitLength + 7) >> 3;
  while (true) {
    final bytes = Uint8List(byteLen);
    for (var i = 0; i < byteLen; i++) {
      bytes[i] = rng.nextInt(256);
    }
    final k = _decodeUnsigned(bytes) % n;
    if (k > BigInt.zero) return k;
  }
}

Uint8List _encodeEcdsaDer(BigInt r, BigInt s) {
  final rDer = _encodeDerInt(r);
  final sDer = _encodeDerInt(s);
  final payload = Uint8List(rDer.length + sDer.length);
  payload.setRange(0, rDer.length, rDer);
  payload.setRange(rDer.length, payload.length, sDer);
  final len = _encodeDerLength(payload.length);
  final out = Uint8List(1 + len.length + payload.length);
  out[0] = 0x30;
  out.setRange(1, 1 + len.length, len);
  out.setRange(1 + len.length, out.length, payload);
  return out;
}

(BigInt, BigInt)? _decodeEcdsaSignature(Uint8List signature, _EcCurve curve) {
  if (signature.isNotEmpty && signature.first == 0x30) {
    return _decodeEcdsaDer(signature);
  }
  final coordLen = (curve.n.bitLength + 7) >> 3;
  if (signature.length != coordLen * 2) return null;
  final r = _decodeUnsigned(signature.sublist(0, coordLen));
  final s = _decodeUnsigned(signature.sublist(coordLen));
  return (r, s);
}

(BigInt, BigInt)? _decodeEcdsaDer(Uint8List bytes) {
  try {
    var off = 0;
    if (bytes[off++] != 0x30) return null;
    final seqLen = _readDerLength(bytes, off);
    off += seqLen.$2;
    final end = off + seqLen.$1;
    if (end != bytes.length) return null;

    if (bytes[off++] != 0x02) return null;
    final rLen = _readDerLength(bytes, off);
    off += rLen.$2;
    final r = _decodeUnsigned(bytes.sublist(off, off + rLen.$1));
    off += rLen.$1;

    if (bytes[off++] != 0x02) return null;
    final sLen = _readDerLength(bytes, off);
    off += sLen.$2;
    final s = _decodeUnsigned(bytes.sublist(off, off + sLen.$1));
    off += sLen.$1;
    if (off != end) return null;
    return (r, s);
  } catch (_) {
    return null;
  }
}

Uint8List _encodeDerInt(BigInt value) {
  var v = value;
  if (v == BigInt.zero) return Uint8List.fromList(<int>[0x02, 0x01, 0x00]);
  final bytes = <int>[];
  while (v > BigInt.zero) {
    bytes.insert(0, (v & BigInt.from(0xff)).toInt());
    v >>= 8;
  }
  if ((bytes.first & 0x80) != 0) {
    bytes.insert(0, 0);
  }
  return Uint8List.fromList(
      <int>[0x02, ..._encodeDerLength(bytes.length), ...bytes]);
}

Uint8List _encodeDerLength(int length) {
  if (length < 128) return Uint8List.fromList(<int>[length]);
  final bytes = <int>[];
  var n = length;
  while (n > 0) {
    bytes.insert(0, n & 0xff);
    n >>= 8;
  }
  return Uint8List.fromList(<int>[0x80 | bytes.length, ...bytes]);
}

(int, int) _readDerLength(Uint8List bytes, int offset) {
  final first = bytes[offset];
  if ((first & 0x80) == 0) return (first, 1);
  final count = first & 0x7f;
  var value = 0;
  for (var i = 0; i < count; i++) {
    value = (value << 8) | bytes[offset + 1 + i];
  }
  return (value, 1 + count);
}
