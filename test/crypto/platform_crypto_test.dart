import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/platform_crypto.dart';
import 'package:pdf_plus/src/crypto/signature_adapter.dart';
import 'package:test/test.dart';

void main() {
  group('PlatformCrypto', () {
    final crypto = createPlatformCrypto();
    final data = Uint8List.fromList('abc'.codeUnits);

    test('digest suporta SHA-1, SHA-256, SHA-384 e SHA-512', () async {
      final sha1 = await crypto.digest('SHA-1', data);
      final sha256 = await crypto.digest('SHA-256', data);
      final sha384 = await crypto.digest('SHA-384', data);
      final sha512 = await crypto.digest('SHA-512', data);

      expect(sha1.length, 20);
      expect(sha256.length, 32);
      expect(sha384.length, 48);
      expect(sha512.length, 64);
    });

    test('sha256 mantém helper compatível', () async {
      final viaMethod = await crypto.sha256(data);
      final viaHelper = await sha256Bytes(data);
      expect(bytesToHex(viaMethod), bytesToHex(viaHelper));
    });

    test('hmacSha256 é determinístico', () async {
      final key = Uint8List.fromList('secret'.codeUnits);
      final h1 = await crypto.hmacSha256(key, data);
      final h2 = await crypto.hmacSha256(key, data);
      expect(bytesToHex(h1), bytesToHex(h2));
      expect(h1.length, 32);
    });

    test('hmac genérico suporta SHA-512', () async {
      final key = Uint8List.fromList('secret'.codeUnits);
      final mac = await crypto.hmac('SHA-512', key, data);
      expect(mac.length, 64);
    });

    test('pbkdf2 sha256 confere vetor conhecido', () {
      final dk = crypto.pbkdf2Sync(
        hashAlgorithm: 'SHA-256',
        password: Uint8List.fromList('password'.codeUnits),
        salt: Uint8List.fromList('salt'.codeUnits),
        iterations: 1,
        length: 32,
      );
      expect(
        bytesToHex(dk),
        '120fb6cffcf8b32c43e7225256c4f837'
        'a86548c92ccc35480805987cb70be17b',
      );
    });

    test('hkdf sha256 confere vetor RFC5869 case 1', () {
      final ikm = Uint8List.fromList(List<int>.filled(22, 0x0b));
      final salt = _hex(
        '000102030405060708090a0b0c',
      );
      final info = _hex(
        'f0f1f2f3f4f5f6f7f8f9',
      );
      final okm = crypto.hkdfSync(
        hashAlgorithm: 'SHA-256',
        ikm: ikm,
        salt: salt,
        info: info,
        length: 42,
      );
      expect(
        bytesToHex(okm),
        '3cb25f25faacd57a90434f64d0362f2a'
        '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        '34007208d5b887185865',
      );
    });

    test('randomBytes retorna tamanho solicitado', () {
      final bytes = crypto.randomBytes(32);
      expect(bytes.length, 32);
    });

    test('randomUuid retorna formato v4', () {
      final uuid = crypto.randomUuid();
      final v4 = RegExp(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
      );
      expect(v4.hasMatch(uuid), isTrue);
    });

    test('SignatureAdapter converte ECDSA raw<->DER para P-256', () {
      final raw = Uint8List.fromList(List<int>.generate(64, (i) => i + 1));
      final der = SignatureAdapter.ecdsaRawToDer(raw, namedCurve: 'P-256');
      final raw2 = SignatureAdapter.ecdsaDerToRaw(der, namedCurve: 'P-256');
      expect(bytesToHex(raw2), bytesToHex(raw));
    });
  });
}

Uint8List _hex(String value) {
  final clean = value.replaceAll(RegExp(r'\s+'), '');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
