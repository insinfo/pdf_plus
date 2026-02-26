import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/pure_ecdsa.dart';
import 'package:pdf_plus/src/crypto/pure_ed25519.dart';
import 'package:pdf_plus/src/crypto/signature_adapter.dart';
import 'package:test/test.dart';

void main() {
  group('PureEd25519', () {
    test('seed/pkcs8/spki roundtrip + sign/verify', () {
      final seed = Uint8List.fromList(List<int>.generate(32, (i) => i + 7));
      final pkcs8 = PureEd25519.buildPkcs8FromSeed(seed);
      final extractedSeed = PureEd25519.extractSeedFromPkcs8(pkcs8);
      expect(extractedSeed, seed);

      final publicKey = PureEd25519.derivePublicKeyFromSeed(seed);
      final spki = PureEd25519.buildSpkiFromPublicKey(publicKey);
      final extractedPublic = PureEd25519.extractPublicKeyFromSpki(spki);
      expect(extractedPublic, publicKey);

      final data = Uint8List.fromList(utf8.encode('pdf_plus ed25519 test'));
      final sig = PureEd25519.sign(pkcs8PrivateKey: pkcs8, data: data);
      expect(sig.length, 64);
      expect(
        PureEd25519.verify(
          spkiPublicKey: spki,
          data: data,
          signature: sig,
        ),
        isTrue,
      );

      final tampered = Uint8List.fromList(data)..[0] ^= 0x01;
      expect(
        PureEd25519.verify(
          spkiPublicKey: spki,
          data: tampered,
          signature: sig,
        ),
        isFalse,
      );
    });

    test('invalid seed/spki/pkcs8 throw', () {
      expect(
        () => PureEd25519.buildPkcs8FromSeed(Uint8List(31)),
        throwsArgumentError,
      );
      expect(
        () => PureEd25519.buildSpkiFromPublicKey(Uint8List(31)),
        throwsArgumentError,
      );
      expect(
        () => PureEd25519.extractSeedFromPkcs8(Uint8List.fromList([1, 2, 3])),
        throwsArgumentError,
      );
      expect(
        () => PureEd25519.extractPublicKeyFromSpki(
          Uint8List.fromList([1, 2, 3]),
        ),
        throwsArgumentError,
      );
    });
  });

  group('PureEcDsa', () {
    test(
      'P-256 sign/verify works and fails on tamper',
      () async {
        if (!_hasOpenSsl()) return;
        final keys = await _generateEcP256Keys();
        final data =
            Uint8List.fromList(utf8.encode('pdf_plus ecdsa p256 test'));

        final sig = PureEcDsa.sign(
          namedCurve: 'P-256',
          hashAlgorithm: 'SHA-256',
          pkcs8PrivateKey: keys.pkcs8PrivateKey,
          data: data,
        );
        expect(sig, isNotEmpty);
        expect(
          PureEcDsa.verify(
            namedCurve: 'P-256',
            hashAlgorithm: 'SHA-256',
            spkiPublicKey: keys.spkiPublicKey,
            data: data,
            signature: sig,
          ),
          isTrue,
        );

        final tampered = Uint8List.fromList(data)..[0] ^= 0x01;
        expect(
          PureEcDsa.verify(
            namedCurve: 'P-256',
            hashAlgorithm: 'SHA-256',
            spkiPublicKey: keys.spkiPublicKey,
            data: tampered,
            signature: sig,
          ),
          isFalse,
        );
      },
      skip: _hasOpenSsl() ? false : 'openssl not available',
    );

    test('unsupported curve and invalid key throw', () {
      expect(
        () => PureEcDsa.sign(
          namedCurve: 'P-999',
          hashAlgorithm: 'SHA-256',
          pkcs8PrivateKey: Uint8List(1),
          data: Uint8List(1),
        ),
        throwsUnsupportedError,
      );
      expect(
        () => PureEcDsa.sign(
          namedCurve: 'P-256',
          hashAlgorithm: 'SHA-256',
          pkcs8PrivateKey: Uint8List.fromList([1, 2, 3]),
          data: Uint8List(1),
        ),
        throwsArgumentError,
      );
    });
  });

  group('SignatureAdapter', () {
    test(
      'ECDSA DER sign/verify through adapter',
      () async {
        if (!_hasOpenSsl()) return;
        final keys = await _generateEcP256Keys();
        final adapter = SignatureAdapter();
        final data = Uint8List.fromList(utf8.encode('adapter ecdsa'));

        final sigDer = await adapter.ecdsaSignDer(
          namedCurve: 'P-256',
          hashAlgorithm: 'SHA-256',
          pkcs8PrivateKey: keys.pkcs8PrivateKey,
          data: data,
        );
        expect(sigDer, isNotEmpty);
        expect(sigDer.first, 0x30);

        final ok = await adapter.ecdsaVerifyDer(
          namedCurve: 'P-256',
          hashAlgorithm: 'SHA-256',
          spkiPublicKey: keys.spkiPublicKey,
          data: data,
          derSignature: sigDer,
        );
        expect(ok, isTrue);
      },
      skip: _hasOpenSsl() ? false : 'openssl not available',
    );

    test('Ed25519 sign/verify through adapter', () async {
      final seed = Uint8List.fromList(List<int>.generate(32, (i) => i + 3));
      final pkcs8 = PureEd25519.buildPkcs8FromSeed(seed);
      final pub = PureEd25519.derivePublicKeyFromSeed(seed);
      final spki = PureEd25519.buildSpkiFromPublicKey(pub);
      final adapter = SignatureAdapter();
      final data = Uint8List.fromList(utf8.encode('adapter ed25519'));

      final sig = await adapter.ed25519Sign(
        pkcs8PrivateKey: pkcs8,
        data: data,
      );
      expect(sig.length, 64);

      expect(
        await adapter.ed25519Verify(
          spkiPublicKey: spki,
          data: data,
          signature: sig,
        ),
        isTrue,
      );

      final bad = Uint8List.fromList(sig)..[10] ^= 0x01;
      expect(
        await adapter.ed25519Verify(
          spkiPublicKey: spki,
          data: data,
          signature: bad,
        ),
        isFalse,
      );
    });
  });
}

class _EcKeys {
  _EcKeys({
    required this.pkcs8PrivateKey,
    required this.spkiPublicKey,
  });

  final Uint8List pkcs8PrivateKey;
  final Uint8List spkiPublicKey;
}

Future<_EcKeys> _generateEcP256Keys() async {
  final dir = await Directory.systemTemp.createTemp('pdf_plus_ec_keys_');
  try {
    final keyPem = '${dir.path}/ec_key.pem';
    final pkcs8Pem = '${dir.path}/ec_key_pkcs8.pem';
    final pubPem = '${dir.path}/ec_pub.pem';

    await _runCmd('openssl', <String>[
      'ecparam',
      '-name',
      'prime256v1',
      '-genkey',
      '-noout',
      '-out',
      keyPem,
    ]);
    await _runCmd('openssl', <String>[
      'pkcs8',
      '-topk8',
      '-nocrypt',
      '-in',
      keyPem,
      '-out',
      pkcs8Pem,
    ]);
    await _runCmd('openssl', <String>[
      'pkey',
      '-in',
      keyPem,
      '-pubout',
      '-out',
      pubPem,
    ]);

    final pkcs8 = _decodePem(File(pkcs8Pem).readAsStringSync(), 'PRIVATE KEY');
    final spki = _decodePem(File(pubPem).readAsStringSync(), 'PUBLIC KEY');
    return _EcKeys(pkcs8PrivateKey: pkcs8, spkiPublicKey: spki);
  } finally {
    await dir.delete(recursive: true);
  }
}

Uint8List _decodePem(String pem, String label) {
  final re = RegExp(
    '-----BEGIN ${RegExp.escape(label)}-----([\\s\\S]*?)-----END ${RegExp.escape(label)}-----',
    multiLine: true,
  );
  final m = re.firstMatch(pem);
  if (m == null) {
    throw StateError('PEM $label não encontrado');
  }
  final body = (m.group(1) ?? '').replaceAll(RegExp(r'\s+'), '');
  return Uint8List.fromList(base64.decode(body));
}

bool _hasOpenSsl() {
  try {
    final result = Process.runSync('openssl', const <String>['version']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

Future<void> _runCmd(String exe, List<String> args) async {
  final result = await Process.run(exe, args, runInShell: true);
  if (result.exitCode != 0) {
    throw StateError(
      'Falha ao executar $exe ${args.join(' ')}\n${result.stdout}\n${result.stderr}',
    );
  }
}
