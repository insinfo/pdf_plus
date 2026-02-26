import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/pure_ecdsa.dart';
import 'package:pdf_plus/src/crypto/signature_adapter.dart';
import 'package:test/test.dart';

void main() {
  group('ASN.1 robustness - SignatureAdapter', () {
    test('ecdsaDerToRaw lança para DER vazio/malformado', () {
      expect(
        () => SignatureAdapter.ecdsaDerToRaw(Uint8List(0), namedCurve: 'P-256'),
        throwsArgumentError,
      );

      expect(
        () => SignatureAdapter.ecdsaDerToRaw(
          Uint8List.fromList(<int>[0x31, 0x00]),
          namedCurve: 'P-256',
        ),
        throwsArgumentError,
      );

      expect(
        () => SignatureAdapter.ecdsaDerToRaw(
          Uint8List.fromList(<int>[0x30, 0x81]),
          namedCurve: 'P-256',
        ),
        throwsArgumentError,
      );
    });

    test('ecdsaDerToRaw lança quando tags de R/S são inválidas', () {
      // SEQUENCE { BIT STRING, INTEGER }
      final badR = Uint8List.fromList(<int>[
        0x30, 0x06, // seq len
        0x03, 0x01, 0x01, // should be INTEGER
        0x02, 0x01, 0x01,
      ]);
      expect(
        () => SignatureAdapter.ecdsaDerToRaw(badR, namedCurve: 'P-256'),
        throwsArgumentError,
      );

      // SEQUENCE { INTEGER, BIT STRING }
      final badS = Uint8List.fromList(<int>[
        0x30, 0x06, // seq len
        0x02, 0x01, 0x01,
        0x03, 0x01, 0x01, // should be INTEGER
      ]);
      expect(
        () => SignatureAdapter.ecdsaDerToRaw(badS, namedCurve: 'P-256'),
        throwsArgumentError,
      );
    });

    test('ecdsaRawToDer lança quando tamanho raw não confere curva', () {
      expect(
        () => SignatureAdapter.ecdsaRawToDer(
          Uint8List.fromList(List<int>.filled(10, 1)),
          namedCurve: 'P-256',
        ),
        throwsArgumentError,
      );
    });
  });

  group('ASN.1 robustness - PureEcDsa', () {
    test(
      'verify retorna false para assinatura DER truncada/malformada',
      () async {
        if (!_hasOpenSsl()) return;
        final keys = await _generateEcP256Keys();
        final data = Uint8List.fromList(utf8.encode('asn1 robustness ecdsa'));
        final sigDer = PureEcDsa.sign(
          namedCurve: 'P-256',
          hashAlgorithm: 'SHA-256',
          pkcs8PrivateKey: keys.pkcs8PrivateKey,
          data: data,
        );

        final truncated = sigDer.sublist(0, sigDer.length - 1);
        expect(
          PureEcDsa.verify(
            namedCurve: 'P-256',
            hashAlgorithm: 'SHA-256',
            spkiPublicKey: keys.spkiPublicKey,
            data: data,
            signature: truncated,
          ),
          isFalse,
        );

        final badTag = Uint8List.fromList(sigDer)..[0] = 0x31;
        expect(
          PureEcDsa.verify(
            namedCurve: 'P-256',
            hashAlgorithm: 'SHA-256',
            spkiPublicKey: keys.spkiPublicKey,
            data: data,
            signature: badTag,
          ),
          isFalse,
        );

        final badIntTag = Uint8List.fromList(<int>[
          0x30, 0x06, // SEQUENCE
          0x03, 0x01, 0x01, // invalid R tag
          0x02, 0x01, 0x01, // valid S INTEGER
        ]);
        expect(
          PureEcDsa.verify(
            namedCurve: 'P-256',
            hashAlgorithm: 'SHA-256',
            spkiPublicKey: keys.spkiPublicKey,
            data: data,
            signature: badIntTag,
          ),
          isFalse,
        );
      },
      skip: _hasOpenSsl() ? false : 'openssl not available',
    );

    test(
      'verify aceita assinatura RAW (não DER) e valida corretamente',
      () async {
        if (!_hasOpenSsl()) return;
        final keys = await _generateEcP256Keys();
        final data = Uint8List.fromList(utf8.encode('asn1 raw ecdsa'));
        final sigDer = PureEcDsa.sign(
          namedCurve: 'P-256',
          hashAlgorithm: 'SHA-256',
          pkcs8PrivateKey: keys.pkcs8PrivateKey,
          data: data,
        );

        final sigRaw =
            SignatureAdapter.ecdsaDerToRaw(sigDer, namedCurve: 'P-256');
        expect(sigRaw.length, 64);

        expect(
          PureEcDsa.verify(
            namedCurve: 'P-256',
            hashAlgorithm: 'SHA-256',
            spkiPublicKey: keys.spkiPublicKey,
            data: data,
            signature: sigRaw,
          ),
          isTrue,
        );
      },
      skip: _hasOpenSsl() ? false : 'openssl not available',
    );
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
  final dir = await Directory.systemTemp.createTemp('pdf_plus_asn1_ec_');
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
