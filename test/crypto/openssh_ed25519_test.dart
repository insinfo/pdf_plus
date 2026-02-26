import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/openssh_ed25519.dart';
import 'package:pdf_plus/src/crypto/pure_ed25519.dart';
import 'package:test/test.dart';

void main() {
  group('OpenSSH Ed25519 converter', () {
    test('roundtrip PKCS#8/SPKI <-> OpenSSH private key', () {
      final seed = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
      final publicKey = PureEd25519.derivePublicKeyFromSeed(seed);
      final pkcs8 = PureEd25519.buildPkcs8FromSeed(seed);
      final spki = PureEd25519.buildSpkiFromPublicKey(publicKey);

      final pair = OpenSshEd25519Converter.fromPkcs8Spki(
        pkcs8PrivateKey: pkcs8,
        spkiPublicKey: spki,
        comment: 'pdf_plus@test',
      );

      expect(pair.opensshPrivateKeyPem, contains('BEGIN OPENSSH PRIVATE KEY'));
      expect(pair.opensshPublicKey, startsWith('ssh-ed25519 '));
      expect(pair.opensshPublicKey, contains('pdf_plus@test'));

      final decoded = OpenSshEd25519Converter.fromOpenSshPrivatePem(
          pair.opensshPrivateKeyPem);
      expect(decoded.pkcs8PrivateKey, pkcs8);
      expect(decoded.spkiPublicKey, spki);
      expect(decoded.opensshPublicKey, pair.opensshPublicKey);
      expect(decoded.comment, 'pdf_plus@test');
    });

    test('decode OpenSSH public key line to SPKI', () {
      final seed = Uint8List.fromList(List<int>.generate(32, (i) => 255 - i));
      final publicKey = PureEd25519.derivePublicKeyFromSeed(seed);
      final line = OpenSshEd25519Converter.encodeOpenSshPublicKey(
        publicKey,
        comment: 'abc',
      );

      final spki = OpenSshEd25519Converter.decodeOpenSshPublicToSpki(line);
      final extracted = PureEd25519.extractPublicKeyFromSpki(spki);
      expect(extracted, publicKey);
    });

    test(
      'generated id_ed25519 is compatible with ssh-keygen -y',
      () async {
        if (!_hasSshKeygen()) return;

        final seed = Uint8List.fromList(List<int>.generate(32, (i) => i));
        final publicKey = PureEd25519.derivePublicKeyFromSeed(seed);
        final pem = OpenSshEd25519Converter.encodeOpenSshPrivatePem(
          seed: seed,
          publicKey: publicKey,
          comment: 'compat@test',
        );
        final expected =
            OpenSshEd25519Converter.encodeOpenSshPublicKey(publicKey);

        final tempDir = await Directory.systemTemp.createTemp('pdf_plus_ssh_');
        try {
          final keyPath = '${tempDir.path}${Platform.pathSeparator}id_ed25519';
          await File(keyPath).writeAsString(pem);
          await _ensurePrivateKeyPermissions(keyPath);
          final result =
              await Process.run('ssh-keygen', <String>['-y', '-f', keyPath]);
          expect(result.exitCode, 0,
              reason: '${result.stdout}\n${result.stderr}');

          final actual = (result.stdout as String).trim().split(RegExp(r'\s+'));
          final exp = expected.trim().split(RegExp(r'\s+'));
          expect(actual.length >= 2, isTrue);
          expect(exp.length >= 2, isTrue);
          expect(actual[0], exp[0]);
          expect(actual[1], exp[1]);
        } finally {
          await tempDir.delete(recursive: true);
        }
      },
      skip: _hasSshKeygen() ? false : 'ssh-keygen not available',
    );
  });
}

bool _hasSshKeygen() {
  try {
    final result = Process.runSync('ssh-keygen', <String>['-h']);
    return result.exitCode == 0 || result.exitCode == 1;
  } catch (_) {
    return false;
  }
}

Future<void> _ensurePrivateKeyPermissions(String keyPath) async {
  if (Platform.isWindows) {
    return;
  }

  final chmod = await Process.run('chmod', <String>['600', keyPath]);
  if (chmod.exitCode != 0) {
    throw StateError(
      'Failed to set private key permissions: ${chmod.stdout}\n${chmod.stderr}',
    );
  }
}
