import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pki.dart';
import 'package:test/test.dart';

Future<bool> _hasOpenSsl() async {
  try {
    final res = await Process.run('openssl', ['version']);
    return res.exitCode == 0;
  } catch (_) {
    return false;
  }
}

Future<Uint8List> _generatePfx({
  required Directory dir,
  required String password,
  String? certPbe,
  String? keyPbe,
}) async {
  final keyPath = '${dir.path}${Platform.pathSeparator}key.pem';
  final certPath = '${dir.path}${Platform.pathSeparator}cert.pem';
  final pfxPath = '${dir.path}${Platform.pathSeparator}bundle.pfx';

  final gen = await Process.run('openssl', [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-keyout',
    keyPath,
    '-out',
    certPath,
    '-nodes',
    '-days',
    '1',
    '-subj',
    '/CN=Test User'
  ]);
  if (gen.exitCode != 0) {
    throw StateError('Falha ao gerar certificado: ${gen.stderr}');
  }

  final args = <String>[
    'pkcs12',
    '-export',
    '-inkey',
    keyPath,
    '-in',
    certPath,
    '-out',
    pfxPath,
    '-passout',
    'pass:$password',
  ];
  if (certPbe != null) {
    args.addAll(['-certpbe', certPbe]);
  }
  if (keyPbe != null) {
    args.addAll(['-keypbe', keyPbe]);
  }

  final res = await Process.run('openssl', args);
  if (res.exitCode != 0) {
    throw StateError('Falha ao gerar PFX: ${res.stderr}');
  }

  return File(pfxPath).readAsBytesSync();
}

void main() {
  test('decodifica PKCS12 com 3DES', () async {
    if (!await _hasOpenSsl()) {
      return;
    }
    final dir = Directory.systemTemp.createTempSync('pfx_test_3des_');
    try {
      final bytes = await _generatePfx(
        dir: dir,
        password: 'senha123',
        certPbe: 'PBE-SHA1-3DES',
        keyPbe: 'PBE-SHA1-3DES',
      );
      final bundle = await decodePkcs12(
        bytes,
        password: 'senha123',
      );
      expect(bundle.privateKeyPem, contains('BEGIN PRIVATE KEY'));
      expect(bundle.certificatePem, contains('BEGIN CERTIFICATE'));
    } finally {
      dir.deleteSync(recursive: true);
    }
  });

  test('decodifica PKCS12 com RC2 (quando suportado pelo OpenSSL)', () async {
    if (!await _hasOpenSsl()) {
      return;
    }
    final dir = Directory.systemTemp.createTempSync('pfx_test_rc2_');
    try {
      Uint8List bytes;
      try {
        bytes = await _generatePfx(
          dir: dir,
          password: 'senha123',
          certPbe: 'PBE-SHA1-RC2-40',
          keyPbe: 'PBE-SHA1-3DES',
        );
      } catch (_) {
        return;
      }
      final bundle = await decodePkcs12(
        bytes,
        password: 'senha123',
      );
      expect(bundle.privateKeyPem, contains('BEGIN PRIVATE KEY'));
      expect(bundle.certificatePem, contains('BEGIN CERTIFICATE'));
    } finally {
      dir.deleteSync(recursive: true);
    }
  });

  test('falha com senha incorreta (MAC)', () async {
    if (!await _hasOpenSsl()) {
      return;
    }
    final dir = Directory.systemTemp.createTempSync('pfx_test_mac_');
    try {
      final bytes = await _generatePfx(
        dir: dir,
        password: 'senha123',
        certPbe: 'PBE-SHA1-3DES',
        keyPbe: 'PBE-SHA1-3DES',
      );
      expect(
        () => decodePkcs12(bytes, password: 'errada'),
        throwsA(isA<StateError>()),
      );
    } finally {
      dir.deleteSync(recursive: true);
    }
  });
}
