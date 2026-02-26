import 'dart:typed_data';

import 'package:pdf_plus/src/pki/keystore/bks_keystore.dart';
import 'package:pdf_plus/src/pki/keystore/icp_brasil_loader.dart';
import 'package:pdf_plus/src/pki/keystore/jks_keystore.dart';
import 'package:pdf_plus/src/pki/keystore/keystore_base.dart';
import 'package:test/test.dart';

void main() {
  group('Keystore core - JKS', () {
    test('load aceita JKS mínimo vazio', () {
      final bytes = _minimalJks();
      final ks = JksKeyStore.load(bytes, storePassword: '');
      expect(ks.entries, isEmpty);
      expect(ks.certs, isEmpty);
    });

    test('load falha com magic inválido', () {
      final bytes = Uint8List.fromList(_minimalJks());
      bytes[0] = 0x00;
      expect(
        () => JksKeyStore.load(bytes, storePassword: ''),
        throwsA(isA<Exception>()),
      );
    });

    test('load falha com versão não suportada', () {
      final bytes = Uint8List.fromList(_minimalJks(version: 3));
      expect(
        () => JksKeyStore.load(bytes, storePassword: ''),
        throwsA(isA<Exception>()),
      );
    });
  });

  group('Keystore core - BKS', () {
    test('load aceita BKS mínimo vazio sem MAC', () {
      final bytes = _minimalBks();
      final ks = BksKeyStore.load(bytes, storePassword: null);
      expect(ks.version, 2);
      expect(ks.entries, isEmpty);
      expect(ks.certs, isEmpty);
    });

    test('load falha para arquivo muito pequeno', () {
      expect(
        () => BksKeyStore.load(Uint8List.fromList(<int>[1, 2, 3, 4])),
        throwsA(isA<BadKeystoreFormatException>()),
      );
    });

    test('load falha para versão inválida', () {
      final bytes = _minimalBks(version: 7);
      expect(
        () => BksKeyStore.load(bytes, storePassword: null),
        throwsA(isA<UnsupportedKeystoreVersionException>()),
      );
    });

    test('keyTypeToString cobre tipos conhecidos e desconhecido', () {
      expect(BksKeyEntry.keyTypeToString(bksKeyTypePrivate), 'PRIVATE');
      expect(BksKeyEntry.keyTypeToString(bksKeyTypePublic), 'PUBLIC');
      expect(BksKeyEntry.keyTypeToString(bksKeyTypeSecret), 'SECRET');
      expect(BksKeyEntry.keyTypeToString(99), 'UNKNOWN');
    });
  });

  group('Keystore core - Loader', () {
    test('loader usa bytes em memória para JKS', () async {
      final loader = IcpBrasilCertificateLoader(
        jksBytes: _minimalJks(),
      );
      final certs = await loader.loadFromJks();
      expect(certs, isEmpty);
    });

    test('loader exige path/url quando bytes não informados', () async {
      final loader = IcpBrasilCertificateLoader(
        jksPath: null,
        jksBytes: null,
      );
      expect(
        () => loader.loadFromJks(),
        throwsA(isA<StateError>()),
      );
    });
  });

  group('Keystore core - Utils', () {
    test('fixedTimeEqual funciona para iguais/diferentes', () {
      expect(
        fixedTimeEqual(
          Uint8List.fromList(<int>[1, 2, 3]),
          Uint8List.fromList(<int>[1, 2, 3]),
        ),
        isTrue,
      );
      expect(
        fixedTimeEqual(
          Uint8List.fromList(<int>[1, 2, 3]),
          Uint8List.fromList(<int>[1, 2, 4]),
        ),
        isFalse,
      );
      expect(
        fixedTimeEqual(
          Uint8List.fromList(<int>[1, 2]),
          Uint8List.fromList(<int>[1, 2, 3]),
        ),
        isFalse,
      );
    });
  });
}

Uint8List _minimalJks({int version = 2}) {
  final bd = ByteData(12);
  bd.setUint32(0, 0xFEEDFEED);
  bd.setUint32(4, version);
  bd.setUint32(8, 0); // count
  return bd.buffer.asUint8List();
}

Uint8List _minimalBks({int version = 2}) {
  final out = BytesBuilder();
  out.add(_u32(version));
  out.add(_u32(0)); // salt length
  out.add(_u32(1)); // iteration count
  out.addByte(0); // entries terminator
  return out.toBytes();
}

Uint8List _u32(int value) {
  final bd = ByteData(4);
  bd.setUint32(0, value);
  return bd.buffer.asUint8List();
}
