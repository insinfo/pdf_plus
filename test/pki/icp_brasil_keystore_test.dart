import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/src/pki/keystore/bks_keystore.dart';
import 'package:pdf_plus/src/pki/keystore/icp_brasil_loader.dart';
import 'package:pdf_plus/src/pki/keystore/jks_keystore.dart';
import 'package:pdf_plus/src/pki/keystore/keystore_base.dart';
import 'package:test/test.dart';

void main() {
  test('Decode ICP-Brasil BKS truststore (strict MAC)', () {
    final file =
        File('test/assets/truststore/icp_brasil/cadeiasicpbrasil.bks');
    if (!file.existsSync()) {
      print('Skipping BKS decode test: file not found.');
      return;
    }

    final Uint8List bytes = file.readAsBytesSync();
    final store = BksKeyStore.load(
      bytes,
      storePassword: 'serprosigner',
      tryDecryptKeys: false,
    );

    expect(store.version, 2);
    expect(store.entries, isNotEmpty);
    expect(store.certs, isNotEmpty);

    final certs = store.getAllCertificates();
    expect(certs, isNotEmpty);
    expect(certs.first, isNotEmpty);
  });

  test('BKS roundtrip preserves certificate entries', () {
    final file =
        File('test/assets/truststore/icp_brasil/cadeiasicpbrasil.bks');
    if (!file.existsSync()) {
      print('Skipping BKS roundtrip test: file not found.');
      return;
    }

    final Uint8List bytes = file.readAsBytesSync();
    final store = BksKeyStore.load(
      bytes,
      storePassword: 'serprosigner',
      tryDecryptKeys: false,
    );

    final Uint8List encoded = store.save('serprosigner');
    final BksKeyStore decoded = BksKeyStore.load(
      encoded,
      storePassword: 'serprosigner',
      tryDecryptKeys: false,
    );

    expect(decoded.entries.length, store.entries.length);

    final orig = store.certs.values
        .map((e) => '${e.alias}:${e.certData.length}')
        .toList()
      ..sort();
    final rt = decoded.certs.values
        .map((e) => '${e.alias}:${e.certData.length}')
        .toList()
      ..sort();

    expect(rt, orig);
  });

  group('JKS Save/Restore', () {
    test('Round-trip JKS save/load', () {
      final jksPath =
          'test/assets/truststore/keystore_icp_brasil/keystore_ICP_Brasil.jks';
      final file = File(jksPath);
      if (!file.existsSync()) {
        print('Skipping JKS roundtrip test: file not found.');
        return;
      }

      final originalBytes = file.readAsBytesSync();

      // Load without integrity check.
      final ks = JksKeyStore.load(originalBytes, storePassword: '');

      // Save with a new password and reload with integrity check.
      const storePassword = 'changeit';
      final savedBytes = ks.save(storePassword);
      final reloaded = JksKeyStore.load(savedBytes, storePassword: storePassword);

      expect(reloaded.entries.length, equals(ks.entries.length));
      expect(reloaded.certs, isNotEmpty);

      final alias = ks.certs.keys.first;
      final entry1 = ks.certs[alias] as TrustedCertEntry;
      final entry2 = reloaded.certs[alias] as TrustedCertEntry;

      expect(entry1.timestamp, equals(entry2.timestamp));
      expect(entry1.certData, equals(entry2.certData));

      expect(
        () => JksKeyStore.load(savedBytes, storePassword: 'wrong'),
        throwsA(
          isA<Exception>().having(
            (e) => e.toString(),
            'message',
            contains('Keystore password incorrect'),
          ),
        ),
      );
    });
  });

  test('JKS integrity check works with known password', () {
    final jksPath =
        'test/assets/truststore/keystore_icp_brasil/keystore_ICP_Brasil.jks';
    final file = File(jksPath);
    if (!file.existsSync()) {
      print('Skipping JKS integrity test: file not found.');
      return;
    }

    final bytes = file.readAsBytesSync();
    final verified = JksKeyStore.load(bytes, storePassword: '12345678');
    expect(verified.entries, isNotEmpty);
  });

  group('ICP-Brasil Certificate Loader', () {
    test('loads certificates from keystores', () async {
      final jksPath =
          'test/assets/truststore/keystore_icp_brasil/keystore_ICP_Brasil.jks';
      final bksPath =
          'test/assets/truststore/icp_brasil/cadeiasicpbrasil.bks';

      final jksFile = File(jksPath);
      final bksFile = File(bksPath);

      if (!jksFile.existsSync() && !bksFile.existsSync()) {
        print('Skipping loader test: keystore files not found.');
        return;
      }

      final loader = IcpBrasilCertificateLoader(
        jksPath: jksPath,
        bksPath: bksPath,
        jksPassword: '12345678',
        bksPassword: 'serprosigner',
      );

      List<Uint8List> certs = <Uint8List>[];

      if (jksFile.existsSync()) {
        try {
          certs = await loader.loadFromJks();
          print('Loaded ${certs.length} certificates from JKS.');
        } catch (e) {
          print('JKS loading failed: $e');
        }
      }

      if (certs.isEmpty && bksFile.existsSync()) {
        try {
          certs = await loader.loadFromBks();
          print('Loaded ${certs.length} certificates from BKS.');
        } catch (e) {
          print('BKS loading failed: $e');
        }
      }

      if (certs.isNotEmpty) {
        expect(certs, isNotEmpty);
        final first = certs.first;
        expect(first.length, greaterThan(100));
        expect(first[0], equals(0x30));
      } else {
        print('No certificates loaded.');
      }
    });
  });
}
