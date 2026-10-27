import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/src/pki/keystore/jks_keystore.dart';
import 'package:pdf_plus/src/pki/keystore/keystore_base.dart';
import 'package:test/test.dart';

/// Keystores gerados pelo `keytool` do Java 8 (`test/assets/keystore`), senha
/// `senha-loja` na loja e na chave:
///
///   keytool -genkeypair -alias chave -keyalg RSA -keysize 2048
///           -dname "CN=Fixture pdf_plus" -storetype JKS|JCEKS ...
///   keytool -importcert -alias confiavel -file ICP-Brasilv12.crt ...
///
/// `chave_*.pk8.der` é a chave privada de cada um em PKCS#8, exportada pelo
/// próprio Java (`-importkeystore` para PKCS#12) e pelo OpenSSL.
const String _senha = 'senha-loja';
const String _pasta = 'test/assets/keystore';

Uint8List _ler(String nome) => File('$_pasta/$nome').readAsBytesSync();

void main() {
  for (final (tipo, arquivo, chave) in <(String, String, String)>[
    ('jks', 'fixture.jks', 'chave_jks.pk8.der'),
    ('jceks', 'fixture.jceks', 'chave_jceks.pk8.der'),
  ]) {
    group('JKS - keytool $tipo', () {
      test('load le a chave privada e o certificado confiavel', () {
        final store = JksKeyStore.load(_ler(arquivo), storePassword: _senha);

        expect(store.storeType, tipo);
        expect(store.certs.keys, <String>['confiavel']);
        final privada = store.entries['chave'] as JksPrivateKeyEntry;
        expect(privada.certChain, hasLength(1),
            reason: 'a cadeia vem depois da chave no formato do JDK');
        expect(privada.certChain.single.$1, 'X.509');

        privada.decrypt(_senha);
        expect(privada.privateKeyPkcs8, _ler(chave),
            reason: 'mesma chave que o Java exporta');
      });

      test('save sem abrir a chave reproduz o arquivo do Java byte a byte',
          () {
        final original = _ler(arquivo);
        final store = JksKeyStore.load(original, storePassword: _senha);
        final gravado =
            tipo == 'jks' ? store.save(_senha) : store.saveJceks(_senha);
        expect(gravado, original);
      });

      test('chave decifrada e protegida de novo abre com a mesma senha', () {
        final store = JksKeyStore.load(_ler(arquivo), storePassword: _senha);
        (store.entries['chave'] as JksPrivateKeyEntry).decrypt(_senha);

        final gravado = tipo == 'jks'
            ? store.save(_senha, keyPassword: 'outra')
            : store.saveJceks(_senha, keyPassword: 'outra');
        final relida = JksKeyStore.load(gravado, storePassword: _senha)
            .entries['chave'] as JksPrivateKeyEntry;

        expect(() => relida.decrypt(_senha),
            throwsA(isA<DecryptionFailureException>()));
        relida.decrypt('outra');
        expect(relida.privateKeyPkcs8, _ler(chave));
      });
    });
  }

  group('JKS - integridade', () {
    test('senha errada e recusada', () {
      expect(
        () => JksKeyStore.load(_ler('fixture.jks'), storePassword: 'x'),
        throwsA(isA<Exception>().having((e) => e.toString(), 'message',
            contains('Keystore password incorrect'))),
      );
    });

    test('arquivo sem o digest nao passa calado', () {
      final semDigest = _ler('fixture.jks');
      expect(
        () => JksKeyStore.load(
            Uint8List.sublistView(semDigest, 0, semDigest.length - 20),
            storePassword: _senha),
        throwsA(isA<Exception>()),
        reason: 'antes a conferência era pulada se não sobrassem 20 bytes',
      );
    });

    test('keystore do ITI volta identico apos load e save', () {
      final original = File(
              'test/assets/truststore/keystore_icp_brasil/keystore_ICP_Brasil.jks')
          .readAsBytesSync();
      final store = JksKeyStore.load(original, storePassword: '12345678');
      expect(store.save('12345678'), original);
    });

    test('loja vazia montada do zero abre no load', () {
      final store = JksKeyStore.empty()
        ..entries['a'] = TrustedCertEntry(
          alias: 'a',
          timestamp: 1700000000000,
          storeType: 'jks',
          certType: 'X.509',
          certData: Uint8List.fromList(<int>[0x30, 0x00]),
        );
      final relida = JksKeyStore.load(store.save('s'), storePassword: 's');
      expect(relida.certs['a']!.timestamp, 1700000000000);
    });
  });
}
