import 'dart:typed_data';

import 'package:pdf_plus/src/pki/keystore/bks_keystore.dart';
import 'package:pdf_plus/src/pki/keystore/jks_keystore.dart';
import 'package:pdf_plus/src/pki/keystore/keystore_base.dart';
import 'package:test/test.dart';

import 'keystore_fixtures_embutidos.dart';

/// JKS, JCEKS e BKS sem `dart:io`, para rodar também no navegador:
///
///   dart test -p vm,chrome test/pki/keystore_navegador_test.dart
///
/// O que quebra em JavaScript e não na VM: inteiro de 64 bits (data das
/// entradas, `ByteData.getInt64` inexistente, `>> 32` truncado) e a cripto
/// de plataforma (SHA-1, MD5, HMAC, 3DES, aleatório) na implementação web.
const String _senhaJks = 'senha-loja';
const String _senhaBks = 'fredfred';

/// Data com a parte alta dos 64 bits ocupada, que um `>> 32` truncado perde.
const int _dataDe2026 = 1793000000000;

void main() {
  for (final (tipo, loja, chave) in <(String, Uint8List, Uint8List)>[
    ('jks', fixtureJks, chaveJksPkcs8),
    ('jceks', fixtureJceks, chaveJceksPkcs8),
  ]) {
    group('JKS no navegador - $tipo do keytool', () {
      test('load confere o digest e decifra a chave', () {
        final store = JksKeyStore.load(loja, storePassword: _senhaJks);
        expect(store.storeType, tipo);
        final privada = store.entries['chave'] as JksPrivateKeyEntry;
        privada.decrypt(_senhaJks);
        expect(privada.privateKeyPkcs8, chave);
      });

      test('save sem abrir a chave devolve o arquivo do Java', () {
        final store = JksKeyStore.load(loja, storePassword: _senhaJks);
        final gravado =
            tipo == 'jks' ? store.save(_senhaJks) : store.saveJceks(_senhaJks);
        expect(gravado, loja,
            reason: 'as datas de 64 bits precisam voltar iguais');
      });

      test('chave protegida de novo abre com a senha nova', () {
        final store = JksKeyStore.load(loja, storePassword: _senhaJks);
        (store.entries['chave'] as JksPrivateKeyEntry).decrypt(_senhaJks);
        final gravado = tipo == 'jks'
            ? store.save('loja', keyPassword: 'outra')
            : store.saveJceks('loja', keyPassword: 'outra');

        final relida = JksKeyStore.load(gravado, storePassword: 'loja')
            .entries['chave'] as JksPrivateKeyEntry;
        relida.decrypt('outra');
        expect(relida.privateKeyPkcs8, chave);
      });
    });
  }

  group('JKS no navegador - montado do zero', () {
    test('data de 2026 sobrevive ao save e ao load', () {
      final store = JksKeyStore.empty()
        ..entries['a'] = TrustedCertEntry(
          alias: 'a',
          timestamp: _dataDe2026,
          storeType: 'jks',
          certType: 'X.509',
          certData: Uint8List.fromList(<int>[0x30, 0x00]),
        );
      final relida = JksKeyStore.load(store.save('s'), storePassword: 's');
      expect(relida.certs['a']!.timestamp, _dataDe2026);
    });
  });

  group('BKS no navegador - amostras do Bouncy Castle', () {
    for (final (nome, amostra) in <(String, Uint8List)>[
      ('v1', bksV1BouncyCastle),
      ('v2', bksV2BouncyCastle),
    ]) {
      test('load confere o HMAC e abre a chave selada da $nome', () {
        final store = BksKeyStore.load(amostra, storePassword: _senhaBks);
        expect(store.sealedKeys['android']!.isDecrypted(), isTrue);
      });
    }

    test('save e load preservam a chave selada', () {
      final original =
          BksKeyStore.load(bksV2BouncyCastle, storePassword: _senhaBks);
      final chave = original.sealedKeys['android']!.nestedEntry.encoded;

      final relido =
          BksKeyStore.load(original.save(_senhaBks), storePassword: _senhaBks);
      expect(relido.sealedKeys['android']!.nestedEntry.encoded, chave);
    });

    test('data de 2026 sobrevive ao save e ao load', () {
      final store = BksKeyStore('bks', <String, KeystoreEntry>{
        'a': BksTrustedCertEntry(
          alias: 'a',
          timestamp: _dataDe2026,
          storeType: 'bks',
          certType: 'X.509',
          certData: Uint8List.fromList(<int>[0x30, 0x00]),
        ),
      });
      final relido = BksKeyStore.load(store.save('s'), storePassword: 's');
      expect(relido.certs['a']!.timestamp, _dataDe2026);
    });
  });
}
