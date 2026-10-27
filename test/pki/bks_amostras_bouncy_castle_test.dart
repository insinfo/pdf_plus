import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/src/pki/keystore/bks_keystore.dart';
import 'package:pdf_plus/src/pki/keystore/keystore_base.dart';
import 'package:test/test.dart';

/// Keystores gerados pelo próprio Bouncy Castle, copiados de
/// `referencias/bc-java-main/prov/src/test/java/org/bouncycastle/jce/provider/test/KeyStoreTest.java`
/// (`v1BKS` e `v2BKS`, senha `fredfred`, uma chave selada de alias `android`).
///
/// O formato é o do `BcKeyStoreSpi`: na versão 1 a chave do HMAC sai de
/// `generateDerivedMacParameters(hMac.getMacSize())` — 20 **bits**, 2 bytes —
/// e na versão 2 de `getMacSize() * 8`, 20 bytes.
const String _v1Bks = 'AAAAAQAAABTqZbNMyPjsFazhFplWWDMBLPRdRAAABcYEAAdhbmRyb2lkAAAB'
    'NOifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8'
    'q20AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wD0b8OP5/XzOz/8knhxmqJZ'
    '3yRJMw==';
const String _v2Bks = 'AAAAAgAAABSkmTXz4VIznO1SSUqsIHdxWcxsuQAABFMEAAdhbmRyb2lkAAABN'
    'OifkPwAAAAAAAAAPAAAABTZOLhcyhB0gKyfoDvyQbpzftB7GgAABEYPrZP8q2'
    '0AJLETjDv0K9C5rIl1erpyvpv20bqcbghK6wBO59KOGPvSrmJpd32P6ZAh9qLZJw==';
const String _senha = 'fredfred';

void main() {
  group('BKS - amostras do Bouncy Castle', () {
    for (final (nome, amostra, versao) in <(String, String, int)>[
      ('v1', _v1Bks, 1),
      ('v2', _v2Bks, 2),
    ]) {
      test('load confere o HMAC da amostra $nome', () {
        final store = BksKeyStore.load(
          base64.decode(amostra),
          storePassword: _senha,
        );
        expect(store.version, versao);
        expect(store.entries.keys, <String>['android']);
        expect(store.sealedKeys['android']!.isDecrypted(), isTrue,
            reason: 'a chave selada abre com a mesma senha');
      });
    }

    test('load recusa a amostra v1 com senha errada', () {
      expect(
        () => BksKeyStore.load(base64.decode(_v1Bks), storePassword: 'x'),
        throwsA(isA<KeystoreSignatureException>()),
      );
    });
  });

  group('BKS - save', () {
    test('chave selada sai no layout do Bouncy Castle e abre de novo', () {
      final original =
          BksKeyStore.load(base64.decode(_v2Bks), storePassword: _senha);
      final chave = original.sealedKeys['android']!.nestedEntry;

      final relido =
          BksKeyStore.load(original.save(_senha), storePassword: _senha);

      final selada = relido.sealedKeys['android']!;
      expect(selada.nestedEntry.encoded, chave.encoded);
      expect(selada.nestedEntry.algorithm, chave.algorithm);
      // Relê sem abrir, para ver o blob como está no arquivo.
      final cru = BksKeyStore.load(original.save(_senha),
              storePassword: _senha, tryDecryptKeys: false)
          .sealedKeys['android']!
          .encryptedData!;
      expect(cru.sublist(0, 4), <int>[0, 0, 0, 20],
          reason: 'BcKeyStoreSpi grava o tamanho do salt antes dele');
    });

    test('chave selada que nao foi aberta e regravada intacta', () {
      final fechado = BksKeyStore.load(base64.decode(_v2Bks),
          storePassword: _senha, tryDecryptKeys: false);
      expect(fechado.sealedKeys['android']!.isDecrypted(), isFalse);

      final relido =
          BksKeyStore.load(fechado.save(_senha), storePassword: _senha);

      expect(relido.sealedKeys['android']!.isDecrypted(), isTrue,
          reason: 'antes o save lançava exceção para chave não aberta');
    });

    test('entradas de chave e de segredo sobrevivem ao save', () {
      final store = BksKeyStore('bks', <String, KeystoreEntry>{
        'publica': BksKeyEntry(
          alias: 'publica',
          timestamp: 1,
          storeType: 'bks',
          keyType: bksKeyTypePublic,
          format: 'X.509',
          algorithm: 'RSA',
          encoded: Uint8List.fromList(<int>[1, 2, 3]),
        ),
        'segredo': BksSecretEntry(
          alias: 'segredo',
          timestamp: 2,
          storeType: 'bks',
          secretData: Uint8List.fromList(<int>[4, 5]),
        ),
      });

      final relido = BksKeyStore.load(store.save('s'), storePassword: 's');

      expect(relido.entries.keys, containsAll(<String>['publica', 'segredo']),
          reason: 'antes o save descartava as duas sem avisar');
      final publica = relido.plainKeys['publica']!;
      expect(publica.algorithm, 'RSA');
      expect(publica.encoded, <int>[1, 2, 3]);
      expect((relido.entries['segredo'] as BksSecretEntry).secretData,
          <int>[4, 5]);
    });
  });

  group('BKS - chave selada', () {
    test('ainda abre o layout antigo do pdf_plus, sem o tamanho do salt', () {
      final blob = BksKeyStore.load(base64.decode(_v2Bks),
              storePassword: _senha, tryDecryptKeys: false)
          .sealedKeys['android']!
          .encryptedData!;
      // Mesmo salt, iterações e cifra; só sem os 4 bytes do tamanho.
      final antigo = BksSealedKeyEntry(
        alias: 'android',
        timestamp: 0,
        storeType: 'bks',
        encryptedData: Uint8List.fromList(blob.sublist(4)),
      )..decrypt(_senha);

      expect(antigo.isDecrypted(), isTrue);
    });

    test('contagem de iteracoes absurda falha em vez de travar', () {
      final blob = Uint8List(40);
      ByteData.sublistView(blob)
        ..setUint32(0, 20)
        ..setUint32(24, 0xF0000000);
      final entrada = BksSealedKeyEntry(
        alias: 'x',
        timestamp: 0,
        storeType: 'bks',
        encryptedData: blob,
      );

      expect(() => entrada.decrypt('s'),
          throwsA(isA<DecryptionFailureException>()));
    });
  });
}
