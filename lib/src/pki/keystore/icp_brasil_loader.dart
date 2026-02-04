import 'dart:io';
import 'dart:typed_data';

import 'bks_keystore.dart';
import 'jks_keystore.dart';

/// Não pode ser exportado porque depende de dart:io o que quebraria a compilação para WEB
/// Loads ICP-Brasil certificates from JKS and BKS keystores.
class IcpBrasilCertificateLoader {
  IcpBrasilCertificateLoader({
    required this.jksPath,
    required this.bksPath,
    this.jksPassword = '12345678',
    this.bksPassword = 'serprosigner',
  });

  final String jksPath;
  final String bksPath;
  final String jksPassword;
  final String bksPassword;

  Future<List<Uint8List>> loadFromJks({bool verifyIntegrity = false}) async {
    final file = File(jksPath);
    final bytes = await file.readAsBytes();
    final store = JksKeyStore.load(
      bytes,
      storePassword: verifyIntegrity ? jksPassword : '',
    );
    return store.getAllCertificates();
  }

  Future<List<Uint8List>> loadFromBks({bool tryDecryptKeys = false}) async {
    final file = File(bksPath);
    final bytes = await file.readAsBytes();
    final store = BksKeyStore.load(
      bytes,
      storePassword: bksPassword,
      tryDecryptKeys: tryDecryptKeys,
    );
    return store.getAllCertificates();
  }
}
