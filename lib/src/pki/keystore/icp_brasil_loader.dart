import 'dart:typed_data';

import '../io/pki_bytes_source.dart';
import 'bks_keystore.dart';
import 'jks_keystore.dart';

/// Loads ICP-Brasil certificates from JKS and BKS keystores.
class IcpBrasilCertificateLoader {
  IcpBrasilCertificateLoader({
    this.jksPath,
    this.bksPath,
    this.jksBytes,
    this.bksBytes,
    this.jksPassword = '12345678',
    this.bksPassword = 'serprosigner',
    PkiBytesSource? bytesSource,
  }) : bytesSource = bytesSource ?? createDefaultPkiBytesSource();

  /// Caminho local (VM) ou URL/asset (web) do truststore JKS.
  final String? jksPath;

  /// Caminho local (VM) ou URL/asset (web) do truststore BKS.
  final String? bksPath;

  /// Bytes de JKS já carregados, útil para web/memória.
  final Uint8List? jksBytes;

  /// Bytes de BKS já carregados, útil para web/memória.
  final Uint8List? bksBytes;

  final String jksPassword;
  final String bksPassword;
  final PkiBytesSource bytesSource;

  Future<List<Uint8List>> loadFromJks({bool verifyIntegrity = false}) async {
    final bytes = jksBytes ?? await _readFromSource(jksPath, storeName: 'JKS');
    final store = JksKeyStore.load(
      bytes,
      storePassword: verifyIntegrity ? jksPassword : '',
    );
    return store.getAllCertificates();
  }

  Future<List<Uint8List>> loadFromBks({bool tryDecryptKeys = false}) async {
    final bytes = bksBytes ?? await _readFromSource(bksPath, storeName: 'BKS');
    final store = BksKeyStore.load(
      bytes,
      storePassword: bksPassword,
      tryDecryptKeys: tryDecryptKeys,
    );
    return store.getAllCertificates();
  }

  Future<Uint8List> _readFromSource(
    String? location, {
    required String storeName,
  }) async {
    if (location == null || location.trim().isEmpty) {
      throw StateError(
        'Nenhum caminho/URL informado para truststore $storeName.',
      );
    }
    return bytesSource.read(location);
  }
}
