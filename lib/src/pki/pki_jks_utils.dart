import 'dart:typed_data';

import 'package:pdf_plus/src/pki/keystore/jks_keystore.dart';
import 'package:pdf_plus/src/pki/keystore/keystore_base.dart';

class JksParseResult {
  JksParseResult({required this.certificates, this.verified = false});

  final List<Uint8List> certificates;
  final bool verified;
}

JksParseResult parseJksCertificates(
  Uint8List bytes, {
  String password = '12345678',
  bool verifyIntegrity = false,
}) {
  final store = JksKeyStore.load(
    bytes,
    storePassword: verifyIntegrity ? password : '',
  );
  final certs = <Uint8List>[];
  for (final entry in store.entries.values) {
    if (entry is TrustedCertEntry) {
      certs.add(entry.certData);
    } else if (entry is PrivateKeyEntry) {
      for (final cert in entry.certChain) {
        certs.add(cert.$2);
      }
    }
  }
  return JksParseResult(certificates: certs, verified: verifyIntegrity);
}
