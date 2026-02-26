import 'dart:typed_data';

import 'pki_bytes_source.dart';

class _UnsupportedPkiBytesSource extends PkiBytesSource {
  const _UnsupportedPkiBytesSource();

  @override
  Future<Uint8List> read(String location) {
    throw UnsupportedError(
      'Leitura de bytes PKI nao suportada nesta plataforma: $location',
    );
  }
}

PkiBytesSource createPkiBytesSourceImpl() => const _UnsupportedPkiBytesSource();
