import 'dart:typed_data';

import 'pki_bytes_source_impl.dart'
    if (dart.library.io) 'pki_bytes_source_io.dart'
    if (dart.library.html) 'pki_bytes_source_web.dart';

/// Abstrai leitura de bytes para permitir uso em VM e navegador.
abstract class PkiBytesSource {
  const PkiBytesSource();

  /// Lê bytes de [location] (caminho local na VM ou URL/asset no navegador).
  Future<Uint8List> read(String location);
}

/// Fonte de bytes em memória útil para testes e ambiente web sem filesystem.
class InMemoryPkiBytesSource extends PkiBytesSource {
  InMemoryPkiBytesSource(this._items);

  final Map<String, Uint8List> _items;

  @override
  Future<Uint8List> read(String location) async {
    final bytes = _items[location];
    if (bytes == null) {
      throw StateError('Recurso PKI nao encontrado em memoria: $location');
    }
    return bytes;
  }
}

PkiBytesSource createDefaultPkiBytesSource() => createPkiBytesSourceImpl();
