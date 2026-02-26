import 'dart:html' as html;
import 'dart:typed_data';

import 'pki_bytes_source.dart';

class _WebPkiBytesSource extends PkiBytesSource {
  const _WebPkiBytesSource();

  @override
  Future<Uint8List> read(String location) async {
    final req = await html.HttpRequest.request(
      location,
      method: 'GET',
      responseType: 'arraybuffer',
    );
    final response = req.response;
    if (response is ByteBuffer) {
      return Uint8List.view(response);
    }
    if (response is Uint8List) {
      return response;
    }
    throw StateError('Resposta invalida ao carregar recurso PKI: $location');
  }
}

PkiBytesSource createPkiBytesSourceImpl() => const _WebPkiBytesSource();
