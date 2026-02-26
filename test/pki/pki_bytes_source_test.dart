import 'dart:typed_data';

import 'package:pdf_plus/src/pki/io/pki_bytes_source.dart';
import 'package:test/test.dart';

void main() {
  group('InMemoryPkiBytesSource', () {
    test('read retorna bytes existentes', () async {
      final source = InMemoryPkiBytesSource({
        'cert.der': Uint8List.fromList(<int>[1, 2, 3, 4]),
      });

      final bytes = await source.read('cert.der');
      expect(bytes, <int>[1, 2, 3, 4]);
    });

    test('read falha para recurso ausente', () async {
      final source = InMemoryPkiBytesSource({});
      expect(
        () => source.read('missing.der'),
        throwsA(isA<StateError>()),
      );
    });
  });
}
