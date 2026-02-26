import 'dart:io';
import 'dart:typed_data';

import 'pki_bytes_source.dart';

class _IoPkiBytesSource extends PkiBytesSource {
  const _IoPkiBytesSource();

  @override
  Future<Uint8List> read(String location) async {
    return File(location).readAsBytes();
  }
}

PkiBytesSource createPkiBytesSourceImpl() => const _IoPkiBytesSource();
