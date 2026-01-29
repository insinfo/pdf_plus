import 'dart:io';
import 'dart:typed_data';

import 'pdf_random_access_reader.dart';

/// Implementação randômica usando RandomAccessFile (Dart VM).
class PdfRandomAccessFileReader implements PdfRandomAccessReader {
  PdfRandomAccessFileReader(this._file, this.length);

  final RandomAccessFile _file;

  @override
  final int length;

  static PdfRandomAccessFileReader openSync(File file) {
    final raf = file.openSync(mode: FileMode.read);
    final len = file.lengthSync();
    return PdfRandomAccessFileReader(raf, len);
  }

  static Future<PdfRandomAccessFileReader> open(File file) async {
    final raf = await file.open(mode: FileMode.read);
    final len = await file.length();
    return PdfRandomAccessFileReader(raf, len);
  }

  @override
  Uint8List readRange(int offset, int length) {
    if (offset < 0 || length <= 0 || offset >= this.length) {
      return Uint8List(0);
    }
    final end = offset + length > this.length ? this.length : offset + length;
    final size = end - offset;
    _file.setPositionSync(offset);
    return _file.readSync(size);
  }

  @override
  Uint8List readAll() {
    _file.setPositionSync(0);
    return _file.readSync(length);
  }

  @override
  void close() {
    _file.closeSync();
  }
}
