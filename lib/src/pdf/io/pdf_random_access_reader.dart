import 'dart:typed_data';

/// Leitor randômico síncrono para PDF.
abstract class PdfRandomAccessReader {
  int get length;

  Uint8List readRange(int offset, int length);

  Uint8List readAll();

  void close();
}

/// Implementação em memória (web e uso simples no VM).
class PdfMemoryRandomAccessReader implements PdfRandomAccessReader {
  PdfMemoryRandomAccessReader(this._bytes);

  final Uint8List _bytes;

  @override
  int get length => _bytes.length;

  @override
  Uint8List readRange(int offset, int length) {
    if (offset < 0 || length <= 0 || offset >= _bytes.length) {
      return Uint8List(0);
    }
    final end = offset + length > _bytes.length ? _bytes.length : offset + length;
    return _bytes.sublist(offset, end);
  }

  @override
  Uint8List readAll() => _bytes;

  @override
  void close() {}
}
