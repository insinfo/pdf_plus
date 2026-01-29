import 'dart:collection';
import 'dart:typed_data';

import 'pdf_random_access_reader.dart';

/// Cache LRU por blocos para leitura randômica.
class PdfCachedRandomAccessReader implements PdfRandomAccessReader {
  PdfCachedRandomAccessReader(
    this._inner, {
    this.blockSize = 256 * 1024,
    this.maxBlocks = 32,
  });

  final PdfRandomAccessReader _inner;
  final int blockSize;
  final int maxBlocks;

  final _cache = LinkedHashMap<int, Uint8List>();

  @override
  int get length => _inner.length;

  @override
  Uint8List readRange(int offset, int length) {
    if (offset < 0 || length <= 0 || offset >= _inner.length) {
      return Uint8List(0);
    }
    final end = offset + length > _inner.length ? _inner.length : offset + length;
    final out = Uint8List(end - offset);

    int dst = 0;
    int pos = offset;
    while (pos < end) {
      final blockIndex = pos ~/ blockSize;
      final blockOffset = blockIndex * blockSize;
      final block = _getBlock(blockIndex, blockOffset);
      final startInBlock = pos - blockOffset;
      final copyLen = (end - pos) < (block.length - startInBlock)
          ? (end - pos)
          : (block.length - startInBlock);
      out.setRange(dst, dst + copyLen, block, startInBlock);
      dst += copyLen;
      pos += copyLen;
    }

    return out;
  }

  Uint8List _getBlock(int blockIndex, int blockOffset) {
    final cached = _cache.remove(blockIndex);
    if (cached != null) {
      _cache[blockIndex] = cached; // move to end (LRU)
      return cached;
    }

    final bytes = _inner.readRange(blockOffset, blockSize);
    _cache[blockIndex] = bytes;
    if (_cache.length > maxBlocks) {
      _cache.remove(_cache.keys.first);
    }
    return bytes;
  }

  @override
  Uint8List readAll() => _inner.readAll();

  @override
  void close() => _inner.close();
}
