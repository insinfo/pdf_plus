import 'dart:typed_data';
import 'package:pdf_plus/src/crypto/sha1.dart' as crypto_sha1;
import 'package:pdf_plus/src/crypto/sha256.dart' as crypto_sha256;
import 'package:pdf_plus/src/crypto/digest.dart' as crypto_digest;
import 'base.dart';

class SHA1Digest extends Digest {
  dynamic _sink;

  SHA1Digest() {
    reset();
  }

  @override
  String get algorithmName => 'SHA-1';

  @override
  int get digestSize => 20;

  @override
  int get byteLength => 64;

  @override
  void reset() {
    _captured = null;
    var innerSink = _DigestSink((d) {
      _captured = d.bytes;
    });
    _sink = crypto_sha1.sha1.startChunkedConversion(innerSink);
  }

  List<int>? _captured;

  @override
  void updateByte(int inp) {
    _sink.add([inp]);
  }

  @override
  void update(Uint8List inp, int inpOff, int len) {
    _sink.add(inp.sublist(inpOff, inpOff + len));
  }

  @override
  int doFinal(Uint8List out, int outOff) {
    _sink.close();
    if (_captured == null) throw StateError('Digest failure');
    var res = Uint8List.fromList(_captured!);
    out.setRange(outOff, outOff + res.length, res);
    reset();
    return res.length;
  }
}

class _DigestSink implements Sink<crypto_digest.Digest> {
  final void Function(crypto_digest.Digest) callback;
  _DigestSink(this.callback);

  @override
  void add(crypto_digest.Digest data) => callback(data);

  @override
  void close() {}
}

class SHA256Digest extends Digest {
  dynamic _sink;

  SHA256Digest() {
    reset();
  }

  @override
  String get algorithmName => 'SHA-256';

  @override
  int get digestSize => 32;

  @override
  int get byteLength => 64;

  @override
  void reset() {
    _captured = null;
    var innerSink = _DigestSink((d) {
      _captured = d.bytes;
    });
    _sink = crypto_sha256.sha256.startChunkedConversion(innerSink);
  }

  List<int>? _captured;

  @override
  void updateByte(int inp) {
    _sink.add([inp]);
  }

  @override
  void update(Uint8List inp, int inpOff, int len) {
    _sink.add(inp.sublist(inpOff, inpOff + len));
  }

  @override
  int doFinal(Uint8List out, int outOff) {
    _sink.close();
    if (_captured == null) throw StateError('Digest failure');
    var res = Uint8List.fromList(_captured!);
    out.setRange(outOff, outOff + res.length, res);
    reset();
    return res.length;
  }
}
