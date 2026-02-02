import 'dart:math';
import 'dart:typed_data';
import 'base.dart';
import 'registry.dart';

class FortunaRandom implements SecureRandom {
  static final FactoryConfig factoryConfig =
      StaticFactoryConfig(SecureRandom, 'Fortuna', () => FortunaRandom());

  final Random _random;

  FortunaRandom() : _random = Random.secure();

  @override
  String get algorithmName => 'Fortuna';

  @override
  void seed(CipherParameters params) {
    // Random.secure() is self-seeded by the OS.
    // We can ignore the manual seed or use it to re-initialize something if we were writing a true PRNG from scratch.
    // For this removal task, relying on OS secure random is the pragmatic choice.
  }

  @override
  int nextUint8() => _random.nextInt(256);

  int nextUint16() => _random.nextInt(65536);

  int nextUint32() =>
      _random.nextInt(256) << 24 |
      _random.nextInt(256) << 16 |
      _random.nextInt(256) << 8 |
      _random.nextInt(256);

  BigInt nextBigInteger(int bitLength) {
    var fullBytes = bitLength ~/ 8;
    var remainingBits = bitLength % 8;
    var res = BigInt.zero;

    for (var i = 0; i < fullBytes; i++) {
      res = (res << 8) | BigInt.from(nextUint8());
    }

    if (remainingBits > 0) {
      var mask = (1 << remainingBits) - 1;
      res = (res << remainingBits) | BigInt.from(nextUint8() & mask);
    }

    return res;
  }

  @override
  Uint8List nextBytes(int count) {
    final list = Uint8List(count);
    for (int i = 0; i < count; i++) {
      list[i] = _random.nextInt(256);
    }
    return list;
  }
}
