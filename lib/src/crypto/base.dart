import 'dart:typed_data';

abstract class BaseAsymmetricBlockCipher extends AsymmetricBlockCipher {
  @override
  String get algorithmName;

  @override
  void reset() {}
}

/// The base class for all cipher parameters.
abstract class CipherParameters {}

/// A [CipherParameters] that holds a key.
class KeyParameter extends CipherParameters {
  final Uint8List key;

  KeyParameter(this.key);
}

/// A [CipherParameters] that holds an asymmetric key.
class AsymmetricKeyParameter<T extends AsymmetricKey> extends CipherParameters {
  final T key;

  AsymmetricKeyParameter(this.key);
}

class PrivateKeyParameter<T extends PrivateKey>
    extends AsymmetricKeyParameter<T> {
  PrivateKeyParameter(T key) : super(key);
}

class PublicKeyParameter<T extends PublicKey>
    extends AsymmetricKeyParameter<T> {
  PublicKeyParameter(T key) : super(key);
}

/// A marker interface for asymmetric keys.
abstract class AsymmetricKey {
  const AsymmetricKey();
}

/// A marker interface for public keys.
abstract class PublicKey extends AsymmetricKey {
  const PublicKey();
}

/// A marker interface for private keys.
abstract class PrivateKey extends AsymmetricKey {
  const PrivateKey();
}

/// A pair of asymmetric keys (a public one and a private one).
class AsymmetricKeyPair<B extends PublicKey, V extends PrivateKey> {
  final B publicKey;
  final V privateKey;

  AsymmetricKeyPair(this.publicKey, this.privateKey);
}

/// The interface for all algorithms.
abstract class Algorithm {
  String get algorithmName;
}

/// The interface for block ciphers.
abstract class BlockCipher implements Algorithm {
  /// Initialise the cipher for processing.
  void init(bool forEncryption, CipherParameters params);

  /// Process a block of data.
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff);

  /// Reset the cipher.
  void reset();

  /// The block size of the cipher.
  int get blockSize;
}

/// The interface for asymmetric block ciphers.
abstract class AsymmetricBlockCipher implements Algorithm {
  /// Initialise the cipher for processing.
  void init(bool forEncryption, CipherParameters params);

  /// Process a block of data.
  int processBlock(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff);

  /// Helper to process a whole block at once
  Uint8List process(Uint8List data) {
    var out = Uint8List(outputBlockSize);
    var len = processBlock(data, 0, data.length, out, 0);
    return out.sublist(0, len);
  }

  /// Reset the cipher.
  void reset();

  /// The input block size of the cipher.
  int get inputBlockSize;

  /// The output block size of the cipher.
  int get outputBlockSize;
}

/// The interface for secure random number generators.
abstract class SecureRandom implements Algorithm {
  void seed(CipherParameters params);
  int nextUint8();
  Uint8List nextBytes(int count);
  BigInt nextBigInteger(int bitLength) {
    // Default impl or force override?
    // Usually interfaces don't have body unless abstract class.
    // SecureRandom is abstract class.
    // I can provide simple impl here or force subclass.
    throw UnimplementedError();
  }

  factory SecureRandom(String algorithmName) {
    // Basic factory logic orthrow if not implemented
    throw UnsupportedError(
        'Implementation required via registry or manual instantiation');
  }
}

/// The interface for digests (hash functions).
abstract class Digest implements Algorithm {
  void reset();
  void updateByte(int inp);
  void update(Uint8List inp, int inpOff, int len);
  int doFinal(Uint8List out, int outOff);

  int get digestSize;
  int get byteLength;

  Uint8List process(Uint8List data) {
    update(data, 0, data.length);
    var out = Uint8List(digestSize);
    doFinal(out, 0);
    return out;
  }
}

/// The interface for signers.
abstract class Signer implements Algorithm {
  void init(bool forSigning, CipherParameters params);

  /// Generates a signature for the given message.
  Signature generateSignature(Uint8List message);

  /// Verifies the given signature against the given message.
  bool verifySignature(Uint8List message, Signature signature);

  void reset();

  factory Signer(String algorithmName) {
    throw UnsupportedError(
        'Implementation required via registry or manual instantiation');
  }
}

/// The base class for all signatures.
abstract class Signature {
  const Signature();
}

class RSASignature extends Signature {
  final Uint8List bytes;
  RSASignature(this.bytes);
}

class ParametersWithRandom extends CipherParameters {
  final CipherParameters parameters;
  final SecureRandom random;

  ParametersWithRandom(this.parameters, this.random);
}

class ParametersWithIV<T extends CipherParameters> extends CipherParameters {
  final T parameters;
  final Uint8List iv;

  ParametersWithIV(this.parameters, this.iv);
}
