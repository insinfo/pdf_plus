import 'dart:typed_data';
import 'base.dart';
import 'rsa_keys.dart';

class RSAEngine extends BaseAsymmetricBlockCipher {
  late bool _forEncryption;
  RSAPrivateKey? _privateKey;
  RSAPublicKey? _publicKey;
  int _bitSize = 0;

  @override
  String get algorithmName => 'RSA';

  @override
  void reset() {}

  @override
  void init(bool forEncryption, CipherParameters params) {
    if (params is ParametersWithRandom) {
      params = params.parameters;
    }

    _forEncryption = forEncryption;
    AsymmetricKey? k;
    if (params is AsymmetricKeyParameter) {
      k = params.key;
    }

    if (forEncryption) {
      if (k is RSAPublicKey) {
        _publicKey = k;
        _bitSize = _publicKey!.modulus.bitLength;
      } else if (k is RSAPrivateKey) {
        // Private key encryption (signing)
        _privateKey = k;
        _bitSize = _privateKey!.modulus.bitLength;
      } else {
        throw ArgumentError('RSA init expected RSAPublicKey or RSAPrivateKey');
      }
    } else {
      if (k is RSAPrivateKey) {
        _privateKey = k;
        _bitSize = _privateKey!.modulus.bitLength;
      } else if (k is RSAPublicKey) {
        // Public key decryption (verifying)
        _publicKey = k;
        _bitSize = _publicKey!.modulus.bitLength;
      } else {
        throw ArgumentError('RSA init expected RSAPrivateKey or RSAPublicKey');
      }
    }
  }

  @override
  int get inputBlockSize {
    if (_forEncryption) {
      return (_bitSize + 7) ~/ 8 - 1;
    } else {
      return (_bitSize + 7) ~/ 8;
    }
  }

  @override
  int get outputBlockSize {
    if (_forEncryption) {
      return (_bitSize + 7) ~/ 8;
    } else {
      return (_bitSize + 7) ~/ 8 - 1;
    }
  }

  @override
  int processBlock(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    // Basic RSA implementation
    if (len > inputBlockSize + 1) {
      throw ArgumentError('Input block too large for RSA key size');
    }

    var input = _decodeBigInt(inp.sublist(inpOff, inpOff + len));

    BigInt output;
    if (_forEncryption) {
      if (_privateKey != null) {
        output =
            input.modPow(_privateKey!.privateExponent, _privateKey!.modulus);
      } else {
        output = input.modPow(_publicKey!.exponent, _publicKey!.modulus);
      }
    } else {
      if (_privateKey != null) {
        output =
            input.modPow(_privateKey!.privateExponent, _privateKey!.modulus);
      } else {
        output = input.modPow(_publicKey!.exponent, _publicKey!.modulus);
      }
    }

    var outBytes = _encodeBigInt(output);

    if (_forEncryption) {
      var targetSize = (_bitSize + 7) ~/ 8;
      if (outBytes.length < targetSize) {
        var padded = Uint8List(targetSize);
        padded.setRange(targetSize - outBytes.length, targetSize, outBytes);
        outBytes = padded;
      } else if (outBytes.length > targetSize) {
        if (outBytes.length == targetSize + 1 && outBytes[0] == 0) {
          outBytes = outBytes.sublist(1);
        } else {
          throw StateError('Output too large');
        }
      }
    } else {
      // Decryption logic if needed
    }

    if (outBytes.length > out.length - outOff) {
      throw ArgumentError('Output buffer too small');
    }

    out.setRange(outOff, outOff + outBytes.length, outBytes);
    return outBytes.length;
  }

  BigInt _decodeBigInt(Uint8List bytes) {
    var result = BigInt.zero;
    for (var i = 0; i < bytes.length; i++) {
      result = (result << 8) | BigInt.from(bytes[i]);
    }
    return result;
  }

  Uint8List _encodeBigInt(BigInt number) {
    if (number == BigInt.zero) return Uint8List.fromList([0]);

    var size = (number.bitLength + 7) >> 3;
    var result = Uint8List(size);
    for (var i = 0; i < size; i++) {
      result[size - i - 1] = (number & BigInt.from(0xff)).toInt();
      number = number >> 8;
    }
    return result;
  }
}
