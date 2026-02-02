import 'dart:typed_data';
import 'base.dart';
import 'pkcs1.dart';
import 'rsa_engine.dart';

class RSASigner implements Signer {
  final Digest _digest;
  final AsymmetricBlockCipher _cipher;
  final String _algorithmName;

  bool _forSigning = false;

  RSASigner(this._digest, this._algorithmName)
      : _cipher = PKCS1Encoding(RSAEngine());

  @override
  String get algorithmName => _algorithmName;

  @override
  void init(bool forSigning, CipherParameters params) {
    _forSigning = forSigning;
    // RSAEngine handles ParametersWithRandom unwrapping
    _cipher.init(forSigning, params);
    _digest.reset();
  }

  @override
  Signature generateSignature(Uint8List message) {
    if (!_forSigning) throw StateError('Not initialized for signing');

    _digest.reset();
    _digest.update(message, 0, message.length);
    var hash = Uint8List(_digest.digestSize);
    _digest.doFinal(hash, 0);

    var digestInfo = _DerHelper.encodeDigestInfo(hash, _digest.algorithmName);

    var sigBytes = _cipher.process(digestInfo);
    return RSASignature(sigBytes);
  }

  @override
  bool verifySignature(Uint8List message, Signature signature) {
    if (_forSigning) throw StateError('Not initialized for verification');

    if (signature is! RSASignature) {
      throw ArgumentError('Invalid signature type');
    }

    _digest.reset();
    _digest.update(message, 0, message.length);
    var hash = Uint8List(_digest.digestSize);
    _digest.doFinal(hash, 0);

    var digestInfo = _DerHelper.encodeDigestInfo(hash, _digest.algorithmName);

    try {
      var decrypted = _cipher.process(signature.bytes);
      // Compare decrypted with digestInfo
      if (decrypted.length != digestInfo.length) return false;
      for (var i = 0; i < decrypted.length; i++) {
        if (decrypted[i] != digestInfo[i]) return false;
      }
      return true;
    } catch (e) {
      return false;
    }
  }

  @override
  void reset() {
    _digest.reset();
    _cipher.reset();
  }
}

class _DerHelper {
  static Uint8List encodeDigestInfo(Uint8List hash, String digestName) {
    // Simplified DER encoding for DigestInfo
    // DigestInfo ::= SEQUENCE {
    //   digestAlgorithm AlgorithmIdentifier,
    //   digest OCTET STRING
    // }
    // SHA-1 OID: 1.3.14.3.2.26
    // SHA-256 OID: 2.16.840.1.101.3.4.2.1

    List<int> oidBytes;
    if (digestName == 'SHA-1') {
      oidBytes = [0x2B, 0x0E, 0x03, 0x02, 0x1A]; // 1.3.14.3.2.26
    } else if (digestName == 'SHA-256') {
      oidBytes = [
        0x60,
        0x86,
        0x48,
        0x01,
        0x65,
        0x03,
        0x04,
        0x02,
        0x01
      ]; // 2.16.840.1.101.3.4.2.1
    } else {
      throw UnsupportedError('Unsupported digest for signing: $digestName');
    }

    // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL }
    // For hash, parameters is usually NULL (05 00)

    var algId = <int>[
      0x30, // SEQUENCE
      oidBytes.length + 2 + 2, // Length (OID + NULL)
      0x06, oidBytes.length, ...oidBytes, // OID
      0x05, 0x00 // NULL
    ];

    var digest = <int>[
      0x04, hash.length, ...hash // OCTET STRING
    ];

    var seq = <int>[
      0x30, // SEQUENCE
      algId.length + digest.length,
      ...algId,
      ...digest
    ];

    return Uint8List.fromList(seq);
  }
}
