import 'base.dart';
import 'fortuna_random.dart';
import 'rsa_keys.dart';

abstract class KeyGenerator {
  void init(CipherParameters params);
  AsymmetricKeyPair generateKeyPair();

  factory KeyGenerator(String algorithmName) {
    if (algorithmName == 'RSA') {
      return RSAKeyGenerator();
    }
    throw ArgumentError('Unknown KeyGenerator: $algorithmName');
  }
}

class RSAKeyGeneratorParameters extends CipherParameters {
  final BigInt publicExponent;
  final int bitStrength;
  final int certainty;

  RSAKeyGeneratorParameters(
      this.publicExponent, this.bitStrength, this.certainty);
}

class RSAKeyGenerator implements KeyGenerator {
  late RSAKeyGeneratorParameters _params;
  late SecureRandom _random;

  @override
  void init(CipherParameters params) {
    if (params is ParametersWithRandom) {
      _random = params.random;
      _params = params.parameters as RSAKeyGeneratorParameters;
    } else {
      _random = FortunaRandom();
      _params = params as RSAKeyGeneratorParameters;
    }
  }

  @override
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateKeyPair() {
    var bitlen = _params.bitStrength;
    var e = _params.publicExponent;

    BigInt p, q, n;

    var qBitlength = bitlen ~/ 2;
    var pBitlength = bitlen - qBitlength;

    p = _generatePrime(pBitlength, e);
    q = _generatePrime(qBitlength, e);

    if (p < q) {
      var tmp = p;
      p = q;
      q = tmp;
    }

    n = p * q;

    var pSub1 = p - BigInt.one;
    var qSub1 = q - BigInt.one;
    var phi = pSub1 * qSub1;

    var d = e.modInverse(phi);

    var dP = d % pSub1;
    var dQ = d % qSub1;
    var qInv = q.modInverse(p);

    return AsymmetricKeyPair(
        RSAPublicKey(n, e), RSAPrivateKey(n, d, p, q, dP, dQ, qInv));
  }

  BigInt _generatePrime(int bits, BigInt e) {
    while (true) {
      var candidate = _random.nextBigInteger(bits);
      candidate = candidate | BigInt.one;
      if (candidate.bitLength < bits) {
        candidate = candidate | (BigInt.one << (bits - 1));
      }

      if (candidate.gcd(e) != BigInt.one) continue;

      if (_isProbablePrime(candidate, _params.certainty)) {
        return candidate;
      }
    }
  }

  bool _isProbablePrime(BigInt n, int iterations) {
    if (n <= BigInt.one) return false;
    if (n == BigInt.two || n == BigInt.from(3)) return true;
    if (n.isEven) return false;

    var nSub1 = n - BigInt.one;
    var s = 0;
    var d = nSub1;
    while (d.isEven) {
      d = d >> 1;
      s++;
    }

    for (var i = 0; i < iterations; i++) {
      var a = _random.nextBigInteger(n.bitLength);
      if (a <= BigInt.one) a = BigInt.two;
      if (a >= nSub1) a = nSub1 - BigInt.one;

      var x = a.modPow(d, n);
      if (x == BigInt.one || x == nSub1) continue;

      var composite = true;
      for (var r = 1; r < s; r++) {
        x = x.modPow(BigInt.two, n);
        if (x == nSub1) {
          composite = false;
          break;
        }
      }
      if (composite) return false;
    }
    return true;
  }
}
