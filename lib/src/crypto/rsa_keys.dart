import 'base.dart';

class RSAPublicKey implements PublicKey {
  final BigInt modulus;
  final BigInt exponent;

  RSAPublicKey(this.modulus, this.exponent);

  BigInt get n => modulus;
  BigInt get e => exponent;
}

class RSAPrivateKey implements PrivateKey {
  final BigInt modulus;
  final BigInt privateExponent;
  final BigInt? p;
  final BigInt? q;

  // Additional CRT parameters could be added if needed, but for now matching basic usage
  final BigInt? dP;
  final BigInt? dQ;
  final BigInt? qInv;

  RSAPrivateKey(this.modulus, this.privateExponent,
      [this.p, this.q, this.dP, this.dQ, this.qInv]);

  BigInt get n => modulus;
  BigInt get d => privateExponent;
}
