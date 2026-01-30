import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/export.dart';

/// Utilities to export PKI material (DER/keys) into PEM.
class PkiPemUtils {
  const PkiPemUtils._();

  /// Encodes an RSA private key (PKCS#1) to PEM.
  ///
  /// If [publicExponent] is not provided, 65537 is used.
  static String rsaPrivateKeyToPem(
    RSAPrivateKey privateKey, {
    BigInt? publicExponent,
  }) {
    final BigInt? n = privateKey.n;
    final BigInt? d = privateKey.exponent;
    final BigInt? p = privateKey.p;
    final BigInt? q = privateKey.q;

    if (n == null || d == null || p == null || q == null) {
      throw ArgumentError(
        'RSAPrivateKey missing CRT parameters (n, d, p, q).',
      );
    }

    final BigInt e = publicExponent ?? BigInt.from(65537);
    final BigInt dp = d % (p - BigInt.one);
    final BigInt dq = d % (q - BigInt.one);
    final BigInt qInv = q.modInverse(p);

    final ASN1Sequence seq = ASN1Sequence();
    seq.add(ASN1Integer(BigInt.zero)); // version
    seq.add(ASN1Integer(n));
    seq.add(ASN1Integer(e));
    seq.add(ASN1Integer(d));
    seq.add(ASN1Integer(p));
    seq.add(ASN1Integer(q));
    seq.add(ASN1Integer(dp));
    seq.add(ASN1Integer(dq));
    seq.add(ASN1Integer(qInv));

    return _wrapPem('RSA PRIVATE KEY', seq.encodedBytes);
  }

  /// Encodes a certificate DER to PEM.
  static String certificateDerToPem(Uint8List der) {
    return _wrapPem('CERTIFICATE', der);
  }

  /// Encodes a list of certificate DER blobs to PEM list.
  static List<String> certificateChainDerToPem(List<Uint8List> chainDer) {
    return chainDer.map(certificateDerToPem).toList(growable: false);
  }

  /// Encodes a list of certificate DER blobs into a single PEM bundle.
  static String certificateChainDerToPemBundle(List<Uint8List> chainDer) {
    return certificateChainDerToPem(chainDer).join('\n');
  }

  static String _wrapPem(String label, Uint8List derBytes) {
    final String b64 = base64.encode(derBytes);
    final StringBuffer buffer = StringBuffer();
    buffer.writeln('-----BEGIN $label-----');
    for (int i = 0; i < b64.length; i += 64) {
      buffer.writeln(
        b64.substring(i, (i + 64 < b64.length) ? i + 64 : b64.length),
      );
    }
    buffer.writeln('-----END $label-----');
    return buffer.toString();
  }
}
