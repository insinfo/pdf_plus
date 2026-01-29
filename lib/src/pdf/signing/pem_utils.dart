import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/export.dart';

class PdfPemUtils {
  const PdfPemUtils._();

  static List<Uint8List> decodePemBlocks(String pem, String label) {
    final escaped = RegExp.escape(label);
    final re = RegExp(
      '-----BEGIN $escaped-----([\\s\\S]*?)-----END $escaped-----',
      multiLine: true,
    );

    final matches = re.allMatches(pem);
    final out = <Uint8List>[];
    for (final m in matches) {
      final body = (m.group(1) ?? '').replaceAll(RegExp(r'\s+'), '');
      if (body.isEmpty) continue;
      out.add(Uint8List.fromList(base64Decode(body)));
    }
    return out;
  }

  static Uint8List decodeFirstPem(String pem, String label) {
    final blocks = decodePemBlocks(pem, label);
    if (blocks.isEmpty) {
      throw ArgumentError('Nenhum bloco PEM $label encontrado.');
    }
    return blocks.first;
  }

  static RSAPrivateKey rsaPrivateKeyFromPem(String pem) {
    final pkcs1 = decodePemBlocks(pem, 'RSA PRIVATE KEY');
    if (pkcs1.isNotEmpty) {
      return _rsaPrivateKeyFromPkcs1(pkcs1.first);
    }

    final pkcs8 = decodePemBlocks(pem, 'PRIVATE KEY');
    if (pkcs8.isNotEmpty) {
      return _rsaPrivateKeyFromPkcs8(pkcs8.first);
    }

    throw ArgumentError('Chave privada PEM não suportada (apenas PKCS#1/PKCS#8).');
  }

  static RSAPrivateKey _rsaPrivateKeyFromPkcs1(Uint8List der) {
    final parser = ASN1Parser(der);
    final seq = parser.nextObject() as ASN1Sequence;
    if (seq.elements.length < 9) {
      throw ArgumentError('PKCS#1 inválido: sequência incompleta.');
    }
    final modulus = (seq.elements[1] as ASN1Integer).valueAsBigInteger;
    final privateExponent = (seq.elements[3] as ASN1Integer).valueAsBigInteger;
    final p = (seq.elements[4] as ASN1Integer).valueAsBigInteger;
    final q = (seq.elements[5] as ASN1Integer).valueAsBigInteger;
    return RSAPrivateKey(modulus, privateExponent, p, q);
  }

  static RSAPrivateKey _rsaPrivateKeyFromPkcs8(Uint8List der) {
    final parser = ASN1Parser(der);
    final seq = parser.nextObject() as ASN1Sequence;
    if (seq.elements.length < 3) {
      throw ArgumentError('PKCS#8 inválido: sequência incompleta.');
    }
    final privateKeyOctet = seq.elements[2] as ASN1OctetString;
    return _rsaPrivateKeyFromPkcs1(privateKeyOctet.valueBytes());
  }
}
