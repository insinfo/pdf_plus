import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/asn1/asn1.dart';
import 'package:pdf_plus/src/crypto/sha256.dart';

import 'package:pdf_plus/src/crypto/base.dart';
import 'package:pdf_plus/src/crypto/pkcs1.dart';
import 'package:pdf_plus/src/crypto/rsa_engine.dart';
import 'package:pdf_plus/src/crypto/rsa_keys.dart';

import 'pem_utils.dart';

class PdfCmsSigner {
  /// Helper compatível com dart_pdf: assina digest com RSA/SHA-256 usando PEM.
  static Uint8List signDetachedSha256RsaFromPem({
    required Uint8List contentDigest,
    required String privateKeyPem,
    required String certificatePem,
    List<String> chainPem = const <String>[],
    DateTime? signingTime,
  }) {
    final signerCertDer =
        PdfPemUtils.decodeFirstPem(certificatePem, 'CERTIFICATE');
    final extraCertsDer = <Uint8List>[];
    for (final pem in chainPem) {
      extraCertsDer.addAll(PdfPemUtils.decodePemBlocks(pem, 'CERTIFICATE'));
    }

    final cms = PdfCmsSigner();
    final signedAttrsDer = cms._buildSignedAttributesDer(
      contentDigest: contentDigest,
      signingTime: (signingTime ?? DateTime.now().toUtc()),
    );
    final signedAttrsDigest = Uint8List.fromList(
      sha256.convert(signedAttrsDer).bytes,
    );

    final key = PdfPemUtils.rsaPrivateKeyFromPem(privateKeyPem);
    final signature = _rsaSignDigestSha256(signedAttrsDigest, key);

    return cms._buildCmsSignedData(
      contentDigest: contentDigest,
      signerCertDer: signerCertDer,
      extraCertsDer: extraCertsDer,
      signedAttrsDer: signedAttrsDer,
      signature: signature,
    );
  }

  Future<Uint8List> buildDetachedCms({
    required Uint8List contentDigest,
    required Uint8List signerCertDer,
    List<Uint8List> extraCertsDer = const <Uint8List>[],
    DateTime? signingTime,
    required Future<Uint8List> Function(
      Uint8List signedAttrsDer,
      Uint8List signedAttrsDigest,
    ) signCallback,
  }) async {
    final signedAttrsDer = _buildSignedAttributesDer(
      contentDigest: contentDigest,
      signingTime: signingTime ?? DateTime.now().toUtc(),
    );
    final signedAttrsDigest = Uint8List.fromList(
      sha256.convert(signedAttrsDer).bytes,
    );

    final signature = await signCallback(signedAttrsDer, signedAttrsDigest);
    if (signature.isEmpty) {
      throw StateError('Assinatura externa retornou vazio.');
    }

    return _buildCmsSignedData(
      contentDigest: contentDigest,
      signerCertDer: signerCertDer,
      extraCertsDer: extraCertsDer,
      signedAttrsDer: signedAttrsDer,
      signature: signature,
    );
  }

  Uint8List _buildSignedAttributesDer({
    required Uint8List contentDigest,
    required DateTime signingTime,
  }) {
    final attrs = <Uint8List>[
      _encodeAttribute(
        oid: '1.2.840.113549.1.9.3',
        valueDer: _oid('1.2.840.113549.1.7.1'),
      ),
      _encodeAttribute(
        oid: '1.2.840.113549.1.9.4',
        valueDer: ASN1OctetString(contentDigest).encodedBytes,
      ),
      _encodeAttribute(
        oid: '1.2.840.113549.1.9.5',
        valueDer: _encodeSigningTime(signingTime),
      ),
    ];

    attrs.sort(_compareBytes);
    return _encodeSet(attrs);
  }

  Uint8List _encodeSigningTime(DateTime dt) {
    final utc = dt.toUtc();
    if (utc.year < 2050) {
      return ASN1UtcTime(utc).encodedBytes;
    }
    return ASN1GeneralizedTime(utc).encodedBytes;
  }

  Uint8List _buildCmsSignedData({
    required Uint8List contentDigest,
    required Uint8List signerCertDer,
    required List<Uint8List> extraCertsDer,
    required Uint8List signedAttrsDer,
    required Uint8List signature,
  }) {
    final signerInfoDer = _buildSignerInfoDer(
      signerCertDer: signerCertDer,
      signedAttrsDer: signedAttrsDer,
      signature: signature,
    );

    final digestAlgsDer = _encodeSet([
      _encodeAlgorithmIdentifier('2.16.840.1.101.3.4.2.1'),
    ]);

    final encapContentInfoDer = _encodeSequence([
      _oid('1.2.840.113549.1.7.1'),
    ]);

    final certs = <Uint8List>[signerCertDer, ...extraCertsDer];
    certs.sort(_compareBytes);
    final certsSetDer = _encodeSet(certs);
    final certsTaggedDer = _encodeTagged(0, certsSetDer, explicit: false);

    final signerInfosSetDer = _encodeSet([signerInfoDer]);

    final signedDataDer = _encodeSequence([
      ASN1Integer(BigInt.from(1)).encodedBytes,
      digestAlgsDer,
      encapContentInfoDer,
      certsTaggedDer,
      signerInfosSetDer,
    ]);

    final contentInfoDer = _encodeSequence([
      _oid('1.2.840.113549.1.7.2'),
      _encodeTagged(0, signedDataDer, explicit: true),
    ]);

    return contentInfoDer;
  }

  Uint8List _buildSignerInfoDer({
    required Uint8List signerCertDer,
    required Uint8List signedAttrsDer,
    required Uint8List signature,
  }) {
    final issuerAndSerialDer = _issuerAndSerialDerFromCert(signerCertDer);
    final digestAlgDer = _encodeAlgorithmIdentifier('2.16.840.1.101.3.4.2.1');
    final sigAlgDer = _encodeAlgorithmIdentifier('1.2.840.113549.1.1.1');
    final signedAttrsTaggedDer =
        _encodeTagged(0, signedAttrsDer, explicit: false);

    return _encodeSequence([
      ASN1Integer(BigInt.from(1)).encodedBytes,
      issuerAndSerialDer,
      digestAlgDer,
      signedAttrsTaggedDer,
      sigAlgDer,
      ASN1OctetString(signature).encodedBytes,
    ]);
  }

  Uint8List _issuerAndSerialDerFromCert(Uint8List certDer) {
    final certSeq = ASN1Parser(certDer).nextObject() as ASN1Sequence;
    final tbs = certSeq.elements.first as ASN1Sequence;

    int idx = 0;
    if (tbs.elements.first is! ASN1Integer) {
      idx = 1;
    }

    final serial = tbs.elements[idx] as ASN1Integer;
    final issuer = tbs.elements[idx + 2];

    return _encodeSequence([
      issuer.encodedBytes,
      ASN1Integer(serial.valueAsBigInteger).encodedBytes,
    ]);
  }

  Uint8List _encodeAttribute(
      {required String oid, required Uint8List valueDer}) {
    return _encodeSequence([
      _oid(oid),
      _encodeSet([valueDer]),
    ]);
  }

  Uint8List _encodeAlgorithmIdentifier(String oid) {
    return _encodeSequence([
      _oid(oid),
      ASN1Null().encodedBytes,
    ]);
  }

  Uint8List _oid(String oid) {
    return ASN1ObjectIdentifier.fromComponentString(oid).encodedBytes;
  }

  int _compareBytes(Uint8List a, Uint8List b) {
    final minLen = a.length < b.length ? a.length : b.length;
    for (int i = 0; i < minLen; i++) {
      final diff = a[i] - b[i];
      if (diff != 0) return diff;
    }
    return a.length - b.length;
  }

  Uint8List _encodeSequence(List<Uint8List> elements) {
    return _encodeWithTag(0x30, _concat(elements));
  }

  Uint8List _encodeSet(List<Uint8List> elements) {
    return _encodeWithTag(0x31, _concat(elements));
  }

  Uint8List _encodeTagged(int tag, Uint8List inner, {required bool explicit}) {
    final content = explicit ? inner : _stripTagAndLength(inner);
    return _encodeWithTag(0xA0 + tag, content);
  }

  Uint8List _stripTagAndLength(Uint8List encoded) {
    if (encoded.length < 2) {
      throw StateError('DER inválido para tagged implicit.');
    }
    final lenByte = encoded[1];
    int lengthBytes = 1;
    int length = 0;
    if ((lenByte & 0x80) == 0) {
      length = lenByte;
    } else {
      lengthBytes = lenByte & 0x7F;
      if (encoded.length < 2 + lengthBytes) {
        throw StateError('DER inválido (length).');
      }
      for (int i = 0; i < lengthBytes; i++) {
        length = (length << 8) | encoded[2 + i];
      }
    }
    final contentStart = (lenByte & 0x80) == 0 ? 2 : 2 + lengthBytes;
    return encoded.sublist(contentStart, contentStart + length);
  }

  Uint8List _encodeWithTag(int tag, Uint8List content) {
    final lengthBytes = _encodeLength(content.length);
    final out = Uint8List(1 + lengthBytes.length + content.length);
    out[0] = tag;
    out.setRange(1, 1 + lengthBytes.length, lengthBytes);
    out.setRange(1 + lengthBytes.length, out.length, content);
    return out;
  }

  Uint8List _encodeLength(int length) {
    if (length < 128) {
      return Uint8List.fromList([length]);
    }
    final bytes = <int>[];
    var n = length;
    while (n > 0) {
      bytes.insert(0, n & 0xFF);
      n >>= 8;
    }
    return Uint8List.fromList([0x80 | bytes.length, ...bytes]);
  }

  Uint8List _concat(List<Uint8List> parts) {
    final total = parts.fold<int>(0, (sum, p) => sum + p.length);
    final out = Uint8List(total);
    var offset = 0;
    for (final p in parts) {
      out.setRange(offset, offset + p.length, p);
      offset += p.length;
    }
    return out;
  }
}

Uint8List _rsaSignDigestSha256(Uint8List digest, RSAPrivateKey key) {
  final algId = ASN1Sequence()
    ..add(ASN1ObjectIdentifier.fromComponentString('2.16.840.1.101.3.4.2.1'))
    ..add(ASN1Null());
  final di = ASN1Sequence()
    ..add(algId)
    ..add(ASN1OctetString(digest));
  final digestInfo = di.encodedBytes;

  final signer = PKCS1Encoding(RSAEngine())
    ..init(true, PrivateKeyParameter<RSAPrivateKey>(key));
  final sig = signer.process(digestInfo);
  return Uint8List.fromList(sig);
}
