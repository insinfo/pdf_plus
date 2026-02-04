//C:\MyDartProjects\pdf_plus\lib\src\pki\x509_certificate.dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/asn1/asn1.dart';
import 'package:pdf_plus/src/pdf/signing/pem_utils.dart';

class X509Certificate {
  X509Certificate._({
    required this.der,
    required this.tbsDer,
    required this.version,
    required this.serialNumber,
    required this.signatureAlgorithmOid,
    required this.tbsSignatureAlgorithmOid,
    required this.issuer,
    required this.subject,
    required this.notBefore,
    required this.notAfter,
    required this.subjectPublicKeyInfoDer,
    required this.signatureValue,
    required this.extensions,
  });

  factory X509Certificate.fromDer(Uint8List der) {
    final parser = ASN1Parser(der);
    final certSeq = parser.nextObject() as ASN1Sequence;
    if (certSeq.elements.length < 3) {
      throw ArgumentError('Invalid X509 certificate: incomplete sequence.');
    }

    final tbs = certSeq.elements[0] as ASN1Sequence;
    final sigAlg = certSeq.elements[1] as ASN1Sequence;
    final sigValue = certSeq.elements[2] as ASN1BitString;

    var index = 0;
    var version = 1;
    final first = tbs.elements[index];
    if (isContextSpecific(first.tag)) {
      final inner = ASN1Parser(first.valueBytes()).nextObject();
      if (inner is ASN1Integer) {
        version = inner.intValue + 1;
      }
      index++;
    }

    final serial = tbs.elements[index++] as ASN1Integer;
    final tbsSigAlg = tbs.elements[index++] as ASN1Sequence;
    final issuerSeq = tbs.elements[index++] as ASN1Sequence;
    final validitySeq = tbs.elements[index++] as ASN1Sequence;
    final subjectSeq = tbs.elements[index++] as ASN1Sequence;
    final spki = tbs.elements[index++] as ASN1Sequence;

    final notBefore = _parseTime(validitySeq.elements[0]);
    final notAfter = _parseTime(validitySeq.elements[1]);

    final extensions = _parseExtensions(tbs, index);

    return X509Certificate._(
      der: Uint8List.fromList(der),
      tbsDer: tbs.encodedBytes,
      version: version,
      serialNumber: serial.valueAsBigInteger,
      signatureAlgorithmOid: _oidFromSequence(sigAlg),
      tbsSignatureAlgorithmOid: _oidFromSequence(tbsSigAlg),
      issuer: X509Name.fromAsn1(issuerSeq),
      subject: X509Name.fromAsn1(subjectSeq),
      notBefore: notBefore,
      notAfter: notAfter,
      subjectPublicKeyInfoDer: spki.encodedBytes,
      signatureValue: Uint8List.fromList(sigValue.contentBytes()),
      extensions: extensions,
    );
  }

  factory X509Certificate.fromPem(String pem) {
    final der = PdfPemUtils.decodeFirstPem(pem, 'CERTIFICATE');
    return X509Certificate.fromDer(der);
  }

  final Uint8List der;
  final Uint8List tbsDer;
  final int version;
  final BigInt serialNumber;
  final String signatureAlgorithmOid;
  final String tbsSignatureAlgorithmOid;
  final X509Name issuer;
  final X509Name subject;
  final DateTime notBefore;
  final DateTime notAfter;
  final Uint8List subjectPublicKeyInfoDer;
  final Uint8List signatureValue;
  final List<X509Extension> extensions;

  String get serialNumberHex => serialNumber.toRadixString(16).toUpperCase();

  bool isValidAt(DateTime instant) {
    final utc = instant.toUtc();
    return !utc.isBefore(notBefore) && !utc.isAfter(notAfter);
  }

  String toPem() {
    final b64 = base64.encode(der);
    final lines = <String>[];
    for (var i = 0; i < b64.length; i += 64) {
      lines.add(b64.substring(i, i + 64 > b64.length ? b64.length : i + 64));
    }
    return '-----BEGIN CERTIFICATE-----\n'
        '${lines.join('\n')}\n'
        '-----END CERTIFICATE-----';
  }
}

class X509Name {
  X509Name(this.attributes);

  factory X509Name.fromAsn1(ASN1Sequence seq) {
    final attrs = <X509NameAttribute>[];
    for (final rdn in seq.elements) {
      final rdnSeqs = <ASN1Sequence>[];
      if (rdn is ASN1Set) {
        for (final el in rdn.elements) {
          if (el is ASN1Sequence) rdnSeqs.add(el);
        }
      } else if (rdn is ASN1Sequence) {
        rdnSeqs.add(rdn);
      }

      for (final attrSeq in rdnSeqs) {
        if (attrSeq.elements.length < 2) continue;
        final oidObj = attrSeq.elements[0] as ASN1ObjectIdentifier;
        final valueObj = attrSeq.elements[1];
        final oid = oidObj.identifier ?? '';
        final shortName = _oidShortName(oid);
        final value = _asn1ValueToString(valueObj);
        attrs.add(
          X509NameAttribute(
            oid: oid,
            shortName: shortName,
            value: value,
          ),
        );
      }
    }
    return X509Name(attrs);
  }

  final List<X509NameAttribute> attributes;

  String? get commonName => _firstByShortName('CN') ?? _firstByOid('2.5.4.3');

  String? get organization => _firstByShortName('O') ?? _firstByOid('2.5.4.10');

  String? get country => _firstByShortName('C') ?? _firstByOid('2.5.4.6');

  String? _firstByShortName(String name) {
    for (final attr in attributes) {
      if (attr.shortName == name) return attr.value;
    }
    return null;
  }

  String? _firstByOid(String oid) {
    for (final attr in attributes) {
      if (attr.oid == oid) return attr.value;
    }
    return null;
  }

  @override
  String toString() {
    if (attributes.isEmpty) return '';
    return attributes
        .map((attr) => '${attr.shortName ?? attr.oid}=${attr.value}')
        .join(', ');
  }
}

class X509NameAttribute {
  X509NameAttribute({
    required this.oid,
    required this.value,
    this.shortName,
  });

  final String oid;
  final String value;
  final String? shortName;
}

class X509Extension {
  X509Extension({
    required this.oid,
    required this.value,
    required this.critical,
  });

  final String oid;
  final Uint8List value;
  final bool critical;
}

String _oidFromSequence(ASN1Sequence seq) {
  if (seq.elements.isEmpty) return '';
  final oid = seq.elements.first;
  if (oid is ASN1ObjectIdentifier) {
    return oid.identifier ?? '';
  }
  return '';
}

DateTime _parseTime(ASN1Object obj) {
  if (obj is ASN1UtcTime) return obj.dateTimeValue;
  if (obj is ASN1GeneralizedTime) return obj.dateTimeValue;
  final parser = ASN1Parser(obj.encodedBytes);
  final parsed = parser.nextObject();
  if (parsed is ASN1UtcTime) return parsed.dateTimeValue;
  if (parsed is ASN1GeneralizedTime) return parsed.dateTimeValue;
  throw ArgumentError('Invalid X509 time.');
}

List<X509Extension> _parseExtensions(ASN1Sequence tbs, int index) {
  if (index >= tbs.elements.length) return const <X509Extension>[];
  for (var i = index; i < tbs.elements.length; i++) {
    final el = tbs.elements[i];
    if (isContextSpecific(el.tag) && (el.tag & 0x1f) == 3) {
      final inner = ASN1Parser(el.valueBytes()).nextObject();
      if (inner is! ASN1Sequence) return const <X509Extension>[];
      final out = <X509Extension>[];
      for (final ext in inner.elements) {
        if (ext is! ASN1Sequence || ext.elements.length < 2) continue;
        final oidObj = ext.elements[0] as ASN1ObjectIdentifier;
        var critical = false;
        var valueIndex = 1;
        if (ext.elements[1] is ASN1Boolean) {
          critical = (ext.elements[1] as ASN1Boolean).booleanValue;
          valueIndex = 2;
        }
        if (ext.elements.length <= valueIndex) continue;
        final valObj = ext.elements[valueIndex] as ASN1OctetString;
        out.add(
          X509Extension(
            oid: oidObj.identifier ?? '',
            value: valObj.valueBytes(),
            critical: critical,
          ),
        );
      }
      return out;
    }
  }
  return const <X509Extension>[];
}

String _asn1ValueToString(ASN1Object obj) {
  if (obj is ASN1UTF8String) return obj.utf8StringValue;
  if (obj is ASN1PrintableString) return obj.stringValue;
  if (obj is ASN1IA5String) return obj.stringValue;
  if (obj is ASN1BMPString) return obj.stringValue;
  if (obj is ASN1TeletextString) return obj.stringValue;
  if (obj is ASN1NumericString) return obj.stringValue;
  return utf8.decode(obj.valueBytes(), allowMalformed: true);
}

String? _oidShortName(String oid) {
  return _oidToName[oid];
}

const Map<String, String> _oidToName = {
  '2.5.4.3': 'CN',
  '2.5.4.4': 'SN',
  '2.5.4.5': 'SERIALNUMBER',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'T',
  '2.5.4.42': 'GIVENNAME',
  '2.5.4.43': 'INITIALS',
  '1.2.840.113549.1.9.1': 'E',
};
