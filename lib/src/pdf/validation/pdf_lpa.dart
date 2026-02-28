import 'dart:typed_data';

import 'package:pdf_plus/src/crypto/asn1/asn1.dart';
import 'pdf_validation_asn1_utils.dart';

class PdfLpaPolicyInfo {
  PdfLpaPolicyInfo({
    required this.policyOid,
    required this.policyUri,
    this.notBefore,
    this.notAfter,
    this.revocationDate,
    this.hashAlgorithmOid,
    this.hashValue,
  });

  final String policyOid;
  final String policyUri;
  final DateTime? notBefore;
  final DateTime? notAfter;
  final DateTime? revocationDate;
  final String? hashAlgorithmOid;
  final Uint8List? hashValue;
}

class PdfLpa {
  PdfLpa({
    required this.policies,
    this.version,
    this.nextUpdate,
  });

  final int? version;
  final DateTime? nextUpdate;
  final List<PdfLpaPolicyInfo> policies;

  PdfLpaPolicyInfo? findPolicy(String oid) {
    for (final policy in policies) {
      if (policy.policyOid == oid) return policy;
    }
    return null;
  }

  static PdfLpa parse(Uint8List der) {
    final obj = ASN1Parser(der).nextObject();
    final seq = _asSequence(obj);
    if (seq == null || seq.elements.isEmpty) {
      return PdfLpa(policies: const <PdfLpaPolicyInfo>[]);
    }

    var index = 0;
    int? version;
    final first = seq.elements.first;
    if (first is ASN1Integer) {
      version = first.valueAsBigInteger.toInt();
      index = 1;
    }

    final policies = <PdfLpaPolicyInfo>[];
    final policiesElements = _asSequenceElements(seq.elements[index]);
    if (policiesElements != null) {
      for (final policyObj in policiesElements) {
        final info = _parsePolicyInfo(policyObj);
        if (info != null) policies.add(info);
      }
    }

    DateTime? nextUpdate;
    if (seq.elements.length > index + 1) {
      nextUpdate = _parseAsn1Time(seq.elements[index + 1]);
    }

    return PdfLpa(
      policies: policies,
      version: version,
      nextUpdate: nextUpdate,
    );
  }
}

PdfLpaPolicyInfo? _parsePolicyInfo(ASN1Object obj) {
  final seq = _asSequence(obj);
  if (seq == null || seq.elements.length < 3) return null;

  final signingPeriod = _asSequence(seq.elements[0]);
  DateTime? notBefore;
  DateTime? notAfter;
  if (signingPeriod != null && signingPeriod.elements.isNotEmpty) {
    notBefore = _parseAsn1Time(signingPeriod.elements[0]);
    if (signingPeriod.elements.length > 1) {
      notAfter = _parseAsn1Time(signingPeriod.elements[1]);
    }
  }

  var idx = 1;
  DateTime? revocationDate;
  final second = seq.elements[idx];
  if (second is! ASN1ObjectIdentifier) {
    revocationDate = _parseAsn1Time(second);
    idx++;
  }

  if (seq.elements.length <= idx + 2) return null;
  final oidObj = seq.elements[idx];
  final uriObj = seq.elements[idx + 1];
  final digestObj = seq.elements[idx + 2];

  final policyOid = _oidToString(oidObj);
  if (policyOid == null) return null;
  final policyUri = _readString(uriObj) ?? '';

  final digestSeq = _asSequence(digestObj);
  String? hashAlgOid;
  Uint8List? hashValue;
  if (digestSeq != null && digestSeq.elements.length >= 2) {
    final algSeq = _asSequence(digestSeq.elements[0]);
    if (algSeq != null && algSeq.elements.isNotEmpty) {
      hashAlgOid = _oidToString(algSeq.elements.first);
    }
    final hashObj = digestSeq.elements[1];
    if (hashObj is ASN1OctetString) {
      hashValue = hashObj.valueBytes();
    }
  }

  return PdfLpaPolicyInfo(
    policyOid: policyOid,
    policyUri: policyUri,
    notBefore: notBefore,
    notAfter: notAfter,
    revocationDate: revocationDate,
    hashAlgorithmOid: hashAlgOid,
    hashValue: hashValue,
  );
}

ASN1Sequence? _asSequence(ASN1Object obj) {
  if (obj is ASN1Sequence) return obj;
  try {
    final parsed = ASN1Parser(obj.encodedBytes).nextObject();
    if (parsed is ASN1Sequence) return parsed;
  } catch (_) {}
  return null;
}

List<ASN1Object>? _asSequenceElements(ASN1Object obj) {
  if (obj is ASN1Sequence) return obj.elements.cast<ASN1Object>();
  if (obj is ASN1Set) return obj.elements.cast<ASN1Object>().toList();
  final seq = _asSequence(obj);
  return seq?.elements.cast<ASN1Object>();
}

String? _oidToString(ASN1Object obj) {
  return asn1ObjectIdentifierToString(obj);
}

String? _readString(ASN1Object obj) {
  if (obj is ASN1IA5String) return obj.stringValue;
  if (obj is ASN1UTF8String) return String.fromCharCodes(obj.valueBytes());
  if (obj is ASN1PrintableString) return obj.stringValue;
  try {
    final bytes = obj.valueBytes();
    return String.fromCharCodes(bytes);
  } catch (_) {
    return null;
  }
}

DateTime? _parseAsn1Time(ASN1Object obj) {
  return parseAsn1TimeLoose(obj);
}
