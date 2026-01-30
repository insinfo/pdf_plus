
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/export.dart';

/// Utilities for cryptographic operations and random data.
class PkiUtils {
  static final SecureRandom _secureRandom = _initSecureRandom();

  static SecureRandom _initSecureRandom() {
    final secureRandom = SecureRandom('Fortuna')
      ..seed(KeyParameter(Uint8List.fromList(List.generate(32, (_) => Random.secure().nextInt(255)))));
    return secureRandom;
  }

  static SecureRandom getSecureRandom() => _secureRandom;

  static AsymmetricKeyPair<PublicKey, PrivateKey> generateRsaKeyPair({int bitStrength = 2048}) {
    final keyGen = KeyGenerator('RSA')
      ..init(ParametersWithRandom(
          RSAKeyGeneratorParameters(BigInt.parse('65537'), bitStrength, 64),
          _secureRandom));
    return keyGen.generateKeyPair();
  }

  /// Generates a cryptographically strong random serial number.
  ///
  /// [bytes] should be between 8 and 20 for production use (RFC 5280).
  static BigInt generateSerialNumberBigInt({int bytes = 16}) {
    if (bytes < 4 || bytes > 20) {
      throw RangeError.range(bytes, 4, 20, 'bytes');
    }
    final Uint8List serialBytes = _secureRandom.nextBytes(bytes);
    // Ensure positive and non-zero by clearing MSB and setting LSB.
    serialBytes[0] = serialBytes[0] & 0x7F;
    serialBytes[serialBytes.length - 1] |= 0x01;
    BigInt serial = BigInt.zero;
    for (final int b in serialBytes) {
      serial = (serial << 8) | BigInt.from(b);
    }
    return serial == BigInt.zero ? BigInt.one : serial;
  }
}

/// A builder for creating X.509 certificates and PKI chains (Root, Intermediate, Leaf).
class PkiBuilder {
  static const String oidCommonName = '2.5.4.3';
  static const String oidOrganizationName = '2.5.4.10';
  static const String oidCountryName = '2.5.4.6';
  
  static const String oidKeyUsage = '2.5.29.15';
  static const String oidBasicConstraints = '2.5.29.19';
  static const String oidSubjectKeyIdentifier = '2.5.29.14';
  static const String oidAuthorityKeyIdentifier = '2.5.29.35';
  static const String oidExtKeyUsage = '2.5.29.37';
  static const String oidCrlDistributionPoints = '2.5.29.31';
  static const String oidAuthorityInfoAccess = '1.3.6.1.5.5.7.1.1';
  static const String oidSubjectAltName = '2.5.29.17';
  
  /// Algorithms
  static const String sha256WithRSAEncryption = '1.2.840.113549.1.1.11';
  static const String rsaEncryption = '1.2.840.113549.1.1.1';

  /// Generates a Self-Signed Root CA Certificate.
  static Uint8List createRootCertificate({
    required AsymmetricKeyPair<PublicKey, PrivateKey> keyPair,
    required String dn,
    int validityYears = 10,
  }) {
    final now = DateTime.now();
    return createCertificate(
      keyPair: keyPair,
      issuerKeyPair: keyPair, // Self-signed
      subjectDn: dn,
      issuerDn: dn,
      serialNumber: 1,
      notBefore: now,
      notAfter: now.add(Duration(days: 365 * validityYears)),
      isCa: true,
    );
  }

  /// Generates an Intermediate CA Certificate signed by [issuerKeyPair].
  static Uint8List createIntermediateCertificate({
    required AsymmetricKeyPair<PublicKey, PrivateKey> keyPair,
    required AsymmetricKeyPair<PublicKey, PrivateKey> issuerKeyPair,
    required String subjectDn,
    required String issuerDn,
    required int serialNumber,
    BigInt? serialNumberBigInt,
    List<String>? crlUrls,
    List<String>? ocspUrls,
    List<String>? extendedKeyUsageOids,
    int validityYears = 5,
  }) {
    final now = DateTime.now();
    return createCertificate(
      keyPair: keyPair,
      issuerKeyPair: issuerKeyPair,
      subjectDn: subjectDn,
      issuerDn: issuerDn,
      serialNumber: serialNumber,
      serialNumberBigInt: serialNumberBigInt,
      notBefore: now,
      notAfter: now.add(Duration(days: 365 * validityYears)),
      isCa: true, // It is a CA
      crlUrls: crlUrls,
      ocspUrls: ocspUrls,
      extendedKeyUsageOids: extendedKeyUsageOids,
    );
  }

  /// Generates a User (End-Entity) Certificate signed by [issuerKeyPair].
  static Uint8List createUserCertificate({
    required AsymmetricKeyPair<PublicKey, PrivateKey> keyPair,
    required AsymmetricKeyPair<PublicKey, PrivateKey> issuerKeyPair,
    required String subjectDn,
    required String issuerDn,
    required int serialNumber,
    BigInt? serialNumberBigInt,
    List<String>? crlUrls,
    List<String>? ocspUrls,
    List<String>? extendedKeyUsageOids,
    int validityDays = 365,
  }) {
    final now = DateTime.now();
    return createCertificate(
      keyPair: keyPair,
      issuerKeyPair: issuerKeyPair,
      subjectDn: subjectDn,
      issuerDn: issuerDn,
      serialNumber: serialNumber,
      serialNumberBigInt: serialNumberBigInt,
      notBefore: now,
      notAfter: now.add(Duration(days: validityDays)),
      isCa: false, // End entity
      crlUrls: crlUrls,
      ocspUrls: ocspUrls,
      extendedKeyUsageOids: extendedKeyUsageOids,
    );
  }

  /// Low-level X.509 Certificate creation.
  static Uint8List createCertificate({
    required AsymmetricKeyPair<PublicKey, PrivateKey> keyPair,
    required AsymmetricKeyPair<PublicKey, PrivateKey> issuerKeyPair,
    required String subjectDn,
    required String issuerDn,
    required int serialNumber,
    BigInt? serialNumberBigInt,
    required DateTime notBefore,
    required DateTime notAfter,
    bool isCa = false,
    List<String>? crlUrls,
    List<String>? ocspUrls,
    List<PkiOtherName>? subjectAltNameOtherNames,
    List<String>? extendedKeyUsageOids,
    int? keyUsageBits,
  }) {
    // 1. Create TBSCertificate
    final tbs = ASN1Sequence();

    // Version (v3 = 2) - [0] EXPLICIT wrapping INTEGER 2
    final versionWrapper = ASN1Sequence(tag: 0xA0); 
    versionWrapper.add(ASN1Integer(BigInt.from(2)));
    tbs.add(versionWrapper);

    // Serial Number
    final BigInt serial = serialNumberBigInt ?? BigInt.from(serialNumber);
    tbs.add(ASN1Integer(serial));

    // Algorithm ID
    tbs.add(createAlgorithmIdentifier(sha256WithRSAEncryption));

    // Issuer
    tbs.add(createName(issuerDn));

    // Validity
    final validity = ASN1Sequence();
    validity.add(_encodeTime(notBefore));
    validity.add(_encodeTime(notAfter));
    tbs.add(validity);

    // Subject
    tbs.add(createName(subjectDn));

    // Subject Public Key Info
    tbs.add(createSubjectPublicKeyInfo(keyPair.publicKey as RSAPublicKey));
    
    // Extensions
    final extensions = ASN1Sequence();
    
    // Basic Constraints
    extensions.add(createExtension(
      oidBasicConstraints,
      createBasicConstraints(isCa),
      critical: true,
    ));

    // Key Usage
    extensions.add(createExtension(
      oidKeyUsage,
      createKeyUsage(isCa, keyUsageBits: keyUsageBits),
      critical: true,
    ));

    // Subject Key Identifier (SKID)
    final subjectKeyBytes = _encodePublicKeyInfo(keyPair.publicKey as RSAPublicKey);
    final subjectKeyId = _calculateSha1(subjectKeyBytes);
    extensions.add(createExtension(
      oidSubjectKeyIdentifier,
      ASN1OctetString(subjectKeyId),
    ));

    // Authority Key Identifier (AKID)
    // RFC 5280: The authority key identifier extension ... MUST be present in all certificates 
    // ... EXCEPT ... self-signed CA certificates.
    if (subjectDn != issuerDn) { 
        final issuerKeyBytes = _encodePublicKeyInfo(issuerKeyPair.publicKey as RSAPublicKey);
        final issuerKeyId = _calculateSha1(issuerKeyBytes);
        
        final akiSeq = ASN1Sequence();
        // keyIdentifier [0] IMPLICIT KeyIdentifier
        // KeyIdentifier is OCTET STRING. Implicit tag replaces it with [0] (0x80).
        final keyIdOctet = ASN1OctetString(issuerKeyId, tag: 0x80);
        akiSeq.add(keyIdOctet);
    
        extensions.add(createExtension(
          oidAuthorityKeyIdentifier,
          akiSeq,
        ));
    }

    if (crlUrls != null && crlUrls.isNotEmpty) {
      extensions.add(createExtension(
        oidCrlDistributionPoints,
        createCrlDistributionPoints(crlUrls),
      ));
    }
    
    if (ocspUrls != null && ocspUrls.isNotEmpty) {
       extensions.add(createExtension(
        oidAuthorityInfoAccess,
        _createAuthorityInfoAccess(ocspUrls),
       ));
    }

    if (subjectAltNameOtherNames != null &&
        subjectAltNameOtherNames.isNotEmpty) {
      extensions.add(createExtension(
        oidSubjectAltName,
        createSubjectAltName(subjectAltNameOtherNames),
      ));
    }

    if (extendedKeyUsageOids != null && extendedKeyUsageOids.isNotEmpty) {
      extensions.add(createExtension(
        oidExtKeyUsage,
        createExtendedKeyUsage(extendedKeyUsageOids),
      ));
    }

    // Wrap extensions in [3] Explicit
    final extWrapper = ASN1Sequence(tag: 0xA3);
    extWrapper.add(extensions);
    tbs.add(extWrapper);

    // 2. Sign
    final signature = signData(tbs.encodedBytes, issuerKeyPair.privateKey as RSAPrivateKey);

    // 3. Assemble Certificate
    final cert = ASN1Sequence();
    cert.add(tbs);
    cert.add(createAlgorithmIdentifier(sha256WithRSAEncryption)); 
    cert.add(ASN1BitString(signature));

    return cert.encodedBytes;
  }

  static Uint8List _encodePublicKeyInfo(RSAPublicKey publicKey) {
    final keySeq = ASN1Sequence();
    keySeq.add(ASN1Integer(publicKey.modulus!));
    keySeq.add(ASN1Integer(publicKey.exponent!));
    return keySeq.encodedBytes;
  }

  static Uint8List _calculateSha1(Uint8List data) {
    final digest = SHA1Digest();
    return digest.process(data);
  }

  static ASN1Sequence createAlgorithmIdentifier(String oid) {
    final seq = ASN1Sequence();
    seq.add(ASN1ObjectIdentifier.fromComponentString(oid));
    seq.add(ASN1Null());
    return seq;
  }

  static ASN1Sequence createName(String dn) {
    final seq = ASN1Sequence();
    final parts = dn.split(',');
    for (final part in parts) {
      final kv = part.trim().split('=');
      if (kv.length != 2) continue;
      
      final type = kv[0].trim().toUpperCase();
      final value = kv[1].trim();

      String? oid;
      if (type == 'CN') oid = oidCommonName;
      else if (type == 'O') oid = oidOrganizationName;
      else if (type == 'C') oid = oidCountryName;
      else if (type == 'OU') oid = '2.5.4.11';
      else if (type == 'L') oid = '2.5.4.7';
      else if (type == 'ST') oid = '2.5.4.8';
      else if (type == 'E' || type == 'EMAIL') oid = '1.2.840.113549.1.9.1';
      else if (type == 'SERIALNUMBER') oid = '2.5.4.5';

      if (oid != null) {
        final set = ASN1Set();
        final attrSeq = ASN1Sequence();
        attrSeq.add(ASN1ObjectIdentifier.fromComponentString(oid));
        attrSeq.add(_encodeDnValue(oid, value));
        set.add(attrSeq);
        seq.add(set);
      }
    }
    return seq;
  }

  static ASN1Sequence createSubjectPublicKeyInfo(RSAPublicKey publicKey) {
    final seq = ASN1Sequence();
    seq.add(createAlgorithmIdentifier(rsaEncryption)); 
    
    final keySeq = ASN1Sequence();
    keySeq.add(ASN1Integer(publicKey.modulus!));
    keySeq.add(ASN1Integer(publicKey.exponent!));
    
    seq.add(ASN1BitString(keySeq.encodedBytes));
    return seq;
  }
  
  static ASN1Sequence createExtension(String oid, ASN1Object value, {bool critical = false}) {
    final seq = ASN1Sequence();
    seq.add(ASN1ObjectIdentifier.fromComponentString(oid));
    if (critical) {
      seq.add(ASN1Boolean(true));
    }
    seq.add(ASN1OctetString(value.encodedBytes));
    return seq;
  }

  static ASN1Sequence createBasicConstraints(bool isCa) {
    final seq = ASN1Sequence();
    if (isCa) {
      seq.add(ASN1Boolean(true));
    }
    return seq;
  }

  static ASN1BitString createKeyUsage(bool isCa, {int? keyUsageBits}) {
    final int bits = keyUsageBits ?? (isCa ? 0x06 : 0xC0);
    return ASN1BitString(Uint8List.fromList([bits]));
  }

  static ASN1Sequence createCrlDistributionPoints(List<String> urls) {
     final points = ASN1Sequence();
     for (final url in urls) {
       final dp = ASN1Sequence(); // DistributionPoint
       
       // fullName [0] IMPLICIT GeneralNames
       final fullName = ASN1Sequence(tag: 0xA0); 
       // GeneralNames SEQUENCE
       final gn = ASN1IA5String(url, tag: 0x86); // [6] IMPLICIT IA5String (URL)
       // Add gn to fullName (which is acting as GeneralNames sequence but tagged A0)
       fullName.add(gn);
       
       // distributionPoint [0] EXPLICIT DistributionPointName
       // Since DistributionPointName is CHOICE { fullName [0] ... }
       // It seems complex. Let's simplify and make distributionPoint [0] EXPLICIT containing fullName
       
       final dpField = ASN1Sequence(tag: 0xA0);
       dpField.add(fullName);
       
       dp.add(dpField);
       points.add(dp);
     }
     return points;
  }
  
  static ASN1Sequence _createAuthorityInfoAccess(List<String> urls) {
    final seq = ASN1Sequence();
    for (final url in urls) {
      final accessDesc = ASN1Sequence();
      accessDesc.add(ASN1ObjectIdentifier.fromComponentString('1.3.6.1.5.5.7.48.1')); // OCSP
      final gn = ASN1IA5String(url, tag: 0x86);
      accessDesc.add(gn);
      seq.add(accessDesc);
    }
    return seq;
  }

  static ASN1Sequence createExtendedKeyUsage(List<String> oids) {
    final seq = ASN1Sequence();
    for (final oid in oids) {
      seq.add(ASN1ObjectIdentifier.fromComponentString(oid));
    }
    return seq;
  }

  static ASN1Object _encodeDnValue(String oid, String value) {
    if (oid == oidCountryName) {
      return ASN1PrintableString(value);
    }
    if (oid == '1.2.840.113549.1.9.1') {
      return ASN1IA5String(value);
    }
    return ASN1UTF8String(value);
  }

  static ASN1Object _encodeTime(DateTime time) {
    final int year = time.toUtc().year;
    if (year >= 2050 || year < 1950) {
      return ASN1GeneralizedTime(time.toUtc());
    }
    return ASN1UtcTime(time.toUtc());
  }

  static ASN1Sequence createSubjectAltName(List<PkiOtherName> otherNames) {
    final seq = ASN1Sequence();
    for (final otherName in otherNames) {
      final otherNameSeq = ASN1Sequence();
      otherNameSeq
          .add(ASN1ObjectIdentifier.fromComponentString(otherName.oid));

      final value = ASN1UTF8String(otherName.value);
      final valueWrapper = ASN1Sequence(tag: 0xA0);
      valueWrapper.add(value);
      otherNameSeq.add(valueWrapper);

      final generalNameWrapper = ASN1Sequence(tag: 0xA0);
      generalNameWrapper.add(otherNameSeq);
      seq.add(generalNameWrapper);
    }
    return seq;
  }

  static Uint8List createCRL({
    required AsymmetricKeyPair<PublicKey, PrivateKey> issuerKeyPair,
    required String issuerDn,
    required List<RevokedCertificate> revokedCertificates,
    required DateTime thisUpdate,
    required DateTime nextUpdate,
    required int crlNumber,
  }) {
    final tbs = ASN1Sequence();
    tbs.add(ASN1Integer(BigInt.from(1))); // Version 2
    tbs.add(createAlgorithmIdentifier(sha256WithRSAEncryption));
    tbs.add(createName(issuerDn));
    tbs.add(ASN1UtcTime(thisUpdate));
    tbs.add(ASN1UtcTime(nextUpdate));

    if (revokedCertificates.isNotEmpty) {
      final revSeq = ASN1Sequence();
      for (final rev in revokedCertificates) {
        final entry = ASN1Sequence();
        entry.add(ASN1Integer(rev.serialNumber));
        entry.add(ASN1UtcTime(rev.revocationDate));
        if (rev.reasonCode != null) {
          final extSeq = ASN1Sequence();
          final reasonExt = ASN1Sequence();
          reasonExt.add(ASN1ObjectIdentifier.fromComponentString('2.5.29.21'));
          final enumVal = ASN1Integer(BigInt.from(rev.reasonCode!), tag: 0x0A);
          reasonExt.add(ASN1OctetString(enumVal.encodedBytes));
          extSeq.add(reasonExt);
          entry.add(extSeq);
        }
        revSeq.add(entry);
      }
      tbs.add(revSeq);
    }

    final extCrl = ASN1Sequence();
    final crlNumExt = ASN1Sequence();
    crlNumExt.add(ASN1ObjectIdentifier.fromComponentString('2.5.29.20'));
    final numInt = ASN1Integer(BigInt.from(crlNumber));
    crlNumExt.add(ASN1OctetString(numInt.encodedBytes));
    extCrl.add(crlNumExt);

    final extWrapper = ASN1Sequence(tag: 0xA0);
    extWrapper.add(extCrl);
    tbs.add(extWrapper);

    final signature = signData(tbs.encodedBytes, issuerKeyPair.privateKey as RSAPrivateKey);

    final crl = ASN1Sequence();
    crl.add(tbs);
    crl.add(createAlgorithmIdentifier(sha256WithRSAEncryption));
    crl.add(ASN1BitString(signature));

    return crl.encodedBytes;
  }

  static Uint8List createOCSPResponse({
    required AsymmetricKeyPair<PublicKey, PrivateKey> responderKeyPair,
    required AsymmetricKeyPair<PublicKey, PrivateKey> issuerKeyPair,
    required Uint8List requestBytes,
    required OcspEntryStatus Function(BigInt serial) checkStatus,
  }) {
    final parser = ASN1Parser(requestBytes);
    final reqSeq = parser.nextObject() as ASN1Sequence;
    final tbsReq = reqSeq.elements[0] as ASN1Sequence;
    
    var reqListIndex = 0;
    while(reqListIndex < tbsReq.elements.length && tbsReq.elements[reqListIndex] is! ASN1Sequence) {
        reqListIndex++;
    }
    final requestList = tbsReq.elements[reqListIndex] as ASN1Sequence;

    Uint8List? nonce;
    for(final el in tbsReq.elements) {
        if (el.tag == 0xA2) { // [2] explicit Extensions
           final extSeq = el as ASN1Sequence;
           if (extSeq.elements.isNotEmpty) {
               final inner = extSeq.elements[0] as ASN1Sequence;
               for(final ext in inner.elements) {
                  final seq = ext as ASN1Sequence;
                  final oidObj = seq.elements[0] as ASN1ObjectIdentifier;
                  final nonceOid = ASN1ObjectIdentifier.fromComponentString('1.3.6.1.5.5.7.48.1.2');
                  
                  bool match = true;
                  if (oidObj.encodedBytes.length != nonceOid.encodedBytes.length) {
                      match = false;
                  } else {
                      for(int i=0; i<oidObj.encodedBytes.length; i++) {
                          if (oidObj.encodedBytes[i] != nonceOid.encodedBytes[i]) {
                              match = false;
                              break;
                          }
                      }
                  }

                  if (match) {
                      nonce = (seq.elements[1] as dynamic).valueBytes();
                  }
               }
           }
        }
    }

    final responses = ASN1Sequence();
    for (final req in requestList.elements) {
       final reqSeq = req as ASN1Sequence;
       final certId = reqSeq.elements[0] as ASN1Sequence;
       final serialC = certId.elements[3] as ASN1Integer;
       final serial = serialC.valueAsBigInteger;

       final statusInfo = checkStatus(serial);

       final singleResp = ASN1Sequence();
       singleResp.add(certId);

       if (statusInfo.status == 0) { // Good
          singleResp.add(ASN1Null(tag: 0x80));
       } else if (statusInfo.status == 1) { // Revoked
           final revInfo = ASN1Sequence(tag: 0xA1);
           revInfo.add(ASN1GeneralizedTime(statusInfo.revocationTime ?? DateTime.now(), tag: 0x18));
           if (statusInfo.revocationReason != null) {
              final enumVal = ASN1Integer(BigInt.from(statusInfo.revocationReason!), tag: 0xA0);
              revInfo.add(enumVal);
           }
           singleResp.add(revInfo);
       } else { // Unknown
           singleResp.add(ASN1Null(tag: 0x82));
       }

       singleResp.add(ASN1GeneralizedTime(statusInfo.thisUpdate ?? DateTime.now().toUtc()));
       if (statusInfo.nextUpdate != null) {
          final nextWrapper = ASN1Sequence(tag: 0xA0);
          nextWrapper.add(ASN1GeneralizedTime(statusInfo.nextUpdate!));
          singleResp.add(nextWrapper);
       }
       
       responses.add(singleResp);
    }
    
    final responseData = ASN1Sequence();
    
    final responderKeyHash = _calculateSha1(_encodePublicKeyInfo(responderKeyPair.publicKey as RSAPublicKey));
    final rid = ASN1OctetString(responderKeyHash, tag: 0x82);
    responseData.add(rid); 
    
    responseData.add(ASN1GeneralizedTime(DateTime.now().toUtc()));
    responseData.add(responses);
    
    if (nonce != null) {
       final extSeq = ASN1Sequence();
       final nonceExt = ASN1Sequence();
       nonceExt.add(ASN1ObjectIdentifier.fromComponentString('1.3.6.1.5.5.7.48.1.2'));
       nonceExt.add(ASN1OctetString(nonce));
       extSeq.add(nonceExt);
       
       final extWrapper = ASN1Sequence(tag: 0xA1);
       extWrapper.add(extSeq);
       responseData.add(extWrapper);
    }

    final signature = signData(responseData.encodedBytes, responderKeyPair.privateKey as RSAPrivateKey);
    
    final basicResp = ASN1Sequence();
    basicResp.add(responseData);
    basicResp.add(createAlgorithmIdentifier(sha256WithRSAEncryption));
    basicResp.add(ASN1BitString(signature));
    
    final ocspResp = ASN1Sequence();
    final successful = ASN1Integer(BigInt.zero, tag: 0x0A); // successful(0)
    ocspResp.add(successful);
    
    final responseBytes = ASN1Sequence(tag: 0xA0);
    responseBytes.add(ASN1ObjectIdentifier.fromComponentString('1.3.6.1.5.5.7.48.1.1'));
    responseBytes.add(ASN1OctetString(basicResp.encodedBytes));
    
    ocspResp.add(responseBytes);
    
    return ocspResp.encodedBytes;
  }

  static Uint8List signData(Uint8List data, RSAPrivateKey key) {
    final signer = Signer('SHA-256/RSA');
    signer.init(true, PrivateKeyParameter<RSAPrivateKey>(key)); 
    final sig = signer.generateSignature(data);
    return (sig as RSASignature).bytes;
  }
}

class PkiOtherName {
  const PkiOtherName(this.oid, this.value);

  final String oid;
  final String value;
}

/// Represents a revoked certificate entry for CRL generation.
class RevokedCertificate {
  final BigInt serialNumber;
  final DateTime revocationDate;
  final int? reasonCode;

  const RevokedCertificate({
    required this.serialNumber,
    required this.revocationDate,
    this.reasonCode,
  });
}

/// Helper for OCSP status.
class OcspEntryStatus {
  final int status; // 0=good, 1=revoked, 2=unknown
  final DateTime? revocationTime;
  final int? revocationReason;
  final DateTime? thisUpdate;
  final DateTime? nextUpdate;

  const OcspEntryStatus({
    this.status = 0,
    this.revocationTime,
    this.revocationReason,
    this.thisUpdate,
    this.nextUpdate,
  });
}

