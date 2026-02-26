import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/src/pki/x509_certificate.dart';
import 'package:test/test.dart';

void main() {
  group('X509Certificate', () {
    test('fromDer extrai campos básicos e toPem roundtrip', () {
      final file = File('test/assets/truststore/iti/ACFinaldoGovernoFederaldoBrasilv1.crt');
      if (!file.existsSync()) {
        return;
      }

      final der = file.readAsBytesSync();
      final cert = X509Certificate.fromDer(der);

      expect(cert.version, greaterThanOrEqualTo(1));
      expect(cert.serialNumber, isNot(BigInt.zero));
      expect(cert.signatureAlgorithmOid, isNotEmpty);
      expect(cert.tbsSignatureAlgorithmOid, isNotEmpty);
      expect(cert.subject.attributes, isNotEmpty);
      expect(cert.issuer.attributes, isNotEmpty);
      expect(cert.subjectPublicKeyInfoDer, isNotEmpty);
      expect(cert.signatureValue, isNotEmpty);

      final pem = cert.toPem();
      expect(pem, contains('-----BEGIN CERTIFICATE-----'));
      final reparsed = X509Certificate.fromPem(pem);
      expect(reparsed.serialNumber, cert.serialNumber);
      expect(reparsed.subject.toString(), cert.subject.toString());
      expect(reparsed.issuer.toString(), cert.issuer.toString());
    });

    test('isValidAt respeita janela de validade', () {
      final file = File('test/assets/truststore/iti/ACFinaldoGovernoFederaldoBrasilv1.crt');
      if (!file.existsSync()) {
        return;
      }
      final cert = X509Certificate.fromDer(file.readAsBytesSync());

      final middle = cert.notBefore.add(
        cert.notAfter.difference(cert.notBefore) ~/ 2,
      );
      expect(cert.isValidAt(middle), isTrue);
      expect(cert.isValidAt(cert.notBefore.subtract(const Duration(seconds: 1))), isFalse);
      expect(cert.isValidAt(cert.notAfter.add(const Duration(seconds: 1))), isFalse);
    });

    test('fromDer falha com DER inválido', () {
      expect(
        () => X509Certificate.fromDer(Uint8List.fromList(const <int>[1, 2, 3])),
        throwsA(isA<Object>()),
      );
    });
  });
}
