import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart' as core;
import 'package:pdf_plus/pki.dart' as pki;
import 'package:pdf_plus/signing.dart' as pdf;
import 'package:test/test.dart';

void main() {
  test(
    'Multi-signatures with pre-created fields validate chain via openssl',
    () async {
      if (!_hasOpenSsl()) return;

      final tempDir =
          await Directory.systemTemp.createTemp('pdf_plus_sig_chain_');
      try {
        final rootKey = pki.PkiUtils.generateRsaKeyPair(
          bitStrength: 2048,
          certainty: 32,
        );
        final interKey = pki.PkiUtils.generateRsaKeyPair(
          bitStrength: 2048,
          certainty: 32,
        );
        final user1Key = pki.PkiUtils.generateRsaKeyPair(
          bitStrength: 2048,
          certainty: 32,
        );
        final user2Key = pki.PkiUtils.generateRsaKeyPair(
          bitStrength: 2048,
          certainty: 32,
        );
        final user3Key = pki.PkiUtils.generateRsaKeyPair(
          bitStrength: 2048,
          certainty: 32,
        );

        final rootCert = pki.PkiBuilder.createRootCertificate(
          keyPair: rootKey,
          dn: 'CN=Test Root CA',
          validityYears: 2,
        );
        final interCert = pki.PkiBuilder.createIntermediateCertificate(
          keyPair: interKey,
          issuerKeyPair: rootKey,
          subjectDn: 'CN=Test Intermediate CA',
          issuerDn: 'CN=Test Root CA',
          serialNumber: 2,
          serialNumberBigInt: pki.PkiUtils.generateSerialNumberBigInt(),
          validityYears: 2,
        );
        final user1Cert = pki.PkiBuilder.createUserCertificate(
          keyPair: user1Key,
          issuerKeyPair: interKey,
          subjectDn: 'CN=User 1',
          issuerDn: 'CN=Test Intermediate CA',
          serialNumber: 3,
          serialNumberBigInt: pki.PkiUtils.generateSerialNumberBigInt(),
          validityDays: 365,
        );
        final user2Cert = pki.PkiBuilder.createUserCertificate(
          keyPair: user2Key,
          issuerKeyPair: interKey,
          subjectDn: 'CN=User 2',
          issuerDn: 'CN=Test Intermediate CA',
          serialNumber: 4,
          serialNumberBigInt: pki.PkiUtils.generateSerialNumberBigInt(),
          validityDays: 365,
        );
        final user3Cert = pki.PkiBuilder.createUserCertificate(
          keyPair: user3Key,
          issuerKeyPair: interKey,
          subjectDn: 'CN=User 3',
          issuerDn: 'CN=Test Intermediate CA',
          serialNumber: 5,
          serialNumberBigInt: pki.PkiUtils.generateSerialNumberBigInt(),
          validityDays: 365,
        );

        final rootPemPath = '${tempDir.path}/root.pem';
        final interPemPath = '${tempDir.path}/inter.pem';
        File(rootPemPath).writeAsStringSync(rootCert.toPem());
        File(interPemPath).writeAsStringSync(interCert.toPem());

        final core.PdfDocument doc = core.PdfDocument();
        final page = core.PdfPage(doc);
        final g = page.getGraphics();
        g.drawString(
          core.PdfFont.helvetica(doc),
          12,
          'Hello, multi-signature chain test.',
          50,
          750,
        );

        doc.addSignatureFieldTopLeft(
          pageNumber: 1,
          left: 50,
          top: 120,
          width: 240,
          height: 70,
          fieldName: 'Signature1',
        );
        doc.addSignatureFieldTopLeft(
          pageNumber: 1,
          left: 50,
          top: 210,
          width: 240,
          height: 70,
          fieldName: 'Signature2',
        );
        doc.addSignatureFieldTopLeft(
          pageNumber: 1,
          left: 50,
          top: 300,
          width: 240,
          height: 70,
          fieldName: 'Signature3',
        );

        final Uint8List baseBytes = Uint8List.fromList(await doc.save());

        final loaded = pdf.PdfLoadedDocument.fromBytes(baseBytes);
        await loaded.addSignature(
          pdf.PdfSignatureRequest(
            pageNumber: 1,
            fieldName: 'Signature1',
            signer: pdf.PdfSignatureSigner.pem(
              privateKeyPem: pki.PkiPemUtils.rsaPrivateKeyToPem(
                user1Key.privateKey as pki.RSAPrivateKey,
              ),
              certificate: user1Cert,
              chain: <pki.X509Certificate>[interCert, rootCert],
            ),
            bounds: pdf.PdfSignatureBounds.topLeft(
              left: 50,
              top: 120,
              width: 240,
              height: 70,
            ),
            name: 'User 1',
            reason: 'Signature 1',
            docMdpPermissionP: 2,
          ),
        );

        await loaded.addSignature(
          pdf.PdfSignatureRequest(
            pageNumber: 1,
            fieldName: 'Signature2',
            signer: pdf.PdfSignatureSigner.pem(
              privateKeyPem: pki.PkiPemUtils.rsaPrivateKeyToPem(
                user2Key.privateKey as pki.RSAPrivateKey,
              ),
              certificate: user2Cert,
              chain: <pki.X509Certificate>[interCert, rootCert],
            ),
            bounds: pdf.PdfSignatureBounds.topLeft(
              left: 50,
              top: 210,
              width: 240,
              height: 70,
            ),
            name: 'User 2',
            reason: 'Signature 2',
          ),
        );

        await loaded.addSignature(
          pdf.PdfSignatureRequest(
            pageNumber: 1,
            fieldName: 'Signature3',
            signer: pdf.PdfSignatureSigner.pem(
              privateKeyPem: pki.PkiPemUtils.rsaPrivateKeyToPem(
                user3Key.privateKey as pki.RSAPrivateKey,
              ),
              certificate: user3Cert,
              chain: <pki.X509Certificate>[interCert, rootCert],
            ),
            bounds: pdf.PdfSignatureBounds.topLeft(
              left: 50,
              top: 300,
              width: 240,
              height: 70,
            ),
            name: 'User 3',
            reason: 'Signature 3',
          ),
        );

        final Uint8List signedBytes = await loaded.save();
        loaded.dispose();

        final fields =
            pdf.PdfDocumentParser(signedBytes).extractSignatureFields();
        final fieldNames = fields
            .map((f) => f.fieldName ?? '')
            .where((name) => name.isNotEmpty)
            .toList();
        expect(fields.length, 3);
        expect(fieldNames.where((n) => n == 'Signature1').length, 1);
        expect(fieldNames.where((n) => n == 'Signature2').length, 1);
        expect(fieldNames.where((n) => n == 'Signature3').length, 1);

        final report = await pdf.PdfSignatureValidator()
            .validateAllSignatures(signedBytes);
        expect(report.signatures.length, 3);
        for (final sig in report.signatures) {
          expect(sig.cmsValid, isTrue);
          expect(sig.digestValid, isTrue);
          expect(sig.intact, isTrue);
        }
        expect(report.signatures.first.docMdp.permissionP, 2);

        final contents = pdf.extractAllSignatureContents(signedBytes);
        expect(contents.length, 3);

        final expectedCns = <String>['User 1', 'User 2', 'User 3'];
        for (var i = 0; i < contents.length; i++) {
          final cmsBytes = contents[i];
          expect(cmsBytes.isNotEmpty, isTrue);

          final sigPath = '${tempDir.path}/sig_$i.p7s';
          File(sigPath).writeAsBytesSync(cmsBytes);

          final certsPath = '${tempDir.path}/sig_${i}_certs.pem';
          await _runCmd('openssl', [
            'pkcs7',
            '-inform',
            'DER',
            '-print_certs',
            '-in',
            sigPath,
            '-out',
            certsPath,
          ]);

          final certsPem = File(certsPath).readAsStringSync();
          final leafPem = _pickLeafPem(certsPem, expectedCns[i]);
          final leafPath = '${tempDir.path}/sig_${i}_leaf.pem';
          File(leafPath).writeAsStringSync(leafPem);

          await _runCmd('openssl', [
            'verify',
            '-CAfile',
            rootPemPath,
            '-untrusted',
            interPemPath,
            leafPath,
          ]);
        }
      } finally {
        await tempDir.delete(recursive: true);
      }
    },
    timeout: const Timeout(Duration(minutes: 5)),
    skip: _hasOpenSsl() ? false : 'openssl not available',
  );

  test(
    'DocTimeStamp via TSA token is embedded and parseable',
    () async {
      if (!_hasOpenSsl()) return;
      if (!_tsaEnabled()) return;

      final tempDir =
          await Directory.systemTemp.createTemp('pdf_plus_tsa_doc_ts_');
      try {
        final rootKey = pki.PkiUtils.generateRsaKeyPair(
          bitStrength: 2048,
          certainty: 32,
        );
        final interKey = pki.PkiUtils.generateRsaKeyPair(
          bitStrength: 2048,
          certainty: 32,
        );
        final userKey = pki.PkiUtils.generateRsaKeyPair(
          bitStrength: 2048,
          certainty: 32,
        );

        final rootCert = pki.PkiBuilder.createRootCertificate(
          keyPair: rootKey,
          dn: 'CN=Test Root CA',
          validityYears: 2,
        );
        final interCert = pki.PkiBuilder.createIntermediateCertificate(
          keyPair: interKey,
          issuerKeyPair: rootKey,
          subjectDn: 'CN=Test Intermediate CA',
          issuerDn: 'CN=Test Root CA',
          serialNumber: 2,
          serialNumberBigInt: pki.PkiUtils.generateSerialNumberBigInt(),
          validityYears: 2,
        );
        final userCert = pki.PkiBuilder.createUserCertificate(
          keyPair: userKey,
          issuerKeyPair: interKey,
          subjectDn: 'CN=User TSA',
          issuerDn: 'CN=Test Intermediate CA',
          serialNumber: 3,
          serialNumberBigInt: pki.PkiUtils.generateSerialNumberBigInt(),
          validityDays: 365,
        );

        final core.PdfDocument doc = core.PdfDocument();
        final page = core.PdfPage(doc);
        final g = page.getGraphics();
        g.drawString(
          core.PdfFont.helvetica(doc),
          12,
          'Hello, TSA DocTimeStamp test.',
          50,
          750,
        );

        doc.addSignatureFieldTopLeft(
          pageNumber: 1,
          left: 50,
          top: 120,
          width: 240,
          height: 70,
          fieldName: 'Signature1',
        );
        doc.addSignatureFieldTopLeft(
          pageNumber: 1,
          left: 50,
          top: 210,
          width: 240,
          height: 70,
          fieldName: 'DocTimeStamp1',
        );

        final Uint8List baseBytes = Uint8List.fromList(await doc.save());

        final loaded = pdf.PdfLoadedDocument.fromBytes(baseBytes);
        await loaded.addSignature(
          pdf.PdfSignatureRequest(
            pageNumber: 1,
            fieldName: 'Signature1',
            signer: pdf.PdfSignatureSigner.pem(
              privateKeyPem: pki.PkiPemUtils.rsaPrivateKeyToPem(
                userKey.privateKey as pki.RSAPrivateKey,
              ),
              certificate: userCert,
              chain: <pki.X509Certificate>[interCert, rootCert],
            ),
            bounds: pdf.PdfSignatureBounds.topLeft(
              left: 50,
              top: 120,
              width: 240,
              height: 70,
            ),
            name: 'User TSA',
            reason: 'Signature with TSA',
          ),
        );

        final Uint8List signedBytes = await loaded.save();
        loaded.dispose();

        final tsaClient = _buildTsaClient();
        final prepared = await pdf.PdfExternalSigning.preparePdf(
          inputBytes: signedBytes,
          pageNumber: 1,
          bounds: core.PdfRect.fromLBRT(50, 400, 290, 470),
          fieldName: 'DocTimeStamp1',
          signature: pdf.PdfSignatureConfig(isDocTimeStamp: true),
          contentsReserveSize: 32768,
        );

        final range = pdf.PdfExternalSigning.extractByteRange(
          prepared.preparedPdfBytes,
        );
        final rangeData =
            _extractByteRangeData(prepared.preparedPdfBytes, range);
        final token = await tsaClient.timestampSignature(rangeData);

        final finalBytes = pdf.PdfExternalSigning.embedSignature(
          preparedPdfBytes: prepared.preparedPdfBytes,
          pkcs7Bytes: token,
        );

        final contents = pdf.extractAllSignatureContents(finalBytes);
        expect(contents.length, 2);
        final tokenPath = '${tempDir.path}/doc_ts_token.der';
        File(tokenPath).writeAsBytesSync(contents.last);

        await _runCmd('openssl', [
          'ts',
          '-reply',
          '-token_in',
          '-in',
          tokenPath,
          '-text',
        ]);

        final dataPath = '${tempDir.path}/doc_ts_data.bin';
        File(dataPath).writeAsBytesSync(rangeData);

        final certsPath = '${tempDir.path}/doc_ts_certs.pem';
        await _runCmd('openssl', [
          'pkcs7',
          '-inform',
          'DER',
          '-print_certs',
          '-in',
          tokenPath,
          '-out',
          certsPath,
        ]);

        final certsPem = File(certsPath).readAsStringSync();
        final (rootPem, untrustedPem) = _splitRootAndChain(certsPem);

        final rootPath = '${tempDir.path}/doc_ts_root.pem';
        final untrustedPath = '${tempDir.path}/doc_ts_chain.pem';
        File(rootPath).writeAsStringSync(rootPem);
        File(untrustedPath).writeAsStringSync(untrustedPem);

        await _runCmd('openssl', [
          'ts',
          '-verify',
          '-token_in',
          '-in',
          tokenPath,
          '-data',
          dataPath,
          '-CAfile',
          rootPath,
          '-untrusted',
          untrustedPath,
        ]);
      } finally {
        await tempDir.delete(recursive: true);
      }
    },
    timeout: const Timeout(Duration(minutes: 5)),
    skip: _hasOpenSsl() && _tsaEnabled()
        ? false
        : 'openssl not available or TSA disabled',
  );
}

String _pickLeafPem(String pem, String expectedCn) {
  final blocks = pdf.PdfPemUtils.decodePemBlocks(pem, 'CERTIFICATE');
  if (blocks.isEmpty) {
    throw StateError('No certificates extracted from CMS.');
  }
  for (final der in blocks) {
    final cert = pki.X509Certificate.fromDer(der);
    if (cert.subject.commonName == expectedCn) {
      return cert.toPem();
    }
  }
  throw StateError('Signer certificate $expectedCn not found.');
}

bool _hasOpenSsl() {
  try {
    final result = Process.runSync('openssl', const <String>['version']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

bool _tsaEnabled() {
  final env = Platform.environment;
  return env['PDFPLUS_DISABLE_TSA'] != '1';
}

pdf.PdfTimestampClient _buildTsaClient() {
  final url = Platform.environment['PDFPLUS_TSA_URL'];
  if (url == null || url.trim().isEmpty) {
    return pdf.PdfTimestampClient.freetsa();
  }
  return pdf.PdfTimestampClient(endpoint: Uri.parse(url));
}

Uint8List _extractByteRangeData(Uint8List bytes, List<int> range) {
  if (range.length != 4) {
    throw ArgumentError('Invalid ByteRange.');
  }
  final start1 = range[0];
  final len1 = range[1];
  final start2 = range[2];
  final len2 = range[3];
  final out = Uint8List(len1 + len2);
  out.setRange(0, len1, bytes.sublist(start1, start1 + len1));
  out.setRange(len1, len1 + len2, bytes.sublist(start2, start2 + len2));
  return out;
}

Future<void> _runCmd(String exe, List<String> args) async {
  final result = await Process.run(exe, args, runInShell: true);
  if (result.exitCode != 0) {
    throw StateError(
      "Failed to run $exe ${args.join(' ')}\n${result.stdout}\n${result.stderr}",
    );
  }
}

(String, String) _splitRootAndChain(String pem) {
  final blocks = pdf.PdfPemUtils.decodePemBlocks(pem, 'CERTIFICATE');
  if (blocks.isEmpty) {
    throw StateError('No certificates extracted from TSA token.');
  }

  final roots = <String>[];
  final rest = <String>[];

  for (final der in blocks) {
    final cert = pki.X509Certificate.fromDer(der);
    final pemBlock = cert.toPem();
    if (cert.subject.toString() == cert.issuer.toString()) {
      roots.add(pemBlock);
    } else {
      rest.add(pemBlock);
    }
  }

  if (roots.isEmpty) {
    throw StateError('No self-signed root certificate found in TSA token.');
  }

  return (roots.join('\n'), rest.join('\n'));
}
