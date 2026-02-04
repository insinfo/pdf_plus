import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart' as core;
import 'package:pdf_plus/pki.dart';
import 'package:pdf_plus/signing.dart' as pdf;
import 'package:test/test.dart';

void main() {
  test('DocMDP is set on first signature via PdfLoadedDocument', () async {
    final rootKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
    final interKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);
    final userKeyPair = PkiUtils.generateRsaKeyPair(bitStrength: 2048);

    final rootCert = PkiBuilder.createRootCertificate(
      keyPair: rootKeyPair,
      dn: 'CN=Test Root CA',
    );
    final interCert = PkiBuilder.createIntermediateCertificate(
      keyPair: interKeyPair,
      issuerKeyPair: rootKeyPair,
      subjectDn: 'CN=Test Intermediate CA',
      issuerDn: 'CN=Test Root CA',
      serialNumber: 2,
    );
    final userCert = PkiBuilder.createUserCertificate(
      keyPair: userKeyPair,
      issuerKeyPair: interKeyPair,
      subjectDn: 'CN=Test User',
      issuerDn: 'CN=Test Intermediate CA',
      serialNumber: 3,
    );

    final userKeyPem = PkiPemUtils.rsaPrivateKeyToPem(
      userKeyPair.privateKey as RSAPrivateKey,
    );

    final signer = pdf.PdfSignatureSigner.pem(
      privateKeyPem: userKeyPem,
      certificate: X509Certificate.fromPem(userCert.toPem()),
      chain: [
        X509Certificate.fromPem(interCert.toPem()),
        X509Certificate.fromPem(rootCert.toPem()),
      ],
    );

    final core.PdfDocument doc = core.PdfDocument();
    final page = core.PdfPage(doc);
    final g = page.getGraphics();
    g.drawString(core.PdfFont.helvetica(doc), 12, 'DocMDP test', 50, 750);
    final Uint8List unsignedPdf = Uint8List.fromList(await doc.save());

    final loaded = pdf.PdfLoadedDocument.fromBytes(unsignedPdf);
    await loaded.addSignature(
      pdf.PdfSignatureRequest(
        pageNumber: 1,
        signer: signer,
        fieldName: 'Sig1',
        bounds: pdf.PdfSignatureBounds.topLeft(
          left: 100,
          top: 100,
          width: 200,
          height: 50,
        ),
        reason: 'DocMDP test',
        docMdpPermissionP: 2,
      ),
    );

    await loaded.addSignature(
      pdf.PdfSignatureRequest(
        pageNumber: 1,
        signer: signer,
        fieldName: 'Sig2',
        bounds: pdf.PdfSignatureBounds.topLeft(
          left: 100,
          top: 170,
          width: 200,
          height: 50,
        ),
        reason: 'Second signature',
      ),
    );

    final signedBytes = await loaded.save();
    final report = await pdf.PdfSignatureValidator().validateAllSignatures(
      signedBytes,
      trustedRootsPem: [rootCert.toPem()],
    );

    expect(report.signatures.length, 2);
    expect(report.signatures.first.docMdp.isCertificationSignature, isTrue);
    expect(report.signatures.first.docMdp.permissionP, 2);
    expect(report.signatures.last.docMdp.isCertificationSignature, isFalse);
  });
}
