import 'dart:typed_data';

import '../document.dart';
import '../obj/annotation.dart';
import '../obj/signature.dart';
import '../rect.dart';
import 'pdf_external_signer.dart';
import 'pdf_pades_signer.dart';
import 'pdf_signature_appearance.dart';

/// Fachada para assinatura de PDFs.
class PdfSigner {
  const PdfSigner();

  /// Assina um [PdfDocument] já construído e retorna os bytes assinados.
  Future<Uint8List> signDocument({
    required PdfDocument document,
    required PdfExternalSigner signer,
    required PdfRect bounds,
    int pageIndex = 0,
    String fieldName = 'Signature1',
    PdfSignatureAppearance? appearance,
    int contentsReserveSize = 16384,
  }) async {
    if (document.pdfPageList.pages.isEmpty) {
      throw StateError('O documento não possui páginas para assinar.');
    }
    if (pageIndex < 0 || pageIndex >= document.pdfPageList.pages.length) {
      throw RangeError.index(pageIndex, document.pdfPageList.pages, 'pageIndex');
    }

    final pades = PdfPadesSigner(
      externalSigner: signer,
      contentsReserveSize: contentsReserveSize,
      signingTime: appearance?.signedAt,
      reason: appearance?.reason,
      location: appearance?.location,
      contactInfo: appearance?.contactInfo,
      name: appearance?.title,
    );

    document.sign = PdfSignature(
      document,
      value: pades,
      flags: {PdfSigFlags.signaturesExist, PdfSigFlags.appendOnly},
      cert: signer.certificates,
    );

    final page = document.pdfPageList.pages[pageIndex];
    PdfAnnot(page, PdfAnnotSign(rect: bounds, fieldName: fieldName));

    return document.save();
  }
}
