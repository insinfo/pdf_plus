import 'dart:typed_data';

import '../color.dart';
import '../document.dart';
import '../obj/font.dart';
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
    final signAnnot = PdfAnnotSign(rect: bounds, fieldName: fieldName);
    if (appearance != null) {
      _applySignatureAppearance(document, signAnnot, appearance);
    }
    PdfAnnot(page, signAnnot);

    return document.save();
  }
}

void _applySignatureAppearance(
  PdfDocument document,
  PdfAnnotSign annot,
  PdfSignatureAppearance appearance,
) {
  final g = annot.appearance(document, PdfAnnotAppearance.normal);
  final font = g.defaultFont ?? PdfFont.helvetica(document);

  final lines = <String>[];
  if (appearance.title != null && appearance.title!.trim().isNotEmpty) {
    lines.add(appearance.title!.trim());
  }
  if (appearance.reason != null && appearance.reason!.trim().isNotEmpty) {
    lines.add('Motivo: ${appearance.reason!.trim()}');
  }
  if (appearance.location != null && appearance.location!.trim().isNotEmpty) {
    lines.add('Local: ${appearance.location!.trim()}');
  }
  if (appearance.contactInfo != null &&
      appearance.contactInfo!.trim().isNotEmpty) {
    lines.add('Contato: ${appearance.contactInfo!.trim()}');
  }
  if (appearance.signedAt != null) {
    final signedAt = appearance.signedAt!.toLocal().toIso8601String();
    lines.add("Data: ${signedAt.replaceFirst('T', ' ')}");
  }

  if (lines.isEmpty) {
    lines.add('Assinado digitalmente');
  }

  const padding = 4.0;
  final height = annot.rect.height;
  final available = height - (padding * 2);
  final baseSize = available / lines.length;
  final fontSize = baseSize.clamp(6.0, 12.0);

  g.setFillColor(const PdfColor(0, 0, 0));

  var y = height - padding - fontSize;
  for (final line in lines) {
    if (y < padding) break;
    g.drawString(font, fontSize, line, padding, y);
    y -= fontSize + 2;
  }
}
