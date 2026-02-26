// ignore_for_file: deprecated_member_use_from_same_package

import 'dart:convert';
import 'dart:typed_data';

import '../color.dart';
import '../document.dart';
import '../graphics.dart';
import '../parsing/pdf_document_parser.dart';
import '../rect.dart';
import 'pdf_cms_signer.dart';
import 'pdf_external_signer.dart';
import 'pdf_external_signing.dart';
import 'pdf_signature_appearance.dart';
import 'pdf_signature_config.dart';
import 'pem_utils.dart';

/// Signature field definition for an existing PDF.
class PdfSignatureField {
  /// Creates a field using PDF-space bounds.
  PdfSignatureField.bounds({
    required this.pageNumber,
    required this.fieldName,
    required this.bounds,
    this.drawAppearance,
  })  : left = null,
        top = null,
        width = null,
        height = null;

  /// Creates a field using top-left coordinates.
  PdfSignatureField.pageTopLeft({
    required this.pageNumber,
    required this.fieldName,
    required this.left,
    required this.top,
    required this.width,
    required this.height,
    this.drawAppearance,
  }) : bounds = null;

  /// Page number (1-based).
  final int pageNumber;
  /// Field name.
  final String fieldName;
  /// Bounds in PDF user space.
  final PdfRect? bounds;
  /// Left coordinate (top-left mode).
  final double? left;
  /// Top coordinate (top-left mode).
  final double? top;
  /// Width (top-left mode).
  final double? width;
  /// Height (top-left mode).
  final double? height;
  /// Custom appearance drawer.
  final void Function(PdfGraphics graphics, PdfRect bounds)? drawAppearance;

  /// Whether the field uses top-left coordinates.
  bool get isTopLeft => bounds == null;
}

/// High-level API for incremental signing of existing PDFs.
class PdfSignatureService {
  /// Creates a signature service.
  PdfSignatureService({PdfCmsSigner? cmsSigner})
      : _cmsSigner = cmsSigner ?? PdfCmsSigner();

  final PdfCmsSigner _cmsSigner;

  /// Signs a PDF byte array and returns the updated bytes.
  ///
  /// If [signature.isDocTimeStamp] is true, [timestampProvider] is required.
  Future<Uint8List> signBytes({
    required Uint8List inputBytes,
    required PdfExternalSigner externalSigner,
    required PdfSignatureField field,
    PdfSignatureConfig? signature,
    PdfSignatureAppearance? appearance,
    Future<Uint8List> Function(Uint8List signature)? timestampProvider,
    int contentsReserveSize = 16384,
    int byteRangeDigits = 10,
  }) async {
    final isDocTimeStamp = signature?.isDocTimeStamp == true;
    final appearanceDrawer = field.drawAppearance ??
        (appearance == null
            ? null
            : (graphics, bounds) =>
                _drawSignatureAppearance(graphics, bounds, appearance));

    final prepared = await _prepare(
      inputBytes: inputBytes,
      field: field,
      signature: signature,
      publicCertificates: externalSigner.certificates,
      drawAppearance: appearanceDrawer,
      contentsReserveSize: contentsReserveSize,
      byteRangeDigits: byteRangeDigits,
    );

    if (isDocTimeStamp) {
      if (timestampProvider == null) {
        throw StateError('Timestamp provider obrigatório para DocTimeStamp.');
      }
      final byteRangeData =
          _extractByteRangeData(prepared.preparedPdfBytes, prepared.byteRange);
      final token = await timestampProvider(byteRangeData);
      if (token.isEmpty) {
        throw StateError('Timestamp retornou vazio.');
      }
      return PdfExternalSigning.embedSignature(
        preparedPdfBytes: prepared.preparedPdfBytes,
        pkcs7Bytes: token,
      );
    }

    final digest = base64.decode(prepared.hashBase64);
    final certs = externalSigner.certificates;
    if (certs.isEmpty) {
      throw StateError('Nenhum certificado fornecido pelo signer externo.');
    }

    final cms = await _cmsSigner.buildDetachedCms(
      contentDigest: digest,
      signerCertDer: certs.first,
      extraCertsDer: certs.length > 1
          ? certs.sublist(1).map(Uint8List.fromList).toList(growable: false)
          : const <Uint8List>[],
      signingTime: signature?.signingTime,
      digestAlgorithmOid: externalSigner.digestAlgorithmOid,
      signatureAlgorithmOid: externalSigner.signatureAlgorithmOid,
      signCallback: (signedAttrsDer, signedAttrsDigest) async {
        return externalSigner.signSignedAttributes(
          signedAttrsDer,
          signedAttrsDigest,
        );
      },
      timestampProvider: timestampProvider,
    );

    return PdfExternalSigning.embedSignature(
      preparedPdfBytes: prepared.preparedPdfBytes,
      pkcs7Bytes: cms,
    );
  }

  Future<PdfExternalSigningPrepared> _prepare({
    required Uint8List inputBytes,
    required PdfSignatureField field,
    required List<Uint8List> publicCertificates,
    PdfSignatureConfig? signature,
    void Function(PdfGraphics graphics, PdfRect bounds)? drawAppearance,
    required int contentsReserveSize,
    required int byteRangeDigits,
  }) async {
    final certs =
        publicCertificates.map<List<int>>((c) => c).toList(growable: false);

    if (field.isTopLeft) {
      final parser = PdfDocumentParser(inputBytes);
      final document = PdfDocument.load(parser);
      final pageIndex = field.pageNumber - 1;
      if (pageIndex < 0 || pageIndex >= document.pdfPageList.pages.length) {
        throw RangeError.index(
            pageIndex, document.pdfPageList.pages, 'pageNumber');
      }
      final page = document.pdfPageList.pages[pageIndex];
      final pageHeight = page.pageFormat.height;
      final bounds = PdfRect(
        field.left!,
        pageHeight - field.top! - field.height!,
        field.width!,
        field.height!,
      );

      return PdfExternalSigning.preparePdf(
        inputBytes: inputBytes,
        pageNumber: field.pageNumber,
        bounds: bounds,
        fieldName: field.fieldName,
        signature: signature,
        publicCertificates: certs,
        drawAppearance: drawAppearance,
        contentsReserveSize: contentsReserveSize,
        byteRangeDigits: byteRangeDigits,
      );
    }

    return PdfExternalSigning.preparePdf(
      inputBytes: inputBytes,
      pageNumber: field.pageNumber,
      bounds: field.bounds!,
      fieldName: field.fieldName,
      signature: signature,
      publicCertificates: certs,
      drawAppearance: drawAppearance,
      contentsReserveSize: contentsReserveSize,
      byteRangeDigits: byteRangeDigits,
    );
  }
}

Uint8List _extractByteRangeData(Uint8List bytes, List<int> byteRange) {
  if (byteRange.length != 4) {
    throw ArgumentError('ByteRange inválido.');
  }
  final start1 = byteRange[0];
  final len1 = byteRange[1];
  final start2 = byteRange[2];
  final len2 = byteRange[3];
  final out = Uint8List(len1 + len2);
  out.setRange(0, len1, bytes.sublist(start1, start1 + len1));
  out.setRange(len1, len1 + len2, bytes.sublist(start2, start2 + len2));
  return out;
}

/// PEM signer adapter for internal signing workflows.
class PdfPemSigner extends PdfExternalSigner {
  /// Creates a PEM signer with private key and certificate chain.
  PdfPemSigner({
    required this.privateKeyPem,
    required this.certificatePem,
    this.chainPem = const <String>[],
  });

  /// PEM-encoded private key.
  final String privateKeyPem;
  /// PEM-encoded signing certificate.
  final String certificatePem;
  /// PEM-encoded extra chain certificates.
  final List<String> chainPem;

  List<Uint8List>? _cached;

  @override
  /// Returns the signer certificate chain as DER bytes.
  List<Uint8List> get certificates {
    if (_cached != null) return _cached!;
    final certs = <Uint8List>[
      PdfPemUtils.decodeFirstPem(certificatePem, 'CERTIFICATE'),
      for (final pem in chainPem)
        ...PdfPemUtils.decodePemBlocks(pem, 'CERTIFICATE'),
    ];
    _cached = certs;
    return certs;
  }

  @override
  /// Signs a digest using RSA/SHA-256.
  Future<Uint8List> signDigest(Uint8List digest) async {
    return PdfCmsSigner.signDigestRsaSha256(digest, privateKeyPem);
  }
}

void _drawSignatureAppearance(
  PdfGraphics graphics,
  PdfRect bounds,
  PdfSignatureAppearance appearance,
) {
  final font = graphics.defaultFont;
  if (font == null) return;

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
  final available = bounds.height - (padding * 2);
  final baseSize = available / lines.length;
  final fontSize = baseSize.clamp(6.0, 12.0);

  graphics.setFillColor(const PdfColor(0, 0, 0));
  var y = bounds.height - padding - fontSize;
  for (final line in lines) {
    if (y < padding) break;
    graphics.drawString(font, fontSize, line, padding, y);
    y -= fontSize + 2;
  }
}
