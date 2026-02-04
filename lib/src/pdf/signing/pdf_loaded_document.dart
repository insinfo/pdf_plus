//C:\MyDartProjects\pdf_plus\lib\src\pdf\signing\pdf_loaded_document.dart
import 'dart:typed_data';

import '../document.dart';
import '../graphics.dart';
import '../obj/page.dart';
import '../point.dart';
import '../rect.dart';
import '../../pki/pkcs12.dart';
import '../../pki/x509_certificate.dart';
import '../../../widgets.dart' as pw;
import 'pdf_external_signer.dart';
import 'pdf_signature_appearance.dart';
import 'pdf_signature_config.dart';
import 'pdf_signature_service.dart';
import 'pdf_timestamp_client.dart';

enum PdfCoordinateSystem {
  pdf,
  topLeft,
}

class PdfSignatureBounds {
  PdfSignatureBounds.pdf(this.rect)
      : coordinateSystem = PdfCoordinateSystem.pdf,
        topLeft = null;

  PdfSignatureBounds.topLeft({
    required double left,
    required double top,
    required double width,
    required double height,
  })  : coordinateSystem = PdfCoordinateSystem.topLeft,
        rect = null,
        topLeft = _TopLeftRect(left, top, width, height);

  final PdfCoordinateSystem coordinateSystem;
  final PdfRect? rect;
  final _TopLeftRect? topLeft;

  PdfRect toPdfRect(PdfPage page) {
    if (coordinateSystem == PdfCoordinateSystem.pdf && rect != null) {
      return rect!;
    }
    final tl = topLeft;
    if (tl == null) {
      throw StateError('Bounds top-left nao informados.');
    }
    final pageHeight = page.pageFormat.height;
    final bottom = pageHeight - tl.top - tl.height;
    return PdfRect(tl.left, bottom, tl.width, tl.height);
  }
}

class _TopLeftRect {
  _TopLeftRect(this.left, this.top, this.width, this.height);
  final double left;
  final double top;
  final double width;
  final double height;
}

class PdfSignatureRequest {
  PdfSignatureRequest({
    required this.pageNumber,
    required this.signer,
    required this.bounds,
    this.fieldName = 'Signature1',
    this.reason,
    this.location,
    this.contactInfo,
    this.name,
    this.signingTime,
    this.appearance,
    this.appearanceWidget,
    this.drawAppearance,
    this.docMdpPermissionP,
    this.timestampProvider,
    this.contentsReserveSize = 16384,
    this.byteRangeDigits = 10,
  });

  final int pageNumber;
  final PdfSignatureSigner signer;
  final PdfSignatureBounds bounds;
  final String fieldName;
  final String? reason;
  final String? location;
  final String? contactInfo;
  final String? name;
  final DateTime? signingTime;
  final PdfSignatureAppearance? appearance;
  final pw.Widget? appearanceWidget;
  final void Function(
          PdfGraphics graphics, PdfRect bounds, PdfDocument document)?
      drawAppearance;
  final int? docMdpPermissionP;
  final PdfTimestampProvider? timestampProvider;
  final int contentsReserveSize;
  final int byteRangeDigits;
}

class PdfSignatureSigner {
  PdfSignatureSigner._(this._externalSigner);

  factory PdfSignatureSigner.external(PdfExternalSigner signer) {
    return PdfSignatureSigner._(signer);
  }

  factory PdfSignatureSigner.raw({
    required String privateKeyPem,
    required String certificate,
    List<String> chain = const <String>[],
  }) {
    final signer = PdfPemSigner(
      privateKeyPem: privateKeyPem,
      certificatePem: certificate,
      chainPem: chain,
    );
    return PdfSignatureSigner._(signer);
  }

  factory PdfSignatureSigner.pem({
    required String privateKeyPem,
    required X509Certificate certificate,
    List<X509Certificate> chain = const <X509Certificate>[],
  }) {
    final signer = PdfPemSigner(
      privateKeyPem: privateKeyPem,
      certificatePem: certificate.toPem(),
      chainPem: chain.map((c) => c.toPem()).toList(growable: false),
    );
    return PdfSignatureSigner._(signer);
  }

  static Future<PdfSignatureSigner> fromPkcs12Bytes({
    required Uint8List pkcs12Bytes,
    required String password,
    Pkcs12Decoder? decoder,
  }) async {
    final bundle = await decodePkcs12(
      pkcs12Bytes,
      password: password,
      decoder: decoder,
    );
    final cert = X509Certificate.fromPem(bundle.certificatePem);
    final chain = bundle.chainPem
        .map<X509Certificate>(X509Certificate.fromPem)
        .toList(growable: false);
    return PdfSignatureSigner.pem(
      privateKeyPem: bundle.privateKeyPem,
      certificate: cert,
      chain: chain,
    );
  }

  final PdfExternalSigner _externalSigner;

  PdfExternalSigner get externalSigner => _externalSigner;
}

class PdfLoadedDocument {
  PdfLoadedDocument._(this._document, this._bytes);

  factory PdfLoadedDocument.fromBytes(Uint8List bytes) {
    final document = PdfDocument.parseFromBytes(bytes);
    return PdfLoadedDocument._(document, Uint8List.fromList(bytes));
  }

  PdfDocument _document;
  Uint8List _bytes;
  bool _disposed = false;

  List<PdfPage> get pages => _document.pdfPageList.pages;

  Future<PdfSignatureRequest> addSignature(PdfSignatureRequest request) async {
    _ensureNotDisposed();
    _validatePage(request.pageNumber);

    final page = pages[request.pageNumber - 1];
    final bounds = request.bounds.toPdfRect(page);

    final field = PdfSignatureField.bounds(
      pageNumber: request.pageNumber,
      fieldName: request.fieldName,
      bounds: bounds,
      drawAppearance: _resolveAppearanceDrawer(
        request: request,
        page: page,
      ),
    );

    final signature = PdfSignatureConfig(
      name: request.name,
      reason: request.reason,
      location: request.location,
      contactInfo: request.contactInfo,
      signingTime: request.signingTime,
    );
    if (request.docMdpPermissionP != null) {
      signature.docMdpPermissionP = request.docMdpPermissionP;
    }

    final service = PdfSignatureService();
    _bytes = await service.signBytes(
      inputBytes: _bytes,
      externalSigner: request.signer.externalSigner,
      field: field,
      signature: signature,
      appearance: request.appearance,
      timestampProvider: request.timestampProvider,
      contentsReserveSize: request.contentsReserveSize,
      byteRangeDigits: request.byteRangeDigits,
    );

    _document = PdfDocument.parseFromBytes(_bytes);
    return request;
  }

  Future<void> addSignatureForPage({
    required PdfPage page,
    required PdfSignatureSigner signer,
    required PdfSignatureBounds bounds,
    String fieldName = 'Signature1',
    String? reason,
    String? location,
    String? contactInfo,
    String? name,
    DateTime? signingTime,
    PdfSignatureAppearance? appearance,
    pw.Widget? appearanceWidget,
    void Function(PdfGraphics graphics, PdfRect bounds, PdfDocument document)?
        drawAppearance,
    int? docMdpPermissionP,
    PdfTimestampProvider? timestampProvider,
    int contentsReserveSize = 16384,
    int byteRangeDigits = 10,
  }) async {
    _ensureNotDisposed();
    final pageIndex = pages.indexOf(page);
    if (pageIndex == -1) {
      throw ArgumentError('A pagina informada nao pertence ao documento.');
    }
    await addSignature(
      PdfSignatureRequest(
        pageNumber: pageIndex + 1,
        signer: signer,
        bounds: bounds,
        fieldName: fieldName,
        reason: reason,
        location: location,
        contactInfo: contactInfo,
        name: name,
        signingTime: signingTime,
        appearance: appearance,
        appearanceWidget: appearanceWidget,
        drawAppearance: drawAppearance,
        docMdpPermissionP: docMdpPermissionP,
        timestampProvider: timestampProvider,
        contentsReserveSize: contentsReserveSize,
        byteRangeDigits: byteRangeDigits,
      ),
    );
  }

  Future<Uint8List> save() async {
    _ensureNotDisposed();
    return Uint8List.fromList(_bytes);
  }

  void dispose() {
    _disposed = true;
  }

  void _ensureNotDisposed() {
    if (_disposed) {
      throw StateError('Documento ja foi descartado.');
    }
  }

  void _validatePage(int pageNumber) {
    if (pageNumber < 1 || pageNumber > pages.length) {
      throw RangeError.index(pageNumber, pages, 'pageNumber');
    }
  }

  void Function(PdfGraphics graphics, PdfRect bounds)?
      _resolveAppearanceDrawer({
    required PdfSignatureRequest request,
    required PdfPage page,
  }) {
    if (request.appearanceWidget != null) {
      return (graphics, rect) {
        final context = pw.Context(
          document: _document,
          page: page,
          canvas: graphics,
        ).inheritFromAll(<pw.Inherited>[pw.ThemeData.base()]);

        pw.Widget.draw(
          request.appearanceWidget!,
          page: page,
          canvas: graphics,
          constraints: pw.BoxConstraints.tightFor(
            width: rect.width,
            height: rect.height,
          ),
          offset: PdfPoint.zero,
          context: context,
        );
      };
    }

    if (request.drawAppearance != null) {
      return (graphics, rect) =>
          request.drawAppearance!(graphics, rect, _document);
    }

    return null;
  }
}
