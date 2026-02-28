import 'dart:typed_data';

import '../format/dict.dart';
import '../format/name.dart';
import '../format/string.dart';
import '../format/stream.dart';
import '../obj/object.dart';
import '../obj/signature.dart';
import 'pdf_cms_signer.dart';
import 'pdf_external_signer.dart';
import 'pdf_signature_internal_utils.dart';
import 'package:pdf_plus/src/pdf/pdf_names.dart';

/// PAdES implementation based on [PdfSignatureBase].
class PdfPadesSigner extends PdfSignatureBase {
  /// Creates a PAdES signer using an external signer and CMS builder.
  PdfPadesSigner({
    required this.externalSigner,
    PdfCmsSigner? cmsSigner,
    this.contentsReserveSize = 16384,
    this.byteRangeDigits = 10,
    this.signingTime,
    this.reason,
    this.location,
    this.contactInfo,
    this.name,
  }) : cmsSigner = cmsSigner ?? PdfCmsSigner();

  /// External signer used to sign CMS attributes.
  final PdfExternalSigner externalSigner;

  /// CMS builder used to build detached signatures.
  final PdfCmsSigner cmsSigner;

  /// Reserved size for /Contents.
  final int contentsReserveSize;

  /// Fixed width for ByteRange numbers.
  final int byteRangeDigits;

  /// Signing time to embed.
  final DateTime? signingTime;

  /// Reason for signing.
  final String? reason;

  /// Location of signing.
  final String? location;

  /// Contact information.
  final String? contactInfo;

  /// Signer name.
  final String? name;

  @override

  /// Populates the signature dictionary before hashing.
  void preSign(PdfObject object, PdfDict params) {
    params[PdfNameTokens.filter] = const PdfName(PdfNameTokens.adobePpkLite);
    params[PdfNameTokens.subFilter] =
        const PdfName(PdfNameTokens.adbePkcs7Detached);
    params[PdfNameTokens.byteRange] =
        PdfByteRangePlaceholder(digits: byteRangeDigits);
    params[PdfNameTokens.contents] = PdfString(
      Uint8List(contentsReserveSize),
      format: PdfStringFormat.binary,
      encrypted: false,
    );

    final when = (signingTime ?? DateTime.now()).toUtc();
    params[PdfNameTokens.m] = PdfString.fromDate(when, encrypted: false);
    if (reason != null) {
      params[PdfNameTokens.reason] = PdfString.fromString(reason!);
    }
    if (location != null) {
      params[PdfNameTokens.location] = PdfString.fromString(location!);
    }
    if (contactInfo != null) {
      params[PdfNameTokens.contactinfo] = PdfString.fromString(contactInfo!);
    }
    if (name != null) {
      params[PdfNameTokens.name] = PdfString.fromString(name!);
    }
  }

  @override

  /// Computes the ByteRange digest, builds CMS, and embeds /Contents.
  Future<void> sign(
    PdfObject object,
    PdfStream os,
    PdfDict params,
    int? offsetStart,
    int? offsetEnd,
  ) async {
    if (offsetStart == null || offsetEnd == null) {
      throw StateError('Offsets de assinatura inválidos.');
    }

    final bytes = os.output();
    final contentsRange =
        findContentsRangeInWindow(bytes, offsetStart, offsetEnd);
    final byteRange = <int>[
      0,
      contentsRange.lt,
      contentsRange.gt + 1,
      bytes.length - (contentsRange.gt + 1),
    ];

    writeByteRangeInWindow(bytes, offsetStart, offsetEnd, byteRange);

    final contentDigest = computeByteRangeDigest(bytes, byteRange);

    final signerCerts = externalSigner.certificates;
    if (signerCerts.isEmpty) {
      throw StateError('Nenhum certificado fornecido pelo signer externo.');
    }

    final cms = await cmsSigner.buildDetachedCms(
      contentDigest: contentDigest,
      signerCertDer: signerCerts.first,
      extraCertsDer: signerCerts.skip(1).toList(growable: false),
      signingTime: signingTime,
      signCallback: (signedAttrsDer, signedAttrsDigest) async {
        return externalSigner.signDigest(signedAttrsDigest);
      },
    );

    embedSignatureHex(bytes, contentsRange.start, contentsRange.end, cms);

    os.setBytes(0, bytes);
  }
}
