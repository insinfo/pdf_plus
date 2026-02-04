import 'dart:typed_data';

import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import 'parser_fields.dart';

/// Fast checks without fully parsing the document structure.
class PdfQuickInfo {
  PdfQuickInfo._({
    required this.pdfVersion,
    required this.hasSignatures,
    required this.docMdpPermissionP,
  });

  factory PdfQuickInfo.fromBytes(Uint8List bytes) {
    final version = PdfParserFields.readPdfVersion(bytes);
    final hasSignatures = PdfParserFields.findByteRangeToken(bytes) != -1;
    final permissionP = PdfParserFields.extractDocMdpPermissionFromBytes(bytes);
    return PdfQuickInfo._(
      pdfVersion: version,
      hasSignatures: hasSignatures,
      docMdpPermissionP: permissionP,
    );
  }

  final double pdfVersion;
  final bool hasSignatures;
  final int? docMdpPermissionP;

  bool get isPdf15OrAbove => pdfVersion >= 1.5;
}

class PdfIndirectRef {
  const PdfIndirectRef(this.obj, this.gen);

  final int obj;
  final int gen;

  @override
  String toString() => '$obj $gen R';
}

class PdfPageMediaBoxInfo {
  const PdfPageMediaBoxInfo({
    required this.pageIndex,
    required this.pageRef,
    required this.box,
  });

  final int pageIndex;
  final PdfIndirectRef pageRef;
  final List<double> box;
}

class PdfImageInfo {
  const PdfImageInfo({
    required this.pageIndex,
    required this.pageRef,
    required this.imageRef,
    required this.width,
    required this.height,
    required this.bitsPerComponent,
    required this.colorSpace,
    required this.filter,
  });

  final int pageIndex;
  final PdfIndirectRef pageRef;
  final PdfIndirectRef imageRef;
  final int? width;
  final int? height;
  final int? bitsPerComponent;
  final String? colorSpace;
  final String? filter;
}

class PdfDocumentInfo {
  const PdfDocumentInfo({
    required this.version,
    this.infoRef,
    this.infoDict,
    required this.pageCount,
    required this.mediaBoxes,
    required this.images,
  });

  final String version;
  final PdfIndirectRef? infoRef;
  final Map<String, String>? infoDict;
  final int pageCount;
  final List<PdfPageMediaBoxInfo> mediaBoxes;
  final List<PdfImageInfo> images;
}

class PdfSignatureFieldInfo {
  const PdfSignatureFieldInfo({
    required this.fieldName,
    this.reason,
    this.location,
    this.name,
    this.signingTimeRaw,
    this.filter,
    this.subFilter,
    this.byteRange,
    this.pageRef,
    this.pageIndex,
    this.rect,
    this.signatureDictionaryPresent,
  });

  final String? fieldName;
  final String? reason;
  final String? location;
  final String? name;
  final String? signingTimeRaw;
  final String? filter;
  final String? subFilter;
  final List<int>? byteRange;
  final PdfIndirectRef? pageRef;
  final int? pageIndex;
  final List<double>? rect;
  final bool? signatureDictionaryPresent;
}

class PdfSignatureFieldObjectInfo {
  const PdfSignatureFieldObjectInfo({
    required this.info,
    this.fieldRef,
    required this.fieldDict,
    this.fieldIndex,
    this.isDirect = false,
    this.signatureRef,
    this.signatureDict,
  });

  final PdfSignatureFieldInfo info;
  final PdfIndirectRef? fieldRef;
  final PdfDict<PdfDataType> fieldDict;
  final int? fieldIndex;
  final bool isDirect;
  final PdfIndirectRef? signatureRef;
  final PdfDict<PdfDataType>? signatureDict;
}

class PdfSignatureFieldEditContext {
  const PdfSignatureFieldEditContext({
    required this.fields,
    this.acroFormRef,
    this.acroFormDict,
    this.fieldsRef,
    this.fieldsArray,
  });

  final List<PdfSignatureFieldObjectInfo> fields;
  final PdfIndirectRef? acroFormRef;
  final PdfDict<PdfDataType>? acroFormDict;
  final PdfIndirectRef? fieldsRef;
  final PdfArray? fieldsArray;
}
