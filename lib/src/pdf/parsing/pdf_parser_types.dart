import 'dart:typed_data';

import '../format/string.dart';
import 'pdf_document_info.dart';

class TrailerInfo {
  const TrailerInfo({
    this.size,
    this.prev,
    this.rootObj,
    this.infoObj,
    this.id,
  });

  final int? size;
  final int? prev;
  final int? rootObj;
  final int? infoObj;
  final Uint8List? id;
}

class ParsedIndirectObject {
  ParsedIndirectObject({
    required this.objId,
    required this.gen,
    required this.value,
    this.streamData,
  });

  final int objId;
  final int gen;
  final dynamic value;
  final Uint8List? streamData;
}

class PdfRefToken {
  PdfRefToken(this.obj, this.gen);

  final int obj;
  final int gen;
}

class ImageScanInfo {
  const ImageScanInfo({
    required this.imageRef,
    required this.width,
    required this.height,
    required this.bitsPerComponent,
    required this.colorSpace,
    required this.filter,
  });

  final PdfIndirectRef imageRef;
  final int? width;
  final int? height;
  final int? bitsPerComponent;
  final String? colorSpace;
  final String? filter;
}

class PdfNameToken {
  PdfNameToken(this.value);
  final String value;
}

class PdfStringToken {
  PdfStringToken(this.bytes, this.format);

  final Uint8List bytes;
  final PdfStringFormat format;
}

class PdfArrayToken {
  PdfArrayToken(this.values);

  final List<dynamic> values;
}

class PdfDictToken {
  PdfDictToken(this.values);

  final Map<String, dynamic> values;
}

class ParseResult {
  ParseResult(this.value, this.nextIndex, {this.dictEnd});

  final dynamic value;
  final int nextIndex;
  final int? dictEnd;
}

class IndirectHeader {
  IndirectHeader(this.dictStart, this.dictEnd);

  final int dictStart;
  final int dictEnd;
}

enum XrefType { free, inUse, compressed }

class XrefEntry {
  XrefEntry({required this.offset, required this.gen, required this.type});

  final int offset;
  final int gen;
  final XrefType type;
}

class XrefStreamDict {
  const XrefStreamDict({
    this.type,
    this.size,
    this.prev,
    this.rootObj,
    this.infoObj,
    this.id,
    this.filter,
    this.length,
    this.w,
    this.index,
  });

  final String? type;
  final int? size;
  final int? prev;
  final int? rootObj;
  final int? infoObj;
  final Uint8List? id;
  final String? filter;
  final int? length;
  final List<int>? w;
  final List<int>? index;
}

class ObjStmHeader {
  ObjStmHeader(this.index);

  final Map<int, int> index;
}

class ScanDictInfoReader {
  ScanDictInfoReader(
    this.nextIndex,
    this.isCatalog,
    this.skipAbs,
    this.streamStartAbs,
  );

  final int nextIndex;
  final bool isCatalog;
  final int? skipAbs;
  final int? streamStartAbs;
}

class ScanDictInfo {
  ScanDictInfo(this.nextIndex, this.isCatalog);

  final int nextIndex;
  final bool isCatalog;
}

class DictLightResult {
  DictLightResult(this.nextIndex, this.length, this.isCatalog);

  final int nextIndex;
  final int? length;
  final bool isCatalog;
}
