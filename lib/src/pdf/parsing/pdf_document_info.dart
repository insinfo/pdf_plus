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
