import '../obj/page.dart';
import '../page_format.dart';
import 'parser_objects.dart';

PdfPageFormat? pageFormatFromBox(List<double>? box) {
  if (box == null || box.length < 4) return null;
  final width = box[2] - box[0];
  final height = box[3] - box[1];
  if (width <= 0 || height <= 0) return null;
  return PdfPageFormat(width, height);
}

PdfPageRotation pageRotationFromValue(dynamic value) {
  final rot = asInt(value) ?? 0;
  switch (rot % 360) {
    case 90:
      return PdfPageRotation.rotate90;
    case 180:
      return PdfPageRotation.rotate180;
    case 270:
      return PdfPageRotation.rotate270;
    default:
      return PdfPageRotation.none;
  }
}
