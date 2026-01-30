import 'dart:typed_data';

import 'package:image/image.dart' as im;

import '../color.dart';
import '../document.dart';
import '../graphics.dart';
import '../obj/font.dart';
import '../obj/image.dart';
import '../obj/ttffont.dart';
import '../rect.dart';

enum PdfVisualFontFamily {
  helvetica,
}

enum PdfVisualFontStyle {
  normal,
  bold,
}

class PdfVisualStringMetrics {
  const PdfVisualStringMetrics({
    required this.width,
    required this.height,
  });

  final double width;
  final double height;
}

/// Lightweight font descriptor for drawing visual elements.
class PdfVisualFont {
  PdfVisualFont.standard(
    this.family,
    this.size, {
    this.style = PdfVisualFontStyle.normal,
  }) : _ttfBytes = null;

  PdfVisualFont.ttf(
    Uint8List bytes,
    this.size, {
    this.style = PdfVisualFontStyle.normal,
  })  : _ttfBytes = bytes,
        family = null;

  final PdfVisualFontFamily? family;
  final PdfVisualFontStyle style;
  final double size;
  final Uint8List? _ttfBytes;

  final Map<PdfDocument, PdfFont> _cache = <PdfDocument, PdfFont>{};

  PdfFont resolve(PdfDocument document) {
    final cached = _cache[document];
    if (cached != null) return cached;

    PdfFont font;
    final bytes = _ttfBytes;
    if (bytes != null) {
      font = PdfTtfFont(document, ByteData.sublistView(bytes));
    } else {
      switch (family ?? PdfVisualFontFamily.helvetica) {
        case PdfVisualFontFamily.helvetica:
          font = style == PdfVisualFontStyle.bold
              ? PdfFont.helveticaBold(document)
              : PdfFont.helvetica(document);
          break;
      }
    }
    _cache[document] = font;
    return font;
  }

  PdfVisualStringMetrics measureString(PdfDocument document, String text) {
    final font = resolve(document);
    final metrics = font.stringMetrics(text);
    final scale = size / font.unitsPerEm;
    return PdfVisualStringMetrics(
      width: metrics.width * scale,
      height: metrics.height * scale,
    );
  }

  double height(PdfDocument document) {
    return lineHeight(document);
  }

  double ascent(PdfDocument document) {
    final font = resolve(document);
    return font.ascent * size;
  }

  double descent(PdfDocument document) {
    final font = resolve(document);
    return font.descent * size;
  }

  double lineHeight(PdfDocument document) {
    final font = resolve(document);
    return (font.ascent - font.descent) * size;
  }
}

/// Bitmap wrapper that exposes width/height without a PdfDocument.
class PdfVisualImage {
  PdfVisualImage(this.bytes);

  final Uint8List bytes;
  im.Image? _decoded;

  int get width => _decode().width;
  int get height => _decode().height;

  PdfImage toPdfImage(PdfDocument document) {
    return PdfImage.file(document, bytes: bytes);
  }

  im.Image _decode() {
    if (_decoded != null) return _decoded!;
    final decoded = im.decodeImage(bytes);
    if (decoded == null) {
      throw StateError('Nao foi possivel decodificar a imagem.');
    }
    _decoded = decoded;
    return decoded;
  }
}

/// Converts a top-left rectangle to a PdfRect (bottom-left).
PdfRect rectFromTopLeft({
  required double left,
  required double top,
  required double width,
  required double height,
  required double pageHeight,
}) {
  final bottom = pageHeight - top - height;
  return PdfRect(left, bottom, width, height);
}

extension PdfGraphicsVisual on PdfGraphics {
  void drawTextBox(
    PdfDocument document,
    String text,
    PdfVisualFont font,
    PdfRect bounds, {
    PdfColor? color,
  }) {
    final resolved = font.resolve(document);
    final y = bounds.bottom + bounds.height - font.ascent(document);

    saveContext();
    if (color != null) {
      setFillColor(color);
    }
    drawString(resolved, font.size, text, bounds.left, y);
    restoreContext();
  }

  void drawImageBox(
    PdfDocument document,
    PdfVisualImage image,
    PdfRect bounds,
  ) {
    final pdfImage = image.toPdfImage(document);
    drawImage(pdfImage, bounds.left, bounds.bottom, bounds.width, bounds.height);
  }

  void drawTextBoxTopLeft(
    PdfDocument document,
    String text,
    PdfVisualFont font, {
    required double left,
    required double top,
    required double width,
    required double height,
    required double pageHeight,
    PdfColor? color,
  }) {
    final resolved = font.resolve(document);
    final y = pageHeight - top - font.ascent(document);
    saveContext();
    if (color != null) {
      setFillColor(color);
    }
    drawString(resolved, font.size, text, left, y);
    restoreContext();
  }

  void drawImageBoxTopLeft(
    PdfDocument document,
    PdfVisualImage image, {
    required double left,
    required double top,
    required double width,
    required double height,
    required double pageHeight,
  }) {
    final bounds = rectFromTopLeft(
      left: left,
      top: top,
      width: width,
      height: height,
      pageHeight: pageHeight,
    );
    drawImageBox(document, image, bounds);
  }
}
