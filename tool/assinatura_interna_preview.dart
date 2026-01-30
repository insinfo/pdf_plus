import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:pdf_plus/signing.dart' as pdf;
import 'package:pdf_plus/pdf.dart' as pdf;

class DadosUsuarioAssinatura {
  DadosUsuarioAssinatura({required this.nome, required this.cpf});

  final String nome;
  final String cpf;
}

void main(List<String> args) async {
  final outputPath =
      args.isNotEmpty ? args[0] : 'assinatura_interna_preview.pdf';
  final url =
      args.length > 1 ? args[1] : 'http://localhost:3350/assinaturas/validar';
  final logoPath =
      args.length > 2 ? args[2] : 'test/assets/images/brasao_editado_1.png';

  Uint8List? logoBytes;
  final logoFile = File(logoPath);
  if (logoFile.existsSync()) {
    logoBytes = logoFile.readAsBytesSync();
  }

  final doc = pdf.PdfDocument();
  final page = pdf.PdfPage(doc);
  final g = page.getGraphics();

  final boundsLeft = 50.0;
  final boundsTop = 150.0;
  final boundsWidth = 320.0;
  final boundsHeight = 95.0;

  final dadosUsuario = DadosUsuarioAssinatura(
    nome: 'ISAQUE NEVES SANT ANA',
    cpf: '13128200000',
  );

  _drawAssinaturaInternaPreview(
    document: doc,
    graphics: g,
    boundsLeft: boundsLeft,
    boundsTop: boundsTop,
    boundsWidth: boundsWidth,
    boundsHeight: boundsHeight,
    pageHeight: page.pageFormat.height,
    dataAssinatura: DateTime(2026, 1, 9, 20, 9, 49),
    dadosUsuario: dadosUsuario,
    urlValidacao: url,
    logoBytes: logoBytes,
  );

  final bytes = await doc.save(useIsolate: false);
  try {
    await File(outputPath).writeAsBytes(bytes, flush: true);
    stdout.writeln('PDF gerado em: $outputPath');
  } on PathAccessException {
    final stamp = DateTime.now().millisecondsSinceEpoch;
    final fallback = outputPath.replaceAll('.pdf', '_$stamp.pdf');
    await File(fallback).writeAsBytes(bytes, flush: true);
    stdout.writeln('PDF gerado em: $fallback');
  }
}

void _drawAssinaturaInternaPreview({
  required pdf.PdfDocument document,
  required pdf.PdfGraphics graphics,
  required double boundsLeft,
  required double boundsTop,
  required double boundsWidth,
  required double boundsHeight,
  required double pageHeight,
  required DateTime dataAssinatura,
  required DadosUsuarioAssinatura dadosUsuario,
  required String urlValidacao,
  Uint8List? logoBytes,
}) {
  final size = _Size(boundsWidth, boundsHeight);

  const padding = 8.0;
  var logoBoxWidth = size.width * 0.28;
  if (logoBoxWidth < 48) {
    logoBoxWidth = 48;
  } else if (logoBoxWidth > 96) {
    logoBoxWidth = 96;
  }
  if (logoBoxWidth > 80) {
    logoBoxWidth = 80;
  }
  final textStartX = padding + logoBoxWidth + 2.0;
  var contentWidth = size.width - textStartX - padding;
  if (contentWidth < 0) {
    contentWidth = 0;
  }

  final fontBold = pdf.PdfVisualFont.standard(
    pdf.PdfVisualFontFamily.helvetica,
    9,
    style: pdf.PdfVisualFontStyle.bold,
  );
  final fontRegular = pdf.PdfVisualFont.standard(
    pdf.PdfVisualFontFamily.helvetica,
    8,
  );
  final fontSmall = pdf.PdfVisualFont.standard(
    pdf.PdfVisualFontFamily.helvetica,
    7,
  );
  final smallHeight = fontSmall.lineHeight(document);
  final regularHeight = fontRegular.lineHeight(document);
  final boldHeight = fontBold.lineHeight(document);
  const lineGap = 2.0;
  const tightGap = 1.0;
  var urlFont = fontSmall;
  var urlLineHeight = smallHeight;

  final logoBoxHeight = size.height - (padding * 2);
  final logoLeft = boundsLeft + padding;
  final textTop = boundsTop + padding + 2;
  final logoTop = textTop;
  if (logoBytes != null) {
    try {
      final image = pdf.PdfVisualImage(logoBytes);
      final aspect = image.width / image.height;
      final maxLogoWidth = logoBoxWidth - 10;
      final maxLogoHeight = logoBoxHeight - 10;
      double drawW = maxLogoWidth;
      double drawH = drawW / aspect;
      if (drawH > maxLogoHeight) {
        drawH = maxLogoHeight;
        drawW = drawH * aspect;
      }
      final left = logoLeft + (logoBoxWidth - drawW) / 2;
      final top = logoTop;
      graphics.drawImageBoxTopLeft(
        document,
        image,
        left: left,
        top: top,
        width: drawW,
        height: drawH,
        pageHeight: pageHeight,
      );
    } catch (_) {
      _drawLogoFallbackText(
        document,
        graphics,
        logoLeft,
        logoTop,
        logoBoxWidth,
        logoBoxHeight,
        fontBold,
        boundsLeft,
        boundsTop,
        boundsWidth,
        boundsHeight,
        pageHeight,
      );
    }
  } else {
    _drawLogoFallbackText(
      document,
      graphics,
      logoLeft,
      logoTop,
      logoBoxWidth,
      logoBoxHeight,
      fontBold,
      boundsLeft,
      boundsTop,
      boundsWidth,
      boundsHeight,
      pageHeight,
    );
  }

  var currentY = textTop;

  if (contentWidth > 0) {
    graphics.drawTextBoxTopLeft(
      document,
      'Documento assinado digitalmente pelo SALI',
      fontSmall,
      color: pdf.PdfColor.fromRgbInt(80, 80, 80),
      left: boundsLeft + textStartX,
      top: currentY,
      width: contentWidth,
      height: smallHeight,
      pageHeight: pageHeight,
    );
    currentY += smallHeight + lineGap;
  }

  final signatario = (dadosUsuario.nome).trim();
  final nomeParte =
      signatario.length > 40 ? '${signatario.substring(0, 40)}...' : signatario;

  if (contentWidth > 0) {
    graphics.drawTextBoxTopLeft(
      document,
      nomeParte.toUpperCase(),
      fontBold,
      left: boundsLeft + textStartX,
      top: currentY,
      width: contentWidth,
      height: boldHeight,
      pageHeight: pageHeight,
    );
    currentY += boldHeight + lineGap;
  }

  if (contentWidth > 0) {
    graphics.drawTextBoxTopLeft(
      document,
      'CPF: ${_maskCpf(dadosUsuario.cpf)}',
      fontRegular,
      left: boundsLeft + textStartX,
      top: currentY,
      width: contentWidth,
      height: regularHeight,
      pageHeight: pageHeight,
    );
    currentY += regularHeight + lineGap;
  }

  if (contentWidth > 0) {
    graphics.drawTextBoxTopLeft(
      document,
      'Data: ${_formatDateTimeBrazil(dataAssinatura)}',
      fontRegular,
      left: boundsLeft + textStartX,
      top: currentY,
      width: contentWidth,
      height: regularHeight,
      pageHeight: pageHeight,
    );
    currentY += regularHeight + lineGap;
  }

  if (contentWidth > 0) {
    final remainingHeight = size.height - padding - (currentY - boundsTop);
    final canShowLabel =
        remainingHeight >= (smallHeight + tightGap + smallHeight);
    if (canShowLabel) {
      graphics.drawTextBoxTopLeft(
        document,
        'Verifique em:',
        fontSmall,
        color: pdf.PdfColor.fromRgbInt(60, 60, 60),
        left: boundsLeft + textStartX,
        top: currentY,
        width: contentWidth,
        height: smallHeight,
        pageHeight: pageHeight,
      );
      currentY += smallHeight + tightGap;
    }
    final availableHeight =
        remainingHeight - (canShowLabel ? (smallHeight + tightGap) : 0);
    var maxUrlLines = availableHeight >= (smallHeight * 2) + tightGap ? 2 : 1;
    final maxUrlHeight =
        (smallHeight * maxUrlLines) + tightGap * (maxUrlLines - 1);
    if (availableHeight > 0 && availableHeight < maxUrlHeight) {
      final scale = availableHeight / maxUrlHeight;
      final scaledSize = math.max(5.0, fontSmall.size * scale);
      urlFont = pdf.PdfVisualFont.standard(
        pdf.PdfVisualFontFamily.helvetica,
        scaledSize,
      );
      urlLineHeight = urlFont.height(document);
      final scaledHeight =
          (urlLineHeight * maxUrlLines) + tightGap * (maxUrlLines - 1);
      if (maxUrlLines > 1 && scaledHeight > availableHeight) {
        maxUrlLines = 1;
      }
    }
    if (urlFont == fontSmall) {
      urlLineHeight = smallHeight;
    }
    final urlLines = _splitUrlToLines(
      document,
      urlValidacao,
      urlFont,
      contentWidth,
      maxLines: maxUrlLines,
    );

    for (final line in urlLines) {
      graphics.drawTextBoxTopLeft(
        document,
        line,
        urlFont,
        color: pdf.PdfColor.fromRgbInt(0, 102, 204),
        left: boundsLeft + textStartX,
        top: currentY,
        width: contentWidth,
        height: urlLineHeight,
        pageHeight: pageHeight,
      );
      currentY += urlLineHeight + tightGap;
    }
  }
}

void _drawLogoFallbackText(
  pdf.PdfDocument document,
  pdf.PdfGraphics graphics,
  double left,
  double top,
  double width,
  double height,
  pdf.PdfVisualFont fontBold,
  double boundsLeft,
  double boundsTop,
  double boundsWidth,
  double boundsHeight,
  double pageHeight,
) {
  graphics.drawTextBoxTopLeft(
    document,
    'SALI',
    fontBold,
    color: pdf.PdfColor.fromRgbInt(134, 15, 239),
    left: left + 6,
    top: top + (height / 2) - 6,
    width: width - 12,
    height: 12,
    pageHeight: pageHeight,
  );
}

List<String> _splitUrlToLines(
  pdf.PdfDocument document,
  String url,
  pdf.PdfVisualFont font,
  double maxWidth, {
  int maxLines = 2,
}) {
  if (maxWidth <= 0 || maxLines <= 1) {
    return [url];
  }
  if (font.measureString(document, url).width <= maxWidth) {
    return [url];
  }

  final lines = <String>[];
  var remaining = url;

  for (var lineIndex = 0; lineIndex < maxLines - 1; lineIndex++) {
    if (font.measureString(document, remaining).width <= maxWidth) {
      break;
    }

    var splitIndex = -1;
    for (var i = remaining.length - 1; i > 0; i--) {
      final candidate = remaining.substring(0, i);
      if (font.measureString(document, candidate).width <= maxWidth) {
        final prev = remaining[i - 1];
        if (prev == '/' || prev == '?' || prev == '&' || prev == '-') {
          splitIndex = i;
          break;
        }
      }
    }

    if (splitIndex == -1) {
      for (var i = remaining.length - 1; i > 0; i--) {
        final candidate = remaining.substring(0, i);
        if (font.measureString(document, candidate).width <= maxWidth) {
          splitIndex = i;
          break;
        }
      }
    }

    if (splitIndex <= 0) {
      break;
    }

    lines.add(remaining.substring(0, splitIndex));
    remaining = remaining.substring(splitIndex);
  }

  lines.add(remaining);
  return lines;
}

String _maskCpf(String cpf) {
  final digits = cpf.replaceAll(RegExp(r'\\D'), '');
  if (digits.length != 11) return cpf;
  return '${digits.substring(0, 3)}.${digits.substring(3, 6)}.'
      '${digits.substring(6, 9)}-${digits.substring(9)}';
}

String _formatDateTimeBrazil(DateTime dt) {
  final two = (int v) => v.toString().padLeft(2, '0');
  return '${two(dt.day)}/${two(dt.month)}/${dt.year} ${two(dt.hour)}:${two(dt.minute)}';
}

class _Size {
  _Size(this.width, this.height);
  final double width;
  final double height;
}
