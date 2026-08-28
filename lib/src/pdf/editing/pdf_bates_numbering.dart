import '../color.dart';
import '../colors.dart';
import '../document.dart';
import '../obj/font.dart';
import '../obj/page.dart';
import 'pdf_box.dart';
import 'pdf_page_content_editor.dart';

/// Sequential Bates-style numbering applied to a range of pages.
///
/// The Bates number is the identification stamp used in legal proceedings and
/// evidentiary documentation: a fixed prefix, a counter with a constant digit
/// count and, optionally, a suffix — `PROC-000042`. Each page gets the next
/// number, always in the same position.
///
/// ```dart
/// const bates = PdfBatesNumbering(prefix: 'PROC-', digits: 6);
/// bates.applyToDocument(document);
/// ```
///
/// The stamp goes in as an overlay isolated by a [PdfPageContentEditor], so
/// the original page content stays intact.
class PdfBatesNumbering {
  /// Configures the numbering.
  const PdfBatesNumbering({
    this.prefix = '',
    this.suffix = '',
    this.start = 1,
    this.step = 1,
    this.digits = 6,
    this.font,
    this.fontSize = 9,
    this.color = PdfColors.black,
    this.anchor = PdfStampAnchor.bottomRight,
    this.marginX = 24,
    this.marginY = 24,
    this.reference = PdfBoxType.crop,
  })  : assert(digits >= 0, 'The digit count cannot be negative.'),
        assert(step != 0, 'The step must be non-zero.');

  /// Fixed text before the number.
  final String prefix;

  /// Fixed text after the number.
  final String suffix;

  /// Number of the first numbered page.
  final int start;

  /// How much the counter advances from one page to the next.
  final int step;

  /// Minimum digit count, padded with leading zeros.
  final int digits;

  /// The font; when null, a Helvetica shared by the document.
  final PdfFont? font;

  /// Font size, in display points.
  final double fontSize;

  /// Text color.
  final PdfColor color;

  /// Position of the stamp within the visible area.
  final PdfStampAnchor anchor;

  /// Horizontal distance to the edge.
  final double marginX;

  /// Vertical distance to the edge.
  final double marginY;

  /// Box that defines the visible area used to position the stamp.
  final PdfBoxType reference;

  /// The text stamped for a given [number].
  String format(int number) {
    final digitsOnly = number.abs().toString().padLeft(digits, '0');
    final sign = number < 0 ? '-' : '';
    return '$prefix$sign$digitsOnly$suffix';
  }

  /// Numbers the pages of [document] in the range `[from, to)`, zero based.
  ///
  /// A null `to` means up to the last page. Returns the number of pages
  /// stamped.
  ///
  /// The page list is the one from [PdfPageContentEditor.distinctPages]: a
  /// loaded document registers each page twice in `pdfPageList.pages`, and
  /// numbering over the raw list would stamp the same page twice.
  int applyToDocument(
    PdfDocument document, {
    int from = 0,
    int? to,
  }) {
    final pages = PdfPageContentEditor.distinctPages(document);
    final first = from < 0 ? 0 : from;
    final last = to == null || to > pages.length ? pages.length : to;
    if (first >= last) return 0;
    return applyToPages(pages.sublist(first, last));
  }

  /// Numbers exactly the given pages, in the order received.
  int applyToPages(Iterable<PdfPage> pages) {
    var number = start;
    var stamped = 0;
    for (final page in pages) {
      final editor = PdfPageContentEditor(page, reference: reference);
      editor.drawStamp(PdfTextStamp(
        text: format(number),
        font: font,
        fontSize: fontSize,
        color: color,
        anchor: anchor,
        marginX: marginX,
        marginY: marginY,
      ));
      number += step;
      stamped++;
    }
    return stamped;
  }
}
