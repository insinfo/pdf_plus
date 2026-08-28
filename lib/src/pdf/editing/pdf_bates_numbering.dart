import '../color.dart';
import '../colors.dart';
import '../document.dart';
import '../obj/font.dart';
import '../obj/page.dart';
import 'pdf_box.dart';
import 'pdf_page_content_editor.dart';

/// Numeração sequencial estilo Bates, aplicada a um intervalo de páginas.
///
/// O número Bates é o carimbo de identificação usado em processos e
/// documentação probatória: um prefixo fixo, um contador com quantidade de
/// dígitos constante e, opcionalmente, um sufixo — `PROC-000042`. Cada página
/// recebe o número seguinte, sempre na mesma posição.
///
/// ```dart
/// const bates = PdfBatesNumbering(prefix: 'PROC-', digits: 6);
/// bates.applyToDocument(document);
/// ```
///
/// O carimbo entra como sobreposição isolada por um [PdfPageContentEditor],
/// de modo que o conteúdo original das páginas continua intacto.
class PdfBatesNumbering {
  /// Configura a numeração.
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
  })  : assert(digits >= 0, 'A quantidade de dígitos não pode ser negativa.'),
        assert(step != 0, 'O passo precisa ser diferente de zero.');

  /// Texto fixo antes do número.
  final String prefix;

  /// Texto fixo depois do número.
  final String suffix;

  /// Número da primeira página numerada.
  final int start;

  /// Quanto o contador avança de uma página para a seguinte.
  final int step;

  /// Quantidade mínima de dígitos, completada com zeros à esquerda.
  final int digits;

  /// A fonte; quando nula, uma Helvetica compartilhada pelo documento.
  final PdfFont? font;

  /// Corpo da fonte, em pontos de exibição.
  final double fontSize;

  /// Cor do texto.
  final PdfColor color;

  /// Posição do carimbo na área visível.
  final PdfStampAnchor anchor;

  /// Distância horizontal até a borda.
  final double marginX;

  /// Distância vertical até a borda.
  final double marginY;

  /// Caixa que define a área visível usada para posicionar o carimbo.
  final PdfBoxType reference;

  /// O texto carimbado para um dado [number].
  String format(int number) {
    final digitsOnly = number.abs().toString().padLeft(digits, '0');
    final sign = number < 0 ? '-' : '';
    return '$prefix$sign$digitsOnly$suffix';
  }

  /// Numera as páginas de [document] no intervalo `[from, to)`, base zero.
  ///
  /// `to` nulo significa até a última página. Devolve a quantidade de páginas
  /// carimbadas.
  ///
  /// A lista de páginas é a de [PdfPageContentEditor.distinctPages]: um
  /// documento carregado registra cada página duas vezes em
  /// `pdfPageList.pages`, e numerar sobre a lista crua carimbaria duas vezes a
  /// mesma página.
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

  /// Numera exatamente as páginas informadas, na ordem recebida.
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
