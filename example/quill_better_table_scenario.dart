import 'dart:collection';
import 'dart:io';
import 'dart:math' as math;

import 'package:pdf_plus/pdf.dart' as pdf;
import 'package:pdf_plus/widgets.dart' as pw;

const _cellText =
    'enim accumsan accumsan. Integer luctus quam sit amet diam tristique tempor.';
const _rowCount = 54;
const _columnCount = 2;
const _repeatColumnTitles = false;

Future<void> main() async {
  final document = pw.Document();
  final tableModel = _buildQuillBetterTableLikeModel();

  document.addPage(
    pw.MultiPage(
      pageFormat: pdf.PdfPageFormat.a4,
      margin: const pw.EdgeInsets.all(28),
      maxPages: 30,
      footer: (context) => pw.Container(
        alignment: pw.Alignment.centerRight,
        margin: const pw.EdgeInsets.only(top: 12),
        child: pw.Text(
          'quill-better-table scenario | pagina ${context.pageNumber}/${context.pagesCount}',
          style: const pw.TextStyle(fontSize: 8, color: pdf.PdfColors.grey700),
        ),
      ),
      build: (context) => <pw.Widget>[
        pw.Text(
          'Simulacao de tabela Quill Better Table',
          style: pw.TextStyle(fontSize: 16, fontWeight: pw.FontWeight.bold),
        ),
        pw.SizedBox(height: 8),
        pw.Text(
          'Este arquivo reproduz o caso do Delta: muito texto alinhado a direita antes da tabela, duas colunas numeradas com largura 321 e modo clip. A repeticao da primeira linha esta desativada por padrao, como no Word quando a opcao de repetir titulo nao foi ligada.',
          textAlign: pw.TextAlign.justify,
          style: const pw.TextStyle(fontSize: 10),
        ),
        pw.SizedBox(height: 10),
        for (final paragraph in _longRightAlignedText()) ...<pw.Widget>[
          pw.Text(
            paragraph,
            textAlign: pw.TextAlign.right,
            style: const pw.TextStyle(fontSize: 11),
          ),
          pw.SizedBox(height: 6),
        ],
        _renderTable(tableModel, repeatFirstRow: _repeatColumnTitles),
        pw.SizedBox(height: 24),
        pw.Text(
          'Mesma tabela com repeat ligado para comparacao',
          style: pw.TextStyle(fontSize: 13, fontWeight: pw.FontWeight.bold),
        ),
        pw.SizedBox(height: 8),
        pw.Text(
          'Use esta segunda tabela para comparar com a opcao ligada: a linha L01 aparece no topo de cada nova pagina como titulo repetido. As demais linhas continuam identificadas como Lxx Cyy.',
          textAlign: pw.TextAlign.justify,
          style: const pw.TextStyle(fontSize: 10),
        ),
        pw.SizedBox(height: 8),
        _renderTable(tableModel, repeatFirstRow: true),
      ],
    ),
  );

  final file = File('example/quill_better_table_scenario.pdf');
  await file.writeAsBytes(await document.save());
  print('PDF gerado em ${file.absolute.path}');
}

class _TCell {
  _TCell({
    required this.text,
    required this.rowId,
    required this.colspan,
    required this.rowspan,
    required this.widthHint,
    required this.align,
    required this.bold,
  });

  final String text;
  final String rowId;
  final int colspan;
  final int rowspan;
  final double widthHint;
  final String align;
  final bool bold;
}

class _TRow {
  _TRow(this.key);

  final String key;
  final List<_TCell> cells = <_TCell>[];
}

class _TTable {
  final List<_TRow> rows = <_TRow>[];
}

class _QuillLikeCellLine {
  const _QuillLikeCellLine({
    required this.rowId,
    required this.text,
    required this.width,
    this.colspan = 1,
    this.rowspan = 1,
    this.align = 'right',
    this.bold = false,
  });

  final String rowId;
  final String text;
  final double width;
  final int colspan;
  final int rowspan;
  final String align;
  final bool bold;
}

_TTable _buildQuillBetterTableLikeModel() {
  final lines = <_QuillLikeCellLine>[
    for (var row = 1; row <= _rowCount; row++)
      for (var column = 1; column <= _columnCount; column++)
        _QuillLikeCellLine(
          rowId: '$row',
          text: _numberedCellText(row, column),
          width: 321,
          colspan: 1,
          rowspan: 1,
          align: 'right',
          bold: row == 1,
        ),
  ];

  final table = _TTable();
  final mapRows = LinkedHashMap<String, _TRow>();

  for (final line in lines) {
    var colspan = line.colspan;
    var rowspan = line.rowspan;
    if (colspan <= 0) colspan = 1;
    if (rowspan <= 0) rowspan = 1;

    final cell = _TCell(
      text: line.text.trim(),
      rowId: line.rowId,
      colspan: colspan,
      rowspan: rowspan,
      widthHint: line.width,
      align: line.align,
      bold: line.bold,
    );

    final row = mapRows.putIfAbsent(cell.rowId, () => _TRow(cell.rowId));
    row.cells.add(cell);
  }

  final keys = mapRows.keys.toList()
    ..sort((a, b) {
      final ai = int.tryParse(a);
      final bi = int.tryParse(b);
      if (ai != null && bi != null) return ai.compareTo(bi);
      return a.compareTo(b);
    });

  for (final key in keys) {
    table.rows.add(mapRows[key]!);
  }

  return table;
}

String _numberedCellText(int row, int column) {
  final label =
      'L${row.toString().padLeft(2, '0')} C${column.toString().padLeft(2, '0')}';
  return '$label | $_cellText | $label fim';
}

List<double> _computeColumnWidths(_TTable model) {
  final widths = <double>[];
  final pending = <int>[];

  for (final row in model.rows) {
    var column = 0;

    while (column < pending.length && pending[column] > 0) {
      pending[column] -= 1;
      column++;
    }

    for (final cell in row.cells) {
      while (column < pending.length && pending[column] > 0) {
        pending[column] -= 1;
        column++;
      }

      final startColumn = column;
      final endColumn = startColumn + cell.colspan;

      while (widths.length < endColumn) {
        widths.add(0.0);
      }
      while (pending.length < endColumn) {
        pending.add(0);
      }

      if (cell.widthHint > 0) {
        final perColumn = cell.widthHint / cell.colspan;
        for (var index = startColumn; index < endColumn; index++) {
          widths[index] = math.max(widths[index], perColumn);
        }
      }

      for (var index = startColumn; index < endColumn; index++) {
        pending[index] += (cell.rowspan - 1).clamp(0, 1000).toInt();
      }
      column = endColumn;
    }

    while (column < pending.length) {
      if (pending[column] > 0) {
        pending[column] -= 1;
      }
      column++;
    }
  }

  return widths;
}

pw.Widget _renderTable(_TTable model, {required bool repeatFirstRow}) {
  final widthHints = _computeColumnWidths(model);
  final totalHint = widthHints.fold<double>(0.0, (sum, width) => sum + width);

  Map<int, pw.TableColumnWidth>? columnWidths;
  if (totalHint > 0) {
    columnWidths = <int, pw.TableColumnWidth>{
      for (var index = 0; index < widthHints.length; index++)
        if (widthHints[index] > 0)
          index: pw.FractionColumnWidth(widthHints[index] / totalHint),
    };
  }

  final rows = <pw.SpanningTableRow>[];
  for (var index = 0; index < model.rows.length; index++) {
    final source = model.rows[index];
    rows.add(
      pw.SpanningTableRow(
        repeat: repeatFirstRow && index == 0,
        verticalAlignment: pw.TableCellVerticalAlignment.middle,
        children: <pw.SpanningTableCell>[
          for (final cell in source.cells) _buildCell(cell),
        ],
      ),
    );
  }

  return pw.SpanningTable(
    border: pw.TableBorder.all(width: 1.0, color: pdf.PdfColors.black),
    defaultVerticalAlignment: pw.TableCellVerticalAlignment.middle,
    defaultCellAlignment: pw.Alignment.center,
    columnWidths: columnWidths,
    overflow: pw.SpanningTableOverflowMode.clip,
    children: rows,
  );
}

pw.SpanningTableCell _buildCell(_TCell cell) {
  return pw.SpanningTableCell(
    columnSpan: cell.colspan,
    rowSpan: cell.rowspan,
    alignment: _toAlign(cell.align),
    verticalAlignment: pw.TableCellVerticalAlignment.middle,
    padding: const pw.EdgeInsets.symmetric(horizontal: 6, vertical: 4),
    child: pw.Text(
      cell.text,
      textAlign: _toTextAlign(cell.align),
      style: cell.bold ? pw.TextStyle(fontWeight: pw.FontWeight.bold) : null,
    ),
  );
}

pw.AlignmentGeometry _toAlign(String align) {
  switch (align) {
    case 'left':
      return pw.Alignment.centerLeft;
    case 'right':
      return pw.Alignment.centerRight;
    case 'justify':
      return pw.Alignment.centerLeft;
    default:
      return pw.Alignment.center;
  }
}

pw.TextAlign _toTextAlign(String align) {
  switch (align) {
    case 'left':
      return pw.TextAlign.left;
    case 'right':
      return pw.TextAlign.right;
    case 'justify':
      return pw.TextAlign.justify;
    default:
      return pw.TextAlign.center;
  }
}

List<String> _longRightAlignedText() {
  const fragments = <String>[
    'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla ligula tellus, porttitor nec augue et, fringilla vehicula tellus. Praesent non facilisis nibh, vitae accumsan urna.',
    'Sed sodales tristique efficitur. Maecenas dictum, neque nec laoreet condimentum, erat risus aliquet odio, sit amet scelerisque urna ex et enim.',
    'Nullam sodales purus eu velit scelerisque sagittis. Etiam vitae massa sed leo congue vehicula. Praesent nec maximus lorem. Maecenas iaculis nunc quis massa ultrices interdum.',
    'Donec sodales nisl viverra, tincidunt metus maximus, gravida metus. Suspendisse a lobortis ipsum, ut mattis sem. Etiam nec sollicitudin lacus, sit amet dapibus orci.',
    'Pellentesque volutpat ultricies iaculis. Aliquam erat volutpat. Morbi ipsum nisi, sagittis ut sollicitudin id, commodo vel est. Nam id purus quis tortor pellentesque sodales iaculis eu urna.',
    'In hac habitasse platea dictumst. Nullam ac lorem ante. Suspendisse ultrices odio sit amet arcu sollicitudin placerat. Sed porttitor semper condimentum.',
  ];

  return <String>[
    for (var index = 0; index < 34; index++)
      fragments[index % fragments.length],
  ];
}
