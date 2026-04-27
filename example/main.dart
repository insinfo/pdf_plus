import 'dart:io';

import 'package:pdf_plus/pdf.dart' as pdf;
import 'package:pdf_plus/widgets.dart' as pw;

Future<void> main() async {
  final document = pw.Document();

  document.addPage(
    pw.MultiPage(
      pageFormat: pdf.PdfPageFormat.a4,
      margin: const pw.EdgeInsets.all(28),
      maxPages: 80,
      header: (pw.Context context) => pw.Container(
        alignment: pw.Alignment.centerRight,
        margin: const pw.EdgeInsets.only(bottom: 12),
        child: pw.Text(
          'Tabela complexa - pagina ${context.pageNumber}',
          style: const pw.TextStyle(fontSize: 9),
        ),
      ),
      footer: (pw.Context context) => pw.Container(
        alignment: pw.Alignment.center,
        margin: const pw.EdgeInsets.only(top: 12),
        child: pw.Text(
          'pdf_plus SpanningTable | ${context.pageNumber}/${context.pagesCount}',
          style: const pw.TextStyle(fontSize: 9, color: pdf.PdfColors.grey700),
        ),
      ),
      build: (pw.Context context) => <pw.Widget>[
        pw.Text(
          'Relatorio - tabela grande com rowspan e colspan',
          style: pw.TextStyle(
            fontSize: 18,
            fontWeight: pw.FontWeight.bold,
          ),
        ),
        pw.SizedBox(height: 8),
        pw.Text(
          'Exemplo de tabela paginavel com cabecalho repetido, larguras fixas/flexiveis, celulas mescladas, alinhamento, padding e conteudo como Widget.',
          style: const pw.TextStyle(fontSize: 10),
        ),
        pw.SizedBox(height: 16),
        pw.SpanningTable(
          border: pw.TableBorder.all(
            color: pdf.PdfColors.blueGrey700,
            width: .5,
          ),
          defaultCellAlignment: pw.Alignment.center,
          defaultVerticalAlignment: pw.TableCellVerticalAlignment.middle,
          columnWidths: const <int, pw.TableColumnWidth>{
            0: pw.FixedColumnWidth(42),
            1: pw.FlexColumnWidth(1.2),
            2: pw.FlexColumnWidth(1.4),
            3: pw.FlexColumnWidth(1),
            4: pw.FixedColumnWidth(56),
            5: pw.FlexColumnWidth(1.1),
          },
          children: _buildComplexRows(groupCount: 90),
        ),
      ],
    ),
  );

  final file = File('example.pdf');
  await file.writeAsBytes(await document.save());
  print('PDF gerado em ${file.absolute.path}');
}

List<pw.SpanningTableRow> _buildComplexRows({required int groupCount}) {
  final rows = <pw.SpanningTableRow>[
    pw.SpanningTableRow(
      repeat: true,
      decoration: const pw.BoxDecoration(color: pdf.PdfColors.blueGrey100),
      verticalAlignment: pw.TableCellVerticalAlignment.middle,
      children: <pw.SpanningTableCell>[
        _headerCell('GRUPO'),
        _headerCell('SERVIDOR'),
        _headerCell('PROCESSO'),
        _headerCell('STATUS'),
        _headerCell('PRAZO'),
        _headerCell('OBSERVACAO'),
      ],
    ),
  ];

  for (var index = 0; index < groupCount; index++) {
    final color = index.isEven ? pdf.PdfColors.grey100 : pdf.PdfColors.white;

    rows.add(
      pw.SpanningTableRow(
        decoration: pw.BoxDecoration(color: color),
        verticalAlignment: pw.TableCellVerticalAlignment.middle,
        children: <pw.SpanningTableCell>[
          _bodyCell(
            'G-${(index + 1).toString().padLeft(3, '0')}',
            rowSpan: 3,
            noWrap: true,
            style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
          ),
          _bodyCell('Servidor titular ${index + 1}', columnSpan: 2),
          _badgeCell(index % 3 == 0 ? 'Pendente' : 'Em andamento'),
          _bodyCell('${5 + (index % 20)} dias'),
          _bodyCell('Prioridade ${index % 4 + 1}'),
        ],
      ),
    );

    rows.add(
      pw.SpanningTableRow(
        decoration: pw.BoxDecoration(color: color),
        children: <pw.SpanningTableCell>[
          _bodyCell('Matricula ${4500 + index}'),
          _bodyCell('Processo ${20260000 + index}'),
          _bodyCell('Setor GEADMC / Protocolo', columnSpan: 2),
          _bodyCell('Login _${index + 1}'),
        ],
      ),
    );

    rows.add(
      pw.SpanningTableRow(
        decoration: pw.BoxDecoration(color: color),
        children: <pw.SpanningTableCell>[
          _bodyCell(
            'Historico: despacho administrativo com texto longo para demonstrar quebra interna, largura flexivel e continuidade correta entre paginas.',
            columnSpan: 4,
            alignment: pw.Alignment.centerLeft,
          ),
          _bodyCell(index.isEven ? 'Revisar' : 'Conferido'),
        ],
      ),
    );
  }

  rows.add(
    pw.SpanningTableRow(
      decoration: const pw.BoxDecoration(color: pdf.PdfColors.blueGrey50),
      children: <pw.SpanningTableCell>[
        _bodyCell(
          'Total de grupos demonstrados',
          columnSpan: 4,
          alignment: pw.Alignment.centerRight,
          style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
        ),
        _bodyCell(
          '$groupCount',
          columnSpan: 2,
          style: pw.TextStyle(fontWeight: pw.FontWeight.bold),
        ),
      ],
    ),
  );

  return rows;
}

pw.SpanningTableCell _headerCell(String text) {
  return pw.SpanningTableCell(
    padding: const pw.EdgeInsets.symmetric(horizontal: 5, vertical: 6),
    child: pw.FittedBox(
      fit: pw.BoxFit.scaleDown,
      child: pw.Text(
        text,
        softWrap: false,
        textAlign: pw.TextAlign.center,
        style: pw.TextStyle(fontSize: 8, fontWeight: pw.FontWeight.bold),
      ),
    ),
  );
}

pw.SpanningTableCell _bodyCell(
  String text, {
  int columnSpan = 1,
  int rowSpan = 1,
  pw.AlignmentGeometry alignment = pw.Alignment.center,
  pw.TextStyle? style,
  bool noWrap = false,
}) {
  final textWidget = pw.Text(
    text,
    softWrap: noWrap ? false : null,
    textAlign: alignment == pw.Alignment.centerRight
        ? pw.TextAlign.right
        : alignment == pw.Alignment.centerLeft
            ? pw.TextAlign.left
            : pw.TextAlign.center,
    style: style ?? const pw.TextStyle(fontSize: 9),
  );

  return pw.SpanningTableCell(
    columnSpan: columnSpan,
    rowSpan: rowSpan,
    alignment: alignment,
    padding: const pw.EdgeInsets.symmetric(horizontal: 5, vertical: 5),
    child: noWrap
        ? pw.FittedBox(fit: pw.BoxFit.scaleDown, child: textWidget)
        : textWidget,
  );
}

pw.SpanningTableCell _badgeCell(String text) {
  final color = text == 'Pendente'
      ? pdf.PdfColors.orange100
      : pdf.PdfColors.lightGreen100;

  return pw.SpanningTableCell(
    padding: const pw.EdgeInsets.symmetric(horizontal: 5, vertical: 5),
    child: pw.Container(
      alignment: pw.Alignment.center,
      padding: const pw.EdgeInsets.symmetric(horizontal: 4, vertical: 3),
      decoration: pw.BoxDecoration(
        color: color,
        borderRadius: const pw.BorderRadius.all(pw.Radius.circular(2)),
      ),
      child: pw.Text(text, style: const pw.TextStyle(fontSize: 8)),
    ),
  );
}
