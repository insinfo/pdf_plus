/*
 * Copyright (C) 2017, David PHAM-VAN <dev.nfet.net@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/widgets.dart';
import 'package:test/test.dart';

SpanningTableCell _stressCell(
  String text, {
  int columnSpan = 1,
  int rowSpan = 1,
  double height = 22,
  AlignmentGeometry alignment = Alignment.center,
  TableCellVerticalAlignment? verticalAlignment,
}) {
  return SpanningTableCell(
    columnSpan: columnSpan,
    rowSpan: rowSpan,
    alignment: alignment,
    verticalAlignment: verticalAlignment,
    padding: const EdgeInsets.symmetric(horizontal: 3, vertical: 3),
    child: SizedBox(height: height, child: Text(text)),
  );
}

List<SpanningTableRow> _buildDenseSpanningTableRows({required int groups}) {
  final rows = <SpanningTableRow>[
    SpanningTableRow(
      repeat: true,
      decoration: const BoxDecoration(color: PdfColors.grey300),
      verticalAlignment: TableCellVerticalAlignment.middle,
      children: <SpanningTableCell>[
        for (final header in <String>[
          'GRUPO',
          'ORIGEM',
          'DESTINO',
          'STATUS',
          'PRAZO',
          'OBS'
        ])
          _stressCell(header, height: 14),
      ],
    ),
  ];

  for (var index = 0; index < groups; index++) {
    rows.add(
      SpanningTableRow(
        verticalAlignment: TableCellVerticalAlignment.middle,
        children: <SpanningTableCell>[
          _stressCell('G$index', rowSpan: 2),
          _stressCell('Processo ${10000 + index}', columnSpan: 2),
          _stressCell(index.isEven ? 'Aberto' : 'Concluido'),
          _stressCell('${index % 30 + 1} dias'),
          _stressCell('SALI'),
        ],
      ),
    );
    rows.add(
      SpanningTableRow(
        children: <SpanningTableCell>[
          _stressCell(
            'Historico detalhado do despacho $index',
            columnSpan: 3,
            alignment: Alignment.centerLeft,
          ),
          _stressCell('U${index % 7}'),
          _stressCell('Rev ${index % 5}'),
        ],
      ),
    );
  }

  return rows;
}

Matcher _spanningTableExceptionContaining(String text) {
  return throwsA(
    isA<SpanningTableException>().having(
      (error) => error.message,
      'message',
      contains(text),
    ),
  );
}

void main() {
  test('SpanningTable paginates long tables with header', () async {
    final doc = Document();

    doc.addPage(
      MultiPage(
        maxPages: 30,
        build: (Context context) => <Widget>[
          SpanningTable(
            border: TableBorder.all(),
            defaultCellAlignment: Alignment.center,
            defaultVerticalAlignment: TableCellVerticalAlignment.middle,
            columnWidths: const <int, TableColumnWidth>{
              0: FlexColumnWidth(3),
              1: FlexColumnWidth(2),
              2: FlexColumnWidth(2),
              3: FlexColumnWidth(2),
            },
            children: <SpanningTableRow>[
              SpanningTableRow(
                repeat: true,
                children: <SpanningTableCell>[
                  for (final header in <String>[
                    'SERVIDOR',
                    'CARGO',
                    'MATRICULA',
                    'LOGIN DO SALI'
                  ])
                    SpanningTableCell(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 6, vertical: 4),
                      child: Text(header,
                          style: TextStyle(fontWeight: FontWeight.bold)),
                    ),
                ],
              ),
              for (var index = 0; index < 80; index++)
                SpanningTableRow(
                  children: <SpanningTableCell>[
                    SpanningTableCell(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 6, vertical: 4),
                      child: Text('Servidor designado numero $index'),
                    ),
                    SpanningTableCell(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 6, vertical: 4),
                      child: Text('Cargo administrativo com descricao longa'),
                    ),
                    SpanningTableCell(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 6, vertical: 4),
                      child: Text('${20000 + index}'),
                    ),
                    SpanningTableCell(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 6, vertical: 4),
                      child: Text('login$index'),
                    ),
                  ],
                ),
            ],
          ),
        ],
      ),
    );

    final bytes = await doc.save();
    expect(bytes, isNotEmpty);
    expect(doc.document.pdfPageList.pages.length, greaterThan(1));
  });

  test('SpanningTable supports colspan and rowspan', () async {
    final doc = Document();

    doc.addPage(
      MultiPage(
        maxPages: 10,
        build: (Context context) => <Widget>[
          SpanningTable(
            border: TableBorder.all(),
            defaultCellAlignment: Alignment.center,
            columnWidths: const <int, TableColumnWidth>{
              0: FlexColumnWidth(),
              1: FlexColumnWidth(),
              2: FlexColumnWidth(),
              3: FlexColumnWidth(),
            },
            children: <SpanningTableRow>[
              SpanningTableRow(
                repeat: true,
                children: <SpanningTableCell>[
                  SpanningTableCell(
                    columnSpan: 4,
                    padding: const EdgeInsets.all(4),
                    child: Text('Relatorio consolidado',
                        style: TextStyle(fontWeight: FontWeight.bold)),
                  ),
                ],
              ),
              SpanningTableRow(
                children: <SpanningTableCell>[
                  SpanningTableCell(
                    rowSpan: 2,
                    padding: const EdgeInsets.all(4),
                    child: Text('Grupo A'),
                  ),
                  SpanningTableCell(
                    columnSpan: 2,
                    padding: const EdgeInsets.all(4),
                    child: Text('Subgrupo'),
                  ),
                  SpanningTableCell(
                    padding: const EdgeInsets.all(4),
                    child: Text('Total'),
                  ),
                ],
              ),
              SpanningTableRow(
                children: <SpanningTableCell>[
                  SpanningTableCell(
                      padding: const EdgeInsets.all(4), child: Text('Item 1')),
                  SpanningTableCell(
                      padding: const EdgeInsets.all(4), child: Text('Item 2')),
                  SpanningTableCell(
                      padding: const EdgeInsets.all(4), child: Text('42')),
                ],
              ),
              for (var index = 0; index < 40; index++)
                SpanningTableRow(
                  children: <SpanningTableCell>[
                    SpanningTableCell(
                        padding: const EdgeInsets.all(4),
                        child: Text('Linha $index')),
                    SpanningTableCell(
                        padding: const EdgeInsets.all(4), child: Text('A')),
                    SpanningTableCell(
                        padding: const EdgeInsets.all(4), child: Text('B')),
                    SpanningTableCell(
                        padding: const EdgeInsets.all(4), child: Text('C')),
                  ],
                ),
            ],
          ),
        ],
      ),
    );

    final bytes = await doc.save();
    expect(bytes, isNotEmpty);
    expect(doc.document.pdfPageList.pages.length, greaterThan(1));
  });

  test('SpanningTable rejects repeat rows without body rows', () {
    final doc = Document();

    expect(
      () => doc.addPage(
        MultiPage(
          build: (Context context) => <Widget>[
            SpanningTable(
              children: <SpanningTableRow>[
                SpanningTableRow(
                  repeat: true,
                  children: <SpanningTableCell>[
                    SpanningTableCell(child: Text('Header')),
                  ],
                ),
              ],
            ),
          ],
        ),
      ),
      _spanningTableExceptionContaining('only repeat rows'),
    );
  });

  test('SpanningTable rejects rowSpan in repeat rows', () {
    final doc = Document();

    expect(
      () => doc.addPage(
        MultiPage(
          build: (Context context) => <Widget>[
            SpanningTable(
              children: <SpanningTableRow>[
                SpanningTableRow(
                  repeat: true,
                  children: <SpanningTableCell>[
                    SpanningTableCell(rowSpan: 2, child: Text('Header')),
                  ],
                ),
                SpanningTableRow(
                  children: <SpanningTableCell>[
                    SpanningTableCell(child: Text('Body')),
                  ],
                ),
              ],
            ),
          ],
        ),
      ),
      _spanningTableExceptionContaining('repeat row 0 cannot contain rowSpan'),
    );
  });

  test('SpanningTable rejects rowSpan past table end', () {
    final doc = Document();

    expect(
      () => doc.addPage(
        MultiPage(
          build: (Context context) => <Widget>[
            SpanningTable(
              children: <SpanningTableRow>[
                SpanningTableRow(
                  children: <SpanningTableCell>[
                    SpanningTableCell(rowSpan: 3, child: Text('Too far')),
                  ],
                ),
                SpanningTableRow(
                  children: <SpanningTableCell>[
                    SpanningTableCell(child: Text('Body')),
                  ],
                ),
              ],
            ),
          ],
        ),
      ),
      _spanningTableExceptionContaining('only 2 row(s) are available'),
    );
  });

  test('SpanningTable rejects row group taller than page', () {
    final doc = Document();

    expect(
      () => doc.addPage(
        MultiPage(
          pageFormat: const PdfPageFormat(220, 120, marginAll: 10),
          maxPages: 4,
          build: (Context context) => <Widget>[
            SpanningTable(
              border: TableBorder.all(),
              children: <SpanningTableRow>[
                SpanningTableRow(
                  repeat: true,
                  children: <SpanningTableCell>[
                    SpanningTableCell(
                      padding: const EdgeInsets.all(4),
                      child: Text('Header'),
                    ),
                  ],
                ),
                SpanningTableRow(
                  children: <SpanningTableCell>[
                    SpanningTableCell(
                      padding: const EdgeInsets.all(4),
                      child: SizedBox(height: 160, child: Text('Too tall')),
                    ),
                  ],
                ),
              ],
            ),
          ],
        ),
      ),
      _spanningTableExceptionContaining(
          'taller than the available page height'),
    );
  });

  test('SpanningTable clips row group taller than page in clip mode', () async {
    final doc = Document();

    doc.addPage(
      MultiPage(
        pageFormat: const PdfPageFormat(220, 120, marginAll: 10),
        maxPages: 4,
        build: (Context context) => <Widget>[
          SpanningTable(
            overflow: SpanningTableOverflowMode.clip,
            border: TableBorder.all(),
            children: <SpanningTableRow>[
              SpanningTableRow(
                repeat: true,
                children: <SpanningTableCell>[
                  SpanningTableCell(
                    padding: const EdgeInsets.all(4),
                    child: Text('Header'),
                  ),
                ],
              ),
              SpanningTableRow(
                children: <SpanningTableCell>[
                  SpanningTableCell(
                    padding: const EdgeInsets.all(4),
                    child: SizedBox(height: 160, child: Text('Too tall')),
                  ),
                ],
              ),
              SpanningTableRow(
                children: <SpanningTableCell>[
                  SpanningTableCell(child: Text('After clipped row')),
                ],
              ),
            ],
          ),
        ],
      ),
    );

    final bytes = await doc.save();
    expect(bytes, isNotEmpty);
  });

  test('SpanningTable clip mode recovers malformed row spans', () async {
    final doc = Document();

    doc.addPage(
      MultiPage(
        maxPages: 4,
        build: (Context context) => <Widget>[
          SpanningTable(
            overflow: SpanningTableOverflowMode.clip,
            border: TableBorder.all(),
            children: <SpanningTableRow>[
              SpanningTableRow(
                repeat: true,
                children: <SpanningTableCell>[
                  SpanningTableCell(rowSpan: 2, child: Text('Header')),
                ],
              ),
              SpanningTableRow(
                children: <SpanningTableCell>[
                  SpanningTableCell(rowSpan: 10, child: Text('Body')),
                ],
              ),
            ],
          ),
        ],
      ),
    );

    final bytes = await doc.save();
    expect(bytes, isNotEmpty);
  });

  test('SpanningTable supports explicit text direction', () async {
    final doc = Document();

    doc.addPage(
      MultiPage(
        build: (Context context) => <Widget>[
          SpanningTable(
            textDirection: TextDirection.rtl,
            border: TableBorder.all(),
            children: <SpanningTableRow>[
              SpanningTableRow(
                children: <SpanningTableCell>[
                  SpanningTableCell(
                    alignment: AlignmentDirectional.centerStart,
                    padding: const EdgeInsetsDirectional.only(start: 12),
                    child: Text('RTL'),
                  ),
                ],
              ),
            ],
          ),
        ],
      ),
    );

    final bytes = await doc.save();
    expect(bytes, isNotEmpty);
  });

  test('SpanningTable.fromTextArray builds a paginated table', () async {
    final doc = Document();

    doc.addPage(
      MultiPage(
        pageFormat: const PdfPageFormat(240, 160, marginAll: 10),
        maxPages: 20,
        build: (Context context) => <Widget>[
          SpanningTable.fromTextArray(
            headers: <String>['A', 'B', 'C'],
            data: <List<dynamic>>[
              <dynamic>[
                SpanningTableCell(
                  columnSpan: 2,
                  child: Text('Merged data cell'),
                ),
                'C0',
              ],
              for (var index = 0; index < 30; index++)
                <String>['A$index', 'B$index', 'C$index'],
            ],
            border: TableBorder.all(),
            cellAlignment: Alignment.center,
            headerStyle: TextStyle(fontWeight: FontWeight.bold),
            overflow: SpanningTableOverflowMode.clip,
          ),
        ],
      ),
    );

    final bytes = await doc.save();
    expect(bytes, isNotEmpty);
    expect(doc.document.pdfPageList.pages.length, greaterThan(1));
  });

  test('SpanningTable handles 250+ pages with dense spans', () async {
    final previousDocumentDebug = Document.debug;
    final previousRichTextDebug = RichText.debug;
    Document.debug = false;
    RichText.debug = false;

    try {
      final doc = Document();

      doc.addPage(
        MultiPage(
          pageFormat: const PdfPageFormat(300, 100, marginAll: 4),
          maxPages: 320,
          build: (Context context) => <Widget>[
            SpanningTable(
              border: TableBorder.all(width: .5),
              defaultCellAlignment: Alignment.center,
              defaultVerticalAlignment: TableCellVerticalAlignment.middle,
              columnWidths: const <int, TableColumnWidth>{
                0: FixedColumnWidth(36),
                1: FractionColumnWidth(.18),
                2: FlexColumnWidth(1.4),
                3: FlexColumnWidth(),
                4: FixedColumnWidth(34),
                5: FlexColumnWidth(),
              },
              children: _buildDenseSpanningTableRows(groups: 252),
            ),
          ],
        ),
      );

      final bytes = await doc.save();
      expect(bytes, isNotEmpty);
      expect(doc.document.pdfPageList.pages.length, greaterThanOrEqualTo(250));
    } finally {
      Document.debug = previousDocumentDebug;
      RichText.debug = previousRichTextDebug;
    }
  });
}
