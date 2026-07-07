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

import 'utils.dart';

late Document pdf;

void main() {
  setUpAll(() {
    Document.debug = true;
    RichText.debug = true;
    pdf = Document();
  });

  test('Pdf Link Annotations', () async {
    pdf.addPage(
      Page(
        build: (context) => Column(
          children: [
            Link(child: Text('A link'), destination: 'destination'),
            UrlLink(
                child: Text('GitHub'),
                destination: 'https://github.com/DavBfr/dart_pdf/'),
          ],
        ),
      ),
    );
  });

  test('Pdf Link Annotations use uppercase action key', () async {
    final doc = Document();
    doc.addPage(
      Page(
        build: (context) => Column(
          children: [
            Anchor(child: Text('Destination'), name: 'destination'),
            Link(child: Text('Named destination'), destination: 'destination'),
            UrlLink(
              child: Text('Internal URL'),
              destination:
                  '/restrito/visualiza-processo/2026/26759?a=67&tab=tramites&tipo=anexo&id=41752',
            ),
          ],
        ),
      ),
    );

    final content = String.fromCharCodes(await doc.save());
    final linkObjects = _linkAnnotationObjects(content);

    expect(linkObjects, hasLength(2));
    for (final object in linkObjects) {
      expect(object, contains('/A'),
          reason: 'PDF annotation actions are case-sensitive and must use /A');
      expect(_hasLowercaseActionKey(object), isFalse,
          reason: 'Lowercase /a is not a valid Link annotation action key');
    }
    expect(
      RegExp(r'/URI\s*\(/restrito/visualiza-processo/2026/26759')
          .hasMatch(linkObjects.join('\n')),
      isTrue,
    );
  });

  test('Pdf Shape Annotations', () async {
    pdf.addPage(
      Page(
        build: (context) => Wrap(
          spacing: 20,
          runSpacing: 20,
          children: [
            SizedBox(
              width: 200,
              height: 200,
              child: CircleAnnotation(
                color: PdfColors.blue,
                author: 'David PHAM-VAN',
              ),
            ),
            SizedBox(
              width: 200,
              height: 200,
              child: SquareAnnotation(
                color: PdfColors.red,
              ),
            ),
            SizedBox(
              width: 200,
              height: 100,
              child: PolyLineAnnotation(
                points: const [
                  PdfPoint(10, 10),
                  PdfPoint(10, 30),
                  PdfPoint(50, 70)
                ],
                color: PdfColors.purple,
              ),
            ),
            SizedBox(
              width: 200,
              height: 100,
              child: PolygonAnnotation(
                points: const [
                  PdfPoint(10, 10),
                  PdfPoint(10, 30),
                  PdfPoint(50, 70)
                ],
                color: PdfColors.orange,
              ),
            ),
            SizedBox(
              width: 200,
              height: 100,
              child: InkAnnotation(
                points: const [
                  [PdfPoint(10, 10), PdfPoint(10, 30), PdfPoint(50, 70)],
                  [PdfPoint(100, 10), PdfPoint(100, 30), PdfPoint(150, 70)],
                ],
                color: PdfColors.green,
              ),
            ),
          ],
        ),
      ),
    );
  });

  test('Pdf Anchor Annotation', () async {
    pdf.addPage(Page(
      build: (context) =>
          Anchor(child: Text('The destination'), name: 'destination'),
    ));
  });

  tearDownAll(() async {
    final file = outputFile('annotations.pdf');
    await file.writeAsBytes(await pdf.save());
  });
}

List<String> _linkAnnotationObjects(String content) {
  final result = <String>[];
  var searchFrom = 0;

  while (searchFrom < content.length) {
    final objStart = content.indexOf(' obj', searchFrom);
    if (objStart < 0) break;

    final objectHeaderStart = content.lastIndexOf('\n', objStart);
    final start = objectHeaderStart < 0 ? 0 : objectHeaderStart + 1;
    final end = content.indexOf('endobj', objStart);
    if (end < 0) break;

    final object = content.substring(start, end);
    if (RegExp(r'/Subtype\s*/Link').hasMatch(object)) {
      result.add(object);
    }

    searchFrom = end + 'endobj'.length;
  }

  return result;
}

bool _hasLowercaseActionKey(String object) {
  return RegExp(r'/a(?=\s|<|/|\[|\])').hasMatch(object);
}
