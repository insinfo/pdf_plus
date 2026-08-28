import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

/// Constrói um PDF cru com uma única página, para exercitar geometrias que
/// nenhum gerador normal produz.
Uint8List rawPage({
  required String mediaBox,
  String extraPageKeys = '',
  String content = 'BT /F1 12 Tf 72 700 Td (teste) Tj ET',
}) {
  final buffer = StringBuffer();
  final offsets = <int>[];

  void object(int id, String body) {
    offsets.add(buffer.length);
    buffer.write('$id 0 obj\n$body\nendobj\n');
  }

  buffer.write('%PDF-1.4\n');
  object(1, '<< /Type /Catalog /Pages 2 0 R >>');
  object(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>');
  object(
    3,
    '<< /Type /Page /Parent 2 0 R /MediaBox $mediaBox $extraPageKeys '
    '/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
  );
  object(4, '<< /Length ${content.length} >>\nstream\n$content\nendstream');
  object(
      5, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');

  final xref = buffer.length;
  buffer.write('xref\n0 6\n0000000000 65535 f \n');
  for (final offset in offsets) {
    buffer.write('${offset.toString().padLeft(10, '0')} 00000 n \n');
  }
  buffer.write('trailer\n<< /Size 6 /Root 1 0 R >>\n'
      'startxref\n$xref\n%%EOF\n');

  return Uint8List.fromList(buffer.toString().codeUnits);
}

void main() {
  group('geometria', () {
    test('MediaBox com origem deslocada é preservado', () async {
      // PdfPageFormat só carrega largura e altura; sem tratamento, a página
      // sairia com `[0 0 595 842]` e o conteúdo deslocado.
      final source = rawPage(mediaBox: '[20 30 615 872]');
      final merged = reopen(await PdfDocument.merge(<Uint8List>[source]));

      final box = merged.resolvePageMediaBox(merged.pageDictAt(0)!)!;
      expect(box, <double>[20, 30, 615, 872]);
    });

    test('MediaBox começando na origem continua sem deslocamento', () async {
      final source = rawPage(mediaBox: '[0 0 595 842]');
      final merged = reopen(await PdfDocument.merge(<Uint8List>[source]));

      final box = merged.resolvePageMediaBox(merged.pageDictAt(0)!)!;
      expect(box[0], 0);
      expect(box[1], 0);
      expect(box[2], closeTo(595, 0.01));
    });

    test('caixa invertida é normalizada', () async {
      final source = rawPage(mediaBox: '[595 842 0 0]');
      final merged = reopen(await PdfDocument.merge(<Uint8List>[source]));

      final box = merged.resolvePageMediaBox(merged.pageDictAt(0)!)!;
      expect(box[2] - box[0], closeTo(595, 0.01));
      expect(box[3] - box[1], closeTo(842, 0.01));
    });

    test('rotação múltipla de 90 é propagada', () async {
      for (final angle in <int>[90, 180, 270]) {
        final source =
            rawPage(mediaBox: '[0 0 595 842]', extraPageKeys: '/Rotate $angle');
        final merged = reopen(await PdfDocument.merge(<Uint8List>[source]));

        final page = merged.pageDictAt(0)!;
        expect(PdfParserObjects.asInt(page.values['/Rotate']), angle,
            reason: 'rotação $angle');
      }
    });

    test('rotação fora dos múltiplos de 90 é preservada como veio', () async {
      final source =
          rawPage(mediaBox: '[0 0 595 842]', extraPageKeys: '/Rotate 45');
      final merged = reopen(await PdfDocument.merge(<Uint8List>[source]));

      final page = merged.pageDictAt(0)!;
      expect(PdfParserObjects.asInt(page.values['/Rotate']), 45);
    });

    test('/CropBox e /UserUnit acompanham a página', () async {
      final source = rawPage(
        mediaBox: '[0 0 595 842]',
        extraPageKeys: '/CropBox [10 10 585 832] /UserUnit 2',
      );
      final merged = reopen(await PdfDocument.merge(<Uint8List>[source]));

      final page = merged.pageDictAt(0)!;
      final crop = merged.resolve(page.values['/CropBox']);
      expect(crop, isA<PdfArrayToken>());
      expect(PdfParserObjects.asInt(page.values['/UserUnit']), 2);
    });

    test('atributos herdados do nó /Pages são materializados', () async {
      // MediaBox e Resources só no nó pai: ao destacar a página da árvore, eles
      // precisam ser trazidos para ela.
      final content = 'BT /F1 12 Tf 72 700 Td (herdado) Tj ET';
      final buffer = StringBuffer();
      final offsets = <int>[];
      void object(int id, String body) {
        offsets.add(buffer.length);
        buffer.write('$id 0 obj\n$body\nendobj\n');
      }

      buffer.write('%PDF-1.4\n');
      object(1, '<< /Type /Catalog /Pages 2 0 R >>');
      object(
        2,
        '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 300 400] '
        '/Resources << /Font << /F1 5 0 R >> >> >>',
      );
      object(3, '<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>');
      object(4, '<< /Length ${content.length} >>\nstream\n$content\nendstream');
      object(5, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');

      final xref = buffer.length;
      buffer.write('xref\n0 6\n0000000000 65535 f \n');
      for (final offset in offsets) {
        buffer.write('${offset.toString().padLeft(10, '0')} 00000 n \n');
      }
      buffer.write(
          'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n$xref\n%%EOF\n');

      final source = Uint8List.fromList(buffer.toString().codeUnits);
      final merged = reopen(await PdfDocument.merge(<Uint8List>[source]));

      final page = merged.pageDictAt(0)!;
      final box = merged.resolvePageMediaBox(page)!;
      expect(box[2] - box[0], closeTo(300, 0.01));
      expect(box[3] - box[1], closeTo(400, 0.01));

      // Os recursos precisam estar na própria página agora.
      final resources = merged.resolve(page.values['/Resources']);
      expect(resources, isA<PdfDictToken>());
      final fonts = merged.resolve((resources as PdfDictToken).values['/Font']);
      expect(fonts, isA<PdfDictToken>());
    });
  });

  group('robustez de entrada', () {
    test('documento com xref danificado ainda mescla', () async {
      final good = rawPage(mediaBox: '[0 0 595 842]');
      // Aponta o startxref para além do fim do arquivo.
      final broken = String.fromCharCodes(good)
          .replaceFirst(RegExp(r'startxref\n\d+'), 'startxref\n999999');
      final merged = await PdfDocument.merge(
          <Uint8List>[Uint8List.fromList(broken.codeUnits)]);

      expect(reopen(merged).pageCount, 1);
    });

    test('intervalo de páginas inválido é recusado', () {
      final document = PdfDocument();
      final merger = PdfDocumentMerger(document);
      final source = reopen(rawPage(mediaBox: '[0 0 595 842]'));

      expect(() => merger.importPageRange(source, 0, 5),
          throwsA(isA<ArgumentError>()));
      expect(() => merger.importPageRange(source, -1, 0),
          throwsA(isA<ArgumentError>()));
    });

    test('mesclar dentro de documento carregado é recusado', () {
      final loaded = PdfDocument.parseFromBytes(asset('termo.pdf'));
      expect(() => PdfDocumentMerger(loaded),
          throwsA(isA<PdfMergeException>()));
    });
  });
}
