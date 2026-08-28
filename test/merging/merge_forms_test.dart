import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

void main() {
  const withForm = 'sample3.pdf';

  group('formulários', () {
    test('todos os campos chegam ao documento mesclado', () async {
      final bytes = asset(withForm);
      final source = reopen(bytes);
      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes]));

      expect(fieldNames(source), isNotEmpty);
      expect(fieldNames(merged).length, fieldNames(source).length);
    });

    test('os nomes dos campos são preservados', () async {
      final bytes = asset(withForm);
      final source = reopen(bytes);
      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes]));

      expect(
        fieldNames(merged).toSet(),
        containsAll(fieldNames(source).toSet()),
      );
    });

    test('mesclar duas vezes desambigua os nomes em conflito', () async {
      final bytes = asset(withForm);
      final source = reopen(bytes);
      final merged =
          reopen(await PdfDocument.merge(<Uint8List>[bytes, bytes]));

      final names = fieldNames(merged);
      expect(names.length, fieldNames(source).length * 2);
      expect(names.toSet().length, names.length,
          reason: 'nenhum nome pode se repetir');
      expect(names.where((n) => n.endsWith('_2')), isNotEmpty);
    });

    test('keepFirst descarta o campo repetido', () async {
      final bytes = asset(withForm);
      final source = reopen(bytes);
      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[bytes, bytes],
        options: const PdfMergeOptions(
          fieldNameConflict: PdfFieldNameConflictPolicy.keepFirst,
        ),
      ));

      expect(fieldNames(merged).length, fieldNames(source).length);
    });

    test('throwError recusa a colisão', () {
      final bytes = asset(withForm);
      final document = PdfDocument();
      final merger = PdfDocumentMerger(
        document,
        options: const PdfMergeOptions(
          fieldNameConflict: PdfFieldNameConflictPolicy.throwError,
        ),
      );

      merger.append(reopen(bytes));
      expect(
        () => merger.append(reopen(bytes)),
        throwsA(isA<PdfMergeException>()),
      );
    });

    test('os widgets continuam ligados ao campo e à página', () async {
      final merged =
          reopen(await PdfDocument.merge(<Uint8List>[asset(withForm)]));

      final form = acroForm(merged);
      expect(form, isNotNull);
      final fields = merged.resolve(form!.values['/Fields']) as PdfArrayToken;

      var widgetsChecados = 0;
      for (final entry in fields.values) {
        final field = merged.resolve(entry);
        if (field is! PdfDictToken) continue;

        final kids = merged.resolve(field.values['/Kids']);
        if (kids is! PdfArrayToken) {
          // Campo e widget no mesmo objeto: precisa estar em alguma página.
          if (PdfParserObjects.asName(field.values['/Subtype']) == '/Widget') {
            expect(field.values['/P'], isNotNull);
            widgetsChecados++;
          }
          continue;
        }

        for (final kid in kids.values) {
          final widget = merged.resolve(kid);
          if (widget is! PdfDictToken) continue;
          expect(widget.values['/Parent'], isNotNull);
          widgetsChecados++;
        }
      }
      expect(widgetsChecados, greaterThan(0));
    });

    test('importFormFields desligado não cria /AcroForm', () async {
      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[asset(withForm)],
        options: const PdfMergeOptions(importFormFields: false),
      ));

      expect(fieldNames(merged), isEmpty);
    });

    test('/DR é mesclado sem perder os recursos do destino', () async {
      final bytes = asset(withForm);
      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes, bytes]));

      final form = acroForm(merged)!;
      final dr = merged.resolve(form.values['/DR']);
      if (dr is! PdfDictToken) return; // documento sem /DR

      final fonts = merged.resolve(dr.values['/Font']);
      if (fonts is! PdfDictToken) return;
      for (final value in fonts.values.values) {
        expect(merged.resolve(value), isA<PdfDictToken>());
      }
    });
  });
}
