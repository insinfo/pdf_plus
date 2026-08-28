import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/signing.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

/// Assinatura digital cobre os bytes exatos do documento em que foi aplicada.
/// Mesclar reescreve o arquivo inteiro, então toda assinatura existente deixa
/// de conferir — não há como contornar. O que se escolhe é o desfecho.
void main() {
  const signed = '2 ass leonardo e mauricio.pdf';

  group('política padrão', () {
    test('não sobra assinatura para nenhum validador conferir', () async {
      final merged = await PdfDocument.merge(<Uint8List>[asset(signed)]);

      expect(reopen(merged).extractSignatureFields(), isEmpty);
      final report =
          await PdfSignatureValidator().validateAllSignatures(merged);
      expect(report.signatures, isEmpty);
    });

    test('a marca visual continua na página, como carimbo somente-leitura',
        () async {
      final merged = reopen(await PdfDocument.merge(<Uint8List>[asset(signed)]));

      var stamps = 0;
      for (var i = 0; i < merged.pageCount; i++) {
        for (final annot in annotationsOf(merged, i)) {
          if (PdfParserObjects.asName(annot.values['/Subtype']) != '/Stamp') {
            continue;
          }
          stamps++;
          // Bit 7 de /F: somente leitura.
          final flags = PdfParserObjects.asInt(annot.values['/F']) ?? 0;
          expect(flags & 64, 64);
          expect(annot.values['/FT'], isNull);
          expect(annot.values['/V'], isNull);
        }
      }
      expect(stamps, greaterThan(0));
    });

    test('o PKCS#7 não fica como objeto órfão no arquivo', () async {
      final source = asset(signed);
      final merged = await PdfDocument.merge(<Uint8List>[source]);

      // O blob da assinatura tem dezenas de KB; se tivesse sido importado e
      // apenas desreferenciado, o arquivo cresceria sem motivo.
      expect(merged.length, lessThan(source.length));

      final parser = reopen(merged);
      for (final id in parser.objectIds) {
        final object = parser.getObject(id);
        final value = object?.value;
        if (value is! PdfDictToken) continue;
        expect(
          PdfParserObjects.asName(value.values['/Type']),
          isNot('/Sig'),
          reason: 'objeto $id ainda é um dicionário de assinatura',
        );
      }
    });

    test('a mesclagem avisa o que aconteceu', () async {
      final document = PdfDocument();
      final merger = PdfDocumentMerger(document);
      merger.append(reopen(asset(signed)));
      merger.finish();
      await document.save(useIsolate: false);

      expect(
        merger.warnings.any((w) => w.contains('assinatura digital')),
        isTrue,
      );
    });
  });

  group('keepInvalidSignatures', () {
    test('mantém os campos e o validador volta a enxergá-los', () async {
      final source = asset(signed);
      final before = reopen(source).extractSignatureFields();

      final merged = await PdfDocument.merge(
        <Uint8List>[source],
        options: const PdfMergeOptions(keepInvalidSignatures: true),
      );

      final after = reopen(merged).extractSignatureFields();
      expect(after.length, before.length);
      expect(
        after.map((f) => f.fieldName).toList(),
        before.map((f) => f.fieldName).toList(),
      );

      final report =
          await PdfSignatureValidator().validateAllSignatures(merged);
      expect(report.signatures.length, before.length);
    });

    test('as assinaturas mantidas são reportadas como inválidas', () async {
      final merged = await PdfDocument.merge(
        <Uint8List>[asset(signed)],
        options: const PdfMergeOptions(keepInvalidSignatures: true),
      );

      final report =
          await PdfSignatureValidator().validateAllSignatures(merged);
      expect(report.signatures, isNotEmpty);
      for (final signature in report.signatures) {
        expect(signature.cmsValid, isFalse);
        expect(signature.digestValid, isFalse);
      }
    });

    test('o /ByteRange é mantido verbatim, como faz o SEI', () async {
      final source = asset(signed);
      final before = reopen(source).extractSignatureFields();
      final merged = await PdfDocument.merge(
        <Uint8List>[source],
        options: const PdfMergeOptions(keepInvalidSignatures: true),
      );
      final after = reopen(merged).extractSignatureFields();

      for (var i = 0; i < before.length; i++) {
        expect(after[i].byteRange, before[i].byteRange);
      }
    });

    test('o dicionário de assinatura chega inteiro, com o CMS', () async {
      final merged = await PdfDocument.merge(
        <Uint8List>[asset(signed)],
        options: const PdfMergeOptions(keepInvalidSignatures: true),
      );
      final parser = reopen(merged);
      final form = acroForm(parser)!;
      final fields = parser.resolve(form.values['/Fields']) as PdfArrayToken;

      for (final entry in fields.values) {
        final field = parser.resolve(entry) as PdfDictToken;
        final value = parser.resolve(field.values['/V']);
        expect(value, isA<PdfDictToken>());
        final dict = value as PdfDictToken;
        expect(dict.values['/Contents'], isNotNull);
        expect(dict.values['/ByteRange'], isNotNull);
      }
    });
  });

  group('outras políticas', () {
    test('rejectSignedSources recusa a origem assinada', () {
      final document = PdfDocument();
      final merger = PdfDocumentMerger(
        document,
        options: const PdfMergeOptions(rejectSignedSources: true),
      );

      expect(
        () => merger.append(reopen(asset(signed))),
        throwsA(isA<PdfMergeException>()),
      );
    });

    test('rejectSignedSources deixa passar documento sem assinatura', () async {
      final plain = await buildTextPdf(pageCount: 1);
      final merged = await PdfDocument.merge(
        <Uint8List>[plain],
        options: const PdfMergeOptions(rejectSignedSources: true),
      );
      expect(reopen(merged).pageCount, 1);
    });

    test('removeSignatureAppearance apaga também o carimbo', () async {
      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[asset(signed)],
        options: const PdfMergeOptions(removeSignatureAppearance: true),
      ));

      for (var i = 0; i < merged.pageCount; i++) {
        for (final annot in annotationsOf(merged, i)) {
          expect(
            PdfParserObjects.asName(annot.values['/Subtype']),
            isNot('/Stamp'),
          );
        }
      }
    });

    test('keepInvalidSignatures tem precedência sobre removeSignatureAppearance',
        () async {
      final merged = await PdfDocument.merge(
        <Uint8List>[asset(signed)],
        options: const PdfMergeOptions(
          keepInvalidSignatures: true,
          removeSignatureAppearance: true,
        ),
      );
      expect(reopen(merged).extractSignatureFields(), isNotEmpty);
    });
  });

  group('assinatura sem widget', () {
    // `/AcroForm /Fields` pode conter um campo que nenhuma página mostra — uma
    // assinatura invisível, a forma que os documentos exportados pelo SEI têm.
    // Descobrir campos apenas pelas anotações das páginas os perderia.
    test('a assinatura invisível do SEI sobrevive à mesclagem', () async {
      final source = mergeAsset('sei_source_signed_invisible.pdf');
      expect(reopen(source).extractSignatureFields().length, 1);

      final merged = await PdfDocument.merge(
        <Uint8List>[source],
        options: const PdfMergeOptions(keepInvalidSignatures: true),
      );
      expect(reopen(merged).extractSignatureFields().length, 1);
    });
  });
}
