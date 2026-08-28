import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/signing.dart';
import 'package:pdf_plus/src/pdf/format/base.dart';
import 'package:pdf_plus/src/pdf/format/dict.dart';
import 'package:pdf_plus/src/pdf/format/string.dart';
import 'package:pdf_plus/src/pdf/obj/object.dart';
import 'package:test/test.dart';

import '../merging/merge_helpers.dart';

/// Quantas vezes [needle] aparece nos bytes do arquivo.
///
/// A varredura é sobre o arquivo cru de propósito: é assim que se enxerga o
/// que sobrou de revisões antigas, que a leitura pelo xref não mostra.
int occurrences(Uint8List bytes, String needle) {
  final text = String.fromCharCodes(bytes);
  var found = 0;
  var index = 0;
  while (true) {
    final at = text.indexOf(needle, index);
    if (at < 0) return found;
    found++;
    index = at + 1;
  }
}

void main() {
  group('regravação — fidelidade', () {
    test('o resultado recarrega com a mesma contagem de páginas', () async {
      final source = await buildTextPdf(pageCount: 4, prefix: 'Folha');
      final result = await PdfDocumentRewriter().rewriteBytes(source);

      expect(result.report.pagesBefore, 4);
      expect(result.report.pagesAfter, 4);
      expect(reopen(result.bytes).pageCount, 4);
    });

    test('o conteúdo decodificado de cada página é idêntico', () async {
      final source = asset('termo.pdf');
      final rewritten = await PdfDocumentRewriter.rewrite(source);

      final before = reopen(source);
      final after = reopen(rewritten);
      expect(after.pageCount, before.pageCount);
      for (var i = 0; i < before.pageCount; i++) {
        expect(
          decodedPageContent(after, i),
          decodedPageContent(before, i),
          reason: 'página ${i + 1}',
        );
      }
    });

    test('regravar duas vezes é estável', () async {
      final source = asset('termo.pdf');
      final once = await PdfDocumentRewriter.rewrite(source);
      final twice = await PdfDocumentRewriter.rewrite(once);

      final first = reopen(once);
      final second = reopen(twice);
      expect(second.pageCount, first.pageCount);
      for (var i = 0; i < first.pageCount; i++) {
        expect(decodedPageContent(second, i), decodedPageContent(first, i));
      }
      // A segunda passagem já não tem lixo para descartar.
      expect(twice.length, lessThanOrEqualTo(once.length + 512));
    });
  });

  group('regravação — coleta de lixo', () {
    test('objeto órfão não sobrevive à regravação', () async {
      final base = await buildTextPdf(pageCount: 1);

      // Um objeto indireto que ninguém referencia: ele é escrito no
      // incremental update e continua no xref, mas está fora do grafo que
      // começa no catálogo.
      final loaded = PdfDocument.parseFromBytes(base);
      PdfObject<PdfDict>(
        loaded,
        params: PdfDict.values(<String, PdfDataType>{
          '/Type': const PdfName('/OrfaoDeTeste'),
          '/Marca': PdfString.fromString('SEGREDO-ORFAO-42'),
        }),
      );
      final withOrphan = await loaded.save(useIsolate: false);

      expect(
        occurrences(withOrphan, 'SEGREDO-ORFAO-42'),
        greaterThan(0),
        reason: 'o órfão precisa existir antes para o teste valer',
      );

      final result = await PdfDocumentRewriter().rewriteBytes(withOrphan);

      expect(occurrences(result.bytes, 'SEGREDO-ORFAO-42'), 0);
      expect(occurrences(result.bytes, '/OrfaoDeTeste'), 0);
      expect(result.report.objectsAfter, lessThan(result.report.objectsBefore));
      expect(result.report.pagesAfter, 1);
      expect(reopen(result.bytes).pageCount, 1);
    });

    test('o relatório fecha com os bytes devolvidos', () async {
      final source = await buildTextPdf(pageCount: 2);
      final result = await PdfDocumentRewriter().rewriteBytes(source);

      expect(result.report.bytesBefore, source.length);
      expect(result.report.bytesAfter, result.bytes.length);
      expect(
        result.report.bytesSaved,
        result.report.bytesBefore - result.report.bytesAfter,
      );
      expect(result.report.sizeRatio, closeTo(
          result.report.bytesAfter / result.report.bytesBefore, 1e-9));
      expect(result.report.signatureFieldsBefore, 0);
      expect(result.report.invalidatedSignatures, isFalse);
      expect(result.report.warnings, isEmpty);
    });
  });

  group('regravação — revisões superseded', () {
    // `3 ass.pdf` tem 3 campos de assinatura, mas 4 ocorrências de
    // `/ByteRange` nos bytes: a quarta é de uma revisão que foi substituída e
    // ficou para trás no arquivo. Nenhuma leitura pelo xref a enxerga; ela só
    // aparece varrendo os bytes.
    const name = '3 ass.pdf';

    test('a origem realmente carrega uma revisão a mais', () {
      final source = asset(name);
      expect(occurrences(source, '/ByteRange'), 4);
      expect(reopen(source).extractSignatureFields(), hasLength(3));
    });

    test('a política padrão não deixa nenhuma estrutura de assinatura',
        () async {
      final source = asset(name);
      final result = await PdfDocumentRewriter().rewriteBytes(source);

      // Nem as 3 alcançáveis, nem a 4ª superseded.
      expect(occurrences(result.bytes, '/ByteRange'), 0);
      expect(reopen(result.bytes).extractSignatureFields(), isEmpty);
      expect(result.report.signatureFieldsBefore, 3);
      expect(result.report.invalidatedSignatures, isTrue);
      expect(result.report.pagesAfter, result.report.pagesBefore);
    });

    test('mantendo as assinaturas, só sobram as 3 alcançáveis', () async {
      final source = asset(name);
      final result = await PdfDocumentRewriter(
        options: const PdfRewriteOptions(keepInvalidSignatures: true),
      ).rewriteBytes(source);

      // 4 -> 3: a revisão superseded não é alcançável a partir do catálogo,
      // então não foi importada.
      expect(occurrences(result.bytes, '/ByteRange'), 3);
      expect(reopen(result.bytes).extractSignatureFields(), hasLength(3));
    });

    test('as assinaturas mantidas não conferem mais', () async {
      final source = asset(name);
      final result = await PdfDocumentRewriter(
        options: const PdfRewriteOptions(keepInvalidSignatures: true),
      ).rewriteBytes(source);

      final report =
          await PdfSignatureValidator().validateAllSignatures(result.bytes);
      expect(report.signatures, hasLength(3));
      for (final signature in report.signatures) {
        expect(signature.intact, isFalse,
            reason: 'regravar quebra toda assinatura existente');
      }
    });

    test('rejectSignedSources recusa antes de regravar', () async {
      final source = asset(name);
      await expectLater(
        PdfDocumentRewriter(
          options: const PdfRewriteOptions(rejectSignedSources: true),
        ).rewriteBytes(source),
        throwsA(isA<PdfMergeException>()),
      );
    });
  });

  group('regravação — tamanho', () {
    test('um documento com muitas revisões incrementais encolhe', () async {
      // 18 seções de xref encadeadas e 12 assinaturas: quase todo o arquivo é
      // revisão antiga.
      final source = asset('12 assinaturas.pdf');
      final result = await PdfDocumentRewriter().rewriteBytes(source);

      expect(result.report.bytesBefore, 1555548);
      // Medido: 1.555.548 -> ~226 KB, cerca de 15% do original.
      expect(result.report.bytesAfter, lessThan(400 * 1024));
      expect(result.report.sizeRatio, lessThan(0.30));
      expect(result.report.bytesSaved, greaterThan(1000 * 1024));

      // Encolher não pode custar página.
      expect(result.report.pagesAfter, result.report.pagesBefore);
      expect(reopen(result.bytes).pageCount, result.report.pagesBefore);
    });

    test('o número de objetos vivos cai junto', () async {
      final source = asset('10 assinaturas.pdf');
      final result = await PdfDocumentRewriter().rewriteBytes(source);

      expect(result.report.objectsAfter,
          lessThan(result.report.objectsBefore));
      expect(result.report.bytesAfter, lessThan(result.report.bytesBefore));
      expect(result.report.pagesAfter, result.report.pagesBefore);
    });
  });

  group('regravação — o que fazer depois', () {
    test('o documento regravado abre e aceita edição incremental', () async {
      final rewritten = await PdfDocumentRewriter.rewrite(asset('termo.pdf'));

      final document = PdfDocument.parseFromBytes(rewritten);
      document.addUriAnnotation(
        pageNumber: 1,
        bounds: const PdfRect(10, 10, 100, 20),
        uri: 'https://example.org/depois-da-regravacao',
      );
      final updated = await document.save(useIsolate: false);

      expect(reopen(updated).pageCount, reopen(rewritten).pageCount);
      expect(
        String.fromCharCodes(updated)
            .contains('https://example.org/depois-da-regravacao'),
        isTrue,
      );
    });

    test('o documento regravado ainda pode ser assinado depois', () async {
      // Caso de uso real: sanear o arquivo e só então assinar o resultado.
      final rewritten = await PdfDocumentRewriter.rewrite(asset('termo.pdf'));

      final document = PdfDocument.parseFromBytes(rewritten);
      document.addSignatureField(
        pageNumber: 1,
        bounds: const PdfRect(40, 40, 200, 60),
        fieldName: 'AssinaturaDepoisDaRegravacao',
      );
      final prepared = await document.save(useIsolate: false);

      final fields = reopen(prepared).extractSignatureFields();
      expect(
        fields.map((f) => f.fieldName),
        contains('AssinaturaDepoisDaRegravacao'),
      );
    });

    test('a saída não tem assinatura pendente inesperada', () async {
      final rewritten = await PdfDocumentRewriter.rewrite(asset('termo.pdf'));
      final report =
          await PdfSignatureValidator().validateAllSignatures(rewritten);
      expect(report.signatures, isEmpty);
    });
  });

  group('regravação — opções de preservação', () {
    test('por padrão /Info e /Metadata continuam no arquivo', () async {
      final source = asset('termo.pdf');
      final before = reopen(source);
      expect(before.rootDict?.values.containsKey('/Metadata'), isTrue);
      expect(before.trailer.infoObj, isNotNull);

      final result = await PdfDocumentRewriter().rewriteBytes(source);
      final after = reopen(result.bytes);
      expect(after.rootDict?.values.containsKey('/Metadata'), isTrue);
      expect(after.trailer.infoObj, isNotNull);
    });

    test('desligar as chaves apaga /Info e /Metadata', () async {
      final source = asset('termo.pdf');
      final result = await PdfDocumentRewriter(
        options: const PdfRewriteOptions(
          keepDocumentInfo: false,
          keepXmpMetadata: false,
        ),
      ).rewriteBytes(source);

      final after = reopen(result.bytes);
      expect(after.rootDict?.values.containsKey('/Metadata'), isFalse);
      expect(after.trailer.infoObj, isNull);
    });

    test('o perfil saneado descarta metadados e o carimbo de assinatura',
        () async {
      final source = asset('3 ass.pdf');
      final result = await PdfDocumentRewriter(
        options: const PdfRewriteOptions.sanitized(),
      ).rewriteBytes(source);

      final after = reopen(result.bytes);
      expect(after.rootDict?.values.containsKey('/Metadata'), isFalse);
      expect(after.trailer.infoObj, isNull);
      expect(occurrences(result.bytes, '/ByteRange'), 0);
      expect(after.pageCount, result.report.pagesBefore);
    });

    test('a marcação estrutural só volta quando pedida', () async {
      // `sample3.pdf` é tagged: a árvore existe e é alcançável.
      final source = asset('sample3.pdf');
      expect(
        reopen(source).rootDict?.values.containsKey('/StructTreeRoot'),
        isTrue,
      );

      final dropped = await PdfDocumentRewriter().rewriteBytes(source);
      expect(
        reopen(dropped.bytes).rootDict?.values.containsKey('/StructTreeRoot'),
        isFalse,
      );
      expect(
        dropped.report.warnings,
        contains(contains('marcação estrutural')),
      );

      final kept = await PdfDocumentRewriter(
        options: const PdfRewriteOptions(keepStructureTree: true),
      ).rewriteBytes(source);
      expect(
        reopen(kept.bytes).rootDict?.values.containsKey('/StructTreeRoot'),
        isTrue,
      );
      expect(reopen(kept.bytes).pageCount, kept.report.pagesBefore);
    }, timeout: const Timeout(Duration(minutes: 3)));

    test('toMergeOptions espelha as chaves de assinatura', () {
      const options = PdfRewriteOptions(
        rejectSignedSources: true,
        keepInvalidSignatures: true,
        removeSignatureAppearance: true,
        keepBookmarks: false,
        keepAttachments: false,
      );
      final merge = options.toMergeOptions();

      expect(merge.rejectSignedSources, isTrue);
      expect(merge.keepInvalidSignatures, isTrue);
      expect(merge.removeSignatureAppearance, isTrue);
      expect(merge.importBookmarks, isFalse);
      expect(merge.importAttachments, isFalse);
      expect(merge.dropStructureTree, isTrue);
    });

    test('copyWith troca só o que foi informado', () {
      const base = PdfRewriteOptions();
      final changed = base.copyWith(keepXmpMetadata: false);

      expect(changed.keepXmpMetadata, isFalse);
      expect(changed.keepDocumentInfo, base.keepDocumentInfo);
      expect(changed.keepBookmarks, base.keepBookmarks);
    });
  });
}
