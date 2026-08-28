import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

/// Referências que não resolvem são o modo de falha mais traiçoeiro de uma
/// mesclagem: o arquivo abre, a página aparece, e só um pedaço do documento
/// some. Estes testes percorrem o grafo inteiro da saída.
void main() {
  /// Percorre todo objeto alcançável a partir do catálogo, conferindo que cada
  /// referência indireta encontra um objeto de verdade.
  List<String> danglingReferences(PdfDocumentParser parser) {
    final problems = <String>[];
    final visited = <int>{};

    void walk(dynamic value, String path, int depth) {
      if (depth > 64) return;

      if (value is PdfRefToken) {
        final target = parser.getObject(value.obj);
        if (target == null) {
          problems.add('$path -> ${value.obj} ${value.gen} R não existe');
          return;
        }
        if (!visited.add(value.obj)) return;
        walk(target.value, '$path/${value.obj}', depth + 1);
        return;
      }

      if (value is PdfArrayToken) {
        for (var i = 0; i < value.values.length; i++) {
          walk(value.values[i], '$path[$i]', depth + 1);
        }
        return;
      }

      if (value is PdfDictToken) {
        for (final entry in value.values.entries) {
          walk(entry.value, '$path${entry.key}', depth + 1);
        }
      }
    }

    final root = parser.rootDict;
    if (root == null) return <String>['sem catálogo'];
    walk(root, '/Root', 0);
    return problems;
  }

  group('integridade referencial', () {
    for (final name in <String>[
      'termo.pdf',
      'paginador.pdf',
      '2 ass leonardo e mauricio.pdf',
      'gov_assinado.pdf',
    ]) {
      test('$name mesclado não deixa referência pendurada', () async {
        final merged = reopen(await PdfDocument.merge(<Uint8List>[asset(name)]));
        expect(danglingReferences(merged), isEmpty);
      });
    }

    test('duas origens diferentes não deixam referência pendurada', () async {
      final merged = reopen(await PdfDocument.merge(<Uint8List>[
        asset('termo.pdf'),
        asset('paginador.pdf'),
      ]));
      expect(danglingReferences(merged), isEmpty);
    });

    test('com assinaturas mantidas também não deixa', () async {
      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[asset('2 ass leonardo e mauricio.pdf')],
        options: const PdfMergeOptions(keepInvalidSignatures: true),
      ));
      expect(danglingReferences(merged), isEmpty);
    });

    test('o modo flatten também não deixa', () async {
      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[asset('termo.pdf')],
        options: const PdfMergeOptions(mode: PdfMergeMode.flatten),
      ));
      expect(danglingReferences(merged), isEmpty);
    });

    test('toda página do resultado é alcançável pela árvore /Pages', () async {
      final merged = reopen(await PdfDocument.merge(<Uint8List>[
        asset('termo.pdf'),
        asset('paginador.pdf'),
      ]));

      final refs = merged.pageRefs;
      expect(refs.length, merged.pageCount);
      for (final ref in refs) {
        final page = merged.getObject(ref.obj);
        expect(page, isNotNull);
        final dict = page!.value;
        expect(dict, isA<PdfDictToken>());
        expect(
          PdfParserObjects.asName((dict as PdfDictToken).values['/Type']),
          '/Page',
        );
        // Toda página precisa apontar de volta para a árvore do destino.
        expect(dict.values['/Parent'], isNotNull);
      }
    });

    test('nenhuma página importada aponta para a árvore da origem', () async {
      final merged = reopen(await PdfDocument.merge(<Uint8List>[
        asset('paginador.pdf'),
      ]));

      final pagesRef =
          PdfParserObjects.asRef(merged.rootDict!.values['/Pages'])!;
      for (final ref in merged.pageRefs) {
        final page = merged.getObject(ref.obj)!.value as PdfDictToken;
        final parent = PdfParserObjects.asRef(page.values['/Parent'])!;
        expect(parent.obj, pagesRef.obj);
      }
    });
  });
}
