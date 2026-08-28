import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:test/test.dart';

import 'merge_helpers.dart';

/// Comparação com o sistema de referência do usuário final desta biblioteca.
///
/// O SEI (Sistema Eletrônico de Informações) tem a função "Gerar Arquivo PDF do
/// Processo", que mescla os documentos de um processo com o Apache PDFBox. As
/// entradas reais de um processo e o consolidado que o SEI produziu estão em
/// `test/assets/merge/`.
///
/// O quarto documento do processo é um HTML que o SEI renderiza na hora da
/// mesclagem; renderizar HTML não é função desta biblioteca, então a comparação
/// é de 41 páginas contra as 42 do SEI e olha a estrutura, não a contagem.
void main() {
  final sources = <String>[
    'sei_source_relatorio.pdf',
    'sei_source_signed_invisible.pdf',
    'sei_source_signed_visible.pdf',
  ];

  Future<Uint8List> mergeSources({PdfMergeOptions? options}) async {
    return PdfDocument.merge(
      sources.map(mergeAsset).toList(),
      options: options,
    );
  }

  group('compatibilidade com o SEI', () {
    test('as entradas somam as páginas esperadas', () {
      final total = sources
          .map((name) => reopen(mergeAsset(name)).pageCount)
          .reduce((a, b) => a + b);
      expect(total, 41);

      final reference = reopen(mergeAsset('sei_merged_reference.pdf'));
      expect(reference.pageCount, 42, reason: 'a 42ª página vem do HTML');
    });

    test('a mesclagem cobre as três entradas', () async {
      final merged = reopen(await mergeSources());
      expect(merged.pageCount, 41);
    });

    test('keepInvalidSignatures reproduz o que o SEI entrega', () async {
      final reference = reopen(mergeAsset('sei_merged_reference.pdf'));
      expect(reference.extractSignatureFields().length, 2);

      final merged = reopen(await mergeSources(
        options: const PdfMergeOptions(keepInvalidSignatures: true),
      ));
      expect(merged.extractSignatureFields().length, 2);
    });

    test('a assinatura sem widget não se perde', () async {
      // A `sei_source_signed_invisible.pdf` traz `Signature1` com
      // `/Rect [0 0 0 0]` e sem widget em `/Annots`. Quem descobre campos só
      // pelas páginas perde essa assinatura — foi o que aconteceu na primeira
      // versão da biblioteca irmã.
      final merged = reopen(await mergeSources(
        options: const PdfMergeOptions(keepInvalidSignatures: true),
      ));

      final names = merged
          .extractSignatureFields()
          .map((f) => f.fieldName)
          .whereType<String>()
          .toList();
      expect(names.length, 2);
    });

    test('a colisão de nomes preserva o nome original', () async {
      // O SEI renomeia para `dummyFieldName1`, perdendo o nome original; aqui o
      // segundo campo vira `Signature1_2`.
      final reference = reopen(mergeAsset('sei_merged_reference.pdf'));
      expect(fieldNames(reference), containsAll(<String>['dummyFieldName1']));

      final merged = reopen(await mergeSources(
        options: const PdfMergeOptions(keepInvalidSignatures: true),
      ));
      final names = fieldNames(merged);
      expect(names, contains('Signature1'));
      expect(names.any((n) => n.startsWith('Signature1_')), isTrue);
    });

    test('o /ByteRange é mantido verbatim, como no consolidado do SEI',
        () async {
      final merged = reopen(await mergeSources(
        options: const PdfMergeOptions(keepInvalidSignatures: true),
      ));

      final originals = <List<int>>[];
      for (final name in sources) {
        for (final field in reopen(mergeAsset(name)).extractSignatureFields()) {
          if (field.byteRange != null) originals.add(field.byteRange!);
        }
      }
      final kept = merged
          .extractSignatureFields()
          .map((f) => f.byteRange)
          .whereType<List<int>>()
          .toList();

      expect(kept.length, originals.length);
      for (final range in originals) {
        expect(kept.any((k) => k.join(',') == range.join(',')), isTrue);
      }
    });

    test('no padrão, o consolidado não tem assinatura para nenhum validador',
        () async {
      // A diferença que importa: o SEI entrega um arquivo que todo validador
      // marca como inválido; o padrão daqui entrega um que ninguém acusa,
      // porque não sobrou assinatura — mantendo o carimbo visual.
      final merged = reopen(await mergeSources());
      expect(merged.extractSignatureFields(), isEmpty);
    });
  });
}
