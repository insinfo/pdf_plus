import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';
import 'package:pdf_plus/src/pdf/parsing/parser_objects.dart';
import 'package:pdf_plus/src/pdf/parsing/pdf_parser_types.dart';
import 'package:pdf_plus/widgets.dart' as pw;
import 'package:test/test.dart';

import 'merge_helpers.dart';

/// Constrói um PDF cru com uma única camada (grupo de conteúdo opcional).
///
/// Nenhum gerador desta biblioteca emite `/OCProperties`, e o corpus de teste
/// também não tem um arquivo com `/OCGs` de verdade — `sample3.pdf` traz
/// `/OCProperties << /D … >>` sem grupo nenhum. Por isso a fixture é montada à
/// mão, no mesmo estilo de `rawPage` em `merge_geometry_test.dart`.
Uint8List rawLayeredPage({
  required String layerName,
  bool visible = true,
  String configName = 'Padrao',
}) {
  final buffer = StringBuffer();
  final offsets = <int>[];

  void object(int id, String body) {
    offsets.add(buffer.length);
    buffer.write('$id 0 obj\n$body\nendobj\n');
  }

  // O conteúdo fica dentro de um bloco marcado como pertencente ao OCG,
  // referenciado pelo nome `/MC0` declarado em `/Resources /Properties`.
  const content =
      'q /OC /MC0 BDC BT /F1 12 Tf 72 700 Td (conteudo em camada) Tj ET EMC Q';
  final state = visible ? '/ON [6 0 R]' : '/OFF [6 0 R]';

  buffer.write('%PDF-1.5\n');
  object(
    1,
    '<< /Type /Catalog /Pages 2 0 R /OCProperties << /OCGs [6 0 R] '
    '/D << /Order [6 0 R] $state /Name ($configName) >> >> >>',
  );
  object(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>');
  object(
    3,
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] '
    '/Resources << /Font << /F1 5 0 R >> /Properties << /MC0 6 0 R >> >> '
    '/Contents 4 0 R >>',
  );
  object(4, '<< /Length ${content.length} >>\nstream\n$content\nendstream');
  object(5, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  object(6, '<< /Type /OCG /Name ($layerName) >>');

  final xref = buffer.length;
  buffer.write('xref\n0 7\n0000000000 65535 f \n');
  for (final offset in offsets) {
    buffer.write('${offset.toString().padLeft(10, '0')} 00000 n \n');
  }
  buffer.write('trailer\n<< /Size 7 /Root 1 0 R >>\n'
      'startxref\n$xref\n%%EOF\n');

  return Uint8List.fromList(buffer.toString().codeUnits);
}

/// Dicionário `/OCProperties` do catálogo, se houver.
PdfDictToken? optionalContent(PdfDocumentParser parser) {
  final root = parser.rootDict;
  if (root == null) return null;
  final oc = parser.resolve(root.values['/OCProperties']);
  return oc is PdfDictToken ? oc : null;
}

/// Nomes dos grupos listados em `/OCProperties /OCGs`, em ordem.
List<String> layerNames(PdfDocumentParser parser) {
  final oc = optionalContent(parser);
  if (oc == null) return const <String>[];
  return _namesOfArray(parser, oc.values['/OCGs']);
}

/// Nomes dos grupos citados por uma chave da configuração padrão (`/D`).
List<String> defaultConfigNames(PdfDocumentParser parser, String key) {
  final oc = optionalContent(parser);
  if (oc == null) return const <String>[];
  final config = parser.resolve(oc.values['/D']);
  if (config is! PdfDictToken) return const <String>[];
  return _namesOfArray(parser, config.values[key]);
}

List<String> _namesOfArray(PdfDocumentParser parser, dynamic value) {
  final array = parser.resolve(value);
  if (array is! PdfArrayToken) return const <String>[];
  final names = <String>[];
  for (final entry in array.values) {
    final group = parser.resolve(entry);
    if (group is! PdfDictToken) continue;
    final name = parser.resolve(group.values['/Name']);
    names.add(name is PdfStringToken
        ? String.fromCharCodes(name.bytes)
        : '(anonimo)');
  }
  return names;
}

/// Nome do grupo que a página [pageIndex] cita em `/Resources /Properties`.
String? layerOfPage(PdfDocumentParser parser, int pageIndex) {
  final page = parser.pageDictAt(pageIndex);
  if (page == null) return null;
  final resources = parser.resolve(page.values['/Resources']);
  if (resources is! PdfDictToken) return null;
  final properties = parser.resolve(resources.values['/Properties']);
  if (properties is! PdfDictToken) return null;
  for (final entry in properties.values.values) {
    final group = parser.resolve(entry);
    if (group is! PdfDictToken) continue;
    final name = parser.resolve(group.values['/Name']);
    if (name is PdfStringToken) return String.fromCharCodes(name.bytes);
  }
  return null;
}

/// Gera um PDF com [pageCount] páginas e a numeração descrita em [labels].
Future<Uint8List> buildLabelledPdf({
  required int pageCount,
  required Map<int, PdfPageLabel> labels,
}) async {
  final document = pw.Document();
  for (var i = 0; i < pageCount; i++) {
    document.addPage(
      pw.Page(build: (context) => pw.Center(child: pw.Text('pagina $i'))),
    );
  }
  document.document.pageLabels.labels.addAll(labels);
  return document.save();
}

/// Faixas de `/PageLabels`, como pares `índice inicial -> descrição`.
///
/// A descrição junta estilo (`/S`), prefixo (`/P`) e primeiro número (`/St`),
/// que é o que interessa comparar depois da mesclagem.
Map<int, String> pageLabelRanges(PdfDocumentParser parser) {
  final root = parser.rootDict;
  if (root == null) return const <int, String>{};
  final labels = parser.resolve(root.values['/PageLabels']);
  if (labels is! PdfDictToken) return const <int, String>{};
  final nums = parser.resolve(labels.values['/Nums']);
  if (nums is! PdfArrayToken) return const <int, String>{};

  final ranges = <int, String>{};
  for (var i = 0; i + 1 < nums.values.length; i += 2) {
    final index = PdfParserObjects.asInt(nums.values[i]);
    final entry = parser.resolve(nums.values[i + 1]);
    if (index == null || entry is! PdfDictToken) continue;

    final style = PdfParserObjects.asName(entry.values['/S']) ?? '-';
    final prefixToken = parser.resolve(entry.values['/P']);
    final prefix = prefixToken is PdfStringToken
        ? String.fromCharCodes(prefixToken.bytes)
        : '';
    final start = PdfParserObjects.asInt(entry.values['/St']);
    ranges[index] = '$style|$prefix|${start ?? '-'}';
  }
  return ranges;
}

void main() {
  group('camadas (/OCProperties)', () {
    test('os grupos das duas origens chegam ao documento mesclado', () async {
      final merged = reopen(await PdfDocument.merge(<Uint8List>[
        rawLayeredPage(layerName: 'Camada A'),
        rawLayeredPage(layerName: 'Camada B'),
      ]));

      expect(merged.pageCount, 2);
      expect(layerNames(merged), <String>['Camada A', 'Camada B']);
    });

    test('/Order e /ON da configuração padrão acumulam as origens', () async {
      final merged = reopen(await PdfDocument.merge(<Uint8List>[
        rawLayeredPage(layerName: 'Camada A'),
        rawLayeredPage(layerName: 'Camada B'),
      ]));

      expect(defaultConfigNames(merged, '/Order'),
          <String>['Camada A', 'Camada B']);
      expect(
          defaultConfigNames(merged, '/ON'), <String>['Camada A', 'Camada B']);
    });

    test('/OFF é preservado separadamente de /ON', () async {
      final merged = reopen(await PdfDocument.merge(<Uint8List>[
        rawLayeredPage(layerName: 'Visivel'),
        rawLayeredPage(layerName: 'Oculta', visible: false),
      ]));

      expect(defaultConfigNames(merged, '/ON'), <String>['Visivel']);
      expect(defaultConfigNames(merged, '/OFF'), <String>['Oculta']);
    });

    test('cada página continua ligada ao próprio grupo', () async {
      // O importador materializa um OCG novo por origem; as páginas não podem
      // acabar apontando todas para o primeiro grupo.
      final merged = reopen(await PdfDocument.merge(<Uint8List>[
        rawLayeredPage(layerName: 'Camada A'),
        rawLayeredPage(layerName: 'Camada B'),
      ]));

      expect(layerOfPage(merged, 0), 'Camada A');
      expect(layerOfPage(merged, 1), 'Camada B');
    });

    test('mesclar o mesmo documento duas vezes duplica o grupo', () async {
      // Os OCGs são objetos de identidade: duas cópias da mesma página são duas
      // camadas independentes, ligáveis e desligáveis em separado. A
      // deduplicação de recursos não vale aqui — ela só junta streams.
      final source = rawLayeredPage(layerName: 'Camada');
      final merged =
          reopen(await PdfDocument.merge(<Uint8List>[source, source]));

      expect(layerNames(merged), <String>['Camada', 'Camada']);

      final oc = optionalContent(merged)!;
      final ocgs = merged.resolve(oc.values['/OCGs']) as PdfArrayToken;
      final ids = ocgs.values
          .map(PdfParserObjects.asRef)
          .map((ref) => ref?.obj)
          .toSet();
      expect(ids.length, 2,
          reason: 'os dois grupos precisam ser objetos distintos');
    });

    test('o nome da configuração da origem não é herdado', () async {
      // `/D /Name` descreve a configuração do documento inteiro; herdar o nome
      // de uma das origens descreveria mal o resultado.
      final merged = reopen(await PdfDocument.merge(<Uint8List>[
        rawLayeredPage(layerName: 'Camada A', configName: 'Config da origem'),
      ]));

      final oc = optionalContent(merged)!;
      final config = merged.resolve(oc.values['/D']) as PdfDictToken;
      expect(config.values.containsKey('/Name'), isFalse);
    });

    test('importLayers: false descarta /OCProperties', () async {
      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[rawLayeredPage(layerName: 'Camada A')],
        options: const PdfMergeOptions(importLayers: false),
      ));

      expect(merged.rootDict!.values.containsKey('/OCProperties'), isFalse);
      // A página segue no lugar: desligar a importação de camadas não descarta
      // conteúdo, só a declaração de nível de documento.
      expect(merged.pageCount, 1);
    });

    test('documento sem camadas não ganha /OCProperties', () async {
      final merged = reopen(await PdfDocument.merge(
          <Uint8List>[await buildTextPdf(pageCount: 1)]));

      expect(merged.rootDict!.values.containsKey('/OCProperties'), isFalse);
    });

    test('/OCProperties sem /OCGs na origem sai sem /OCGs no destino',
        () async {
      // Comportamento REAL observado, e não o que a especificação pede:
      // `sample3.pdf` traz `/OCProperties << /D << … >> >>` sem `/OCGs`, e o
      // resultado repete a omissão. A ISO 32000-1 lista `/OCGs` como
      // obrigatório, mas como não existe grupo nenhum para listar o desvio é
      // inócuo — nenhum visualizador tem o que exibir. Vale fixar aqui para que
      // a omissão seja notada se um dia passar a importar `/OCGs` de verdade.
      final bytes = asset('sample3.pdf');
      final source = reopen(bytes);
      expect(optionalContent(source)!.values.containsKey('/OCGs'), isFalse,
          reason: 'premissa da fixture');

      final merged = reopen(await PdfDocument.merge(<Uint8List>[bytes]));
      final oc = optionalContent(merged);
      expect(oc, isNotNull);
      expect(oc!.values.containsKey('/OCGs'), isFalse);
    });

    test('a mesclagem do mesclado mantém as camadas', () async {
      final once = await PdfDocument.merge(<Uint8List>[
        rawLayeredPage(layerName: 'Camada A'),
        rawLayeredPage(layerName: 'Camada B'),
      ]);
      final twice = reopen(await PdfDocument.merge(<Uint8List>[once]));

      expect(layerNames(twice), <String>['Camada A', 'Camada B']);
      expect(layerOfPage(twice, 1), 'Camada B');
    });
  });

  group('numeração de páginas (/PageLabels)', () {
    test('as faixas do segundo documento entram deslocadas', () async {
      // Documento A: 3 páginas, faixa em 0 e outra em 2.
      final a =
          await buildLabelledPdf(pageCount: 3, labels: <int, PdfPageLabel>{
        0: PdfPageLabel.romanUpper(),
        2: PdfPageLabel.arabic(subsequent: 1),
      });
      // Documento B: 2 páginas, uma única faixa em 0.
      final b =
          await buildLabelledPdf(pageCount: 2, labels: <int, PdfPageLabel>{
        0: PdfPageLabel.lettersUpper(prefix: 'Anexo-'),
      });

      final merged = reopen(await PdfDocument.merge(<Uint8List>[a, b]));
      expect(merged.pageCount, 5);

      final ranges = pageLabelRanges(merged);
      // As faixas de A ficam onde estavam; a de B desloca pelas 3 páginas de A.
      expect(ranges.keys.toList()..sort(), <int>[0, 2, 3]);
    });

    test('estilo e prefixo sobrevivem à mesclagem', () async {
      final a =
          await buildLabelledPdf(pageCount: 2, labels: <int, PdfPageLabel>{
        0: PdfPageLabel.romanUpper(),
      });
      final b =
          await buildLabelledPdf(pageCount: 1, labels: <int, PdfPageLabel>{
        0: PdfPageLabel.arabic(prefix: 'Doc-', subsequent: 7),
      });

      final merged = reopen(await PdfDocument.merge(<Uint8List>[a, b]));
      final ranges = pageLabelRanges(merged);

      // `/St` ausente na origem volta como `1`, que é o padrão da
      // especificação para a chave — o valor efetivo não muda.
      expect(ranges[0], '/R||1');
      expect(ranges[2], '/D|Doc-|7');
    });

    test('cada estilo de numeração mantém o próprio nome', () async {
      // `PdfPageLabel.toDict` gravava romanLower como `/R` e lettersUpper como
      // `/a`, colidindo com os estilos maiúsculo e minúsculo respectivamente
      // (ISO 32000-1, tabela 159). A distinção se perdia antes mesmo da
      // mesclagem; hoje cada estilo tem o nome certo dos dois lados.
      final esperado = <PdfPageLabel, String>{
        PdfPageLabel.arabic(): '/D',
        PdfPageLabel.romanUpper(): '/R',
        PdfPageLabel.romanLower(): '/r',
        PdfPageLabel.lettersUpper(): '/A',
        PdfPageLabel.lettersLower(): '/a',
      };

      for (final entry in esperado.entries) {
        final source = await buildLabelledPdf(
          pageCount: 1,
          labels: <int, PdfPageLabel>{0: entry.key},
        );

        expect(pageLabelRanges(reopen(source))[0], '${entry.value}||-',
            reason: 'origem, estilo ${entry.value}');

        final merged = reopen(await PdfDocument.merge(<Uint8List>[source]));
        expect(pageLabelRanges(merged)[0], '${entry.value}||1',
            reason: 'mesclado, estilo ${entry.value}');
      }
    });

    test('três documentos empilham as faixas em ordem', () async {
      Future<Uint8List> doc(int pages, String prefix) => buildLabelledPdf(
            pageCount: pages,
            labels: <int, PdfPageLabel>{
              0: PdfPageLabel.arabic(prefix: prefix, subsequent: 1),
            },
          );

      final merged = reopen(await PdfDocument.merge(<Uint8List>[
        await doc(2, 'A-'),
        await doc(3, 'B-'),
        await doc(1, 'C-'),
      ]));

      expect(merged.pageCount, 6);
      final ranges = pageLabelRanges(merged);
      expect(ranges[0], '/D|A-|1');
      expect(ranges[2], '/D|B-|1');
      expect(ranges[5], '/D|C-|1');
    });

    test('importPageLabels: false descarta /PageLabels', () async {
      final source =
          await buildLabelledPdf(pageCount: 2, labels: <int, PdfPageLabel>{
        0: PdfPageLabel.romanUpper(),
      });

      final merged = reopen(await PdfDocument.merge(
        <Uint8List>[source],
        options: const PdfMergeOptions(importPageLabels: false),
      ));

      expect(merged.rootDict!.values.containsKey('/PageLabels'), isFalse);
      expect(merged.pageCount, 2);
    });

    test('documento sem numeração não cria /PageLabels', () async {
      final merged = reopen(await PdfDocument.merge(
          <Uint8List>[await buildTextPdf(pageCount: 2)]));

      expect(merged.rootDict!.values.containsKey('/PageLabels'), isFalse);
    });

    test('intervalo parcial desloca pela primeira página importada', () async {
      // A tem faixas em 0 (romana) e em 2 (arábica). Importando só as páginas
      // 1 e 2, a faixa que começava na página 0 é recortada: passa a valer da
      // primeira página importada em diante, com a numeração adiantada pelo
      // tanto que ficou de fora — a página 1 é a segunda da faixa, então a
      // numeração romana começa em II.
      final a =
          await buildLabelledPdf(pageCount: 3, labels: <int, PdfPageLabel>{
        0: PdfPageLabel.romanUpper(),
        2: PdfPageLabel.arabic(subsequent: 1),
      });

      final destination = PdfDocument();
      final merger = PdfDocumentMerger(destination);
      merger.importPageRange(reopen(a), 1, 2);
      merger.finish();

      final merged = reopen(await destination.save());
      expect(merged.pageCount, 2);

      final ranges = pageLabelRanges(merged);
      // Índice 2 na origem, primeira importada é a 1: 0 + 2 - 1 = 1.
      expect(ranges.keys.toList(), <int>[0, 1]);
      expect(ranges[0], '/R||2');
      expect(ranges[1], '/D||1');
    });

    test('primeiro documento sem faixas deixa /Nums começando fora do zero',
        () async {
      // Comportamento REAL: a especificação exige uma entrada para o índice 0
      // em `/Nums`. Como o primeiro documento não declarava numeração, ela não
      // é sintetizada e o `/Nums` do resultado começa no índice da primeira
      // página rotulada. Na prática os visualizadores caem no rótulo arábico
      // padrão para as páginas anteriores, que é o que a origem já mostrava.
      final plain = await buildTextPdf(pageCount: 2);
      final labelled =
          await buildLabelledPdf(pageCount: 1, labels: <int, PdfPageLabel>{
        0: PdfPageLabel.lettersUpper(prefix: 'Anexo-'),
      });

      final merged =
          reopen(await PdfDocument.merge(<Uint8List>[plain, labelled]));
      final ranges = pageLabelRanges(merged);

      expect(ranges.keys.toList(), <int>[2]);
      expect(ranges[2], '/A|Anexo-|1');
    });

    test('mesclar o mesclado preserva as faixas', () async {
      final a =
          await buildLabelledPdf(pageCount: 2, labels: <int, PdfPageLabel>{
        0: PdfPageLabel.romanUpper(),
      });
      final b =
          await buildLabelledPdf(pageCount: 2, labels: <int, PdfPageLabel>{
        0: PdfPageLabel.arabic(prefix: 'B-', subsequent: 1),
      });

      final once = await PdfDocument.merge(<Uint8List>[a, b]);
      final twice = reopen(await PdfDocument.merge(<Uint8List>[once]));

      expect(pageLabelRanges(reopen(once)), pageLabelRanges(twice));
    });

    test('camadas e numeração não geram avisos', () async {
      // Nada aqui é perda de informação, então `warnings` precisa ficar limpo —
      // é o canal reservado para o que realmente se perdeu.
      final destination = PdfDocument();
      final merger = PdfDocumentMerger(destination);
      merger.append(reopen(rawLayeredPage(layerName: 'Camada A')),
          label: 'camadas');
      merger.append(
        reopen(await buildLabelledPdf(
            pageCount: 1,
            labels: <int, PdfPageLabel>{0: PdfPageLabel.romanUpper()})),
        label: 'numeracao',
      );
      merger.finish();

      expect(merger.warnings, isEmpty);
      expect(reopen(await destination.save()).pageCount, 2);
    });
  });
}
