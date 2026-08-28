// Exemplo de mesclagem (merge) de PDFs com pdf_plus.
//
// Execute a partir da raiz do repositorio:
//
//     dart run example/merge_documents.dart
//
// O exemplo usa dois arquivos do corpus de teste, mostra os avisos coletados
// durante a mesclagem e grava o resultado em `merged.pdf`.

import 'dart:io';
import 'dart:typed_data';

import 'package:pdf_plus/pdf.dart';

Future<void> main() async {
  // Um documento simples e um documento assinado, para que a mesclagem tenha
  // algo de concreto a relatar em `warnings`.
  final origens = <String, Uint8List>{
    'example.pdf': _ler('test/assets/pdfs/example.pdf'),
    'duas_assinaturas.pdf': _ler('test/assets/pdfs/duas_assinaturas.pdf'),
  };

  // --- Caminho de alto nivel -------------------------------------------------
  // `PdfDocument.merge` resolve tudo em uma chamada: abre cada entrada com
  // reparo habilitado, importa todas as paginas e devolve os bytes prontos.
  final rapido = await PdfDocument.merge(origens.values.toList());
  print('PdfDocument.merge: ${rapido.length} bytes');

  // --- Caminho detalhado -----------------------------------------------------
  // `PdfDocumentMerger` da controle sobre cada origem (rotulo nas mensagens,
  // intervalo de paginas) e expoe os avisos do que se perdeu no caminho.
  final destino = PdfDocument(compress: true);
  final merger = PdfDocumentMerger(
    destino,
    options: const PdfMergeOptions(
      // Modo padrao: importa o grafo de objetos da pagina de origem, com
      // conteudo, recursos, anotacoes, campos, bookmarks, camadas e numeracao.
      mode: PdfMergeMode.objectImport,

      // Modo alternativo: `PdfMergeMode.flatten` envolve cada pagina em um
      // Form XObject e a desenha na pagina nova. Mantem apenas o conteudo
      // grafico — anotacoes, links e campos ficam pelo caminho — em troca de um
      // resultado previsivel para documentos exoticos.

      // Mesclar reescreve o arquivo inteiro, entao toda assinatura digital
      // existente deixa de conferir. Por padrao os campos `/FT /Sig` sao
      // removidos e o carimbo visual vira uma anotacao somente-leitura: o
      // documento continua parecendo assinado e nenhum validador acusa
      // assinatura quebrada, porque nao sobrou assinatura para conferir.
      //
      // Para preservar os campos de assinatura com o CMS e os certificados,
      // aceitando que os visualizadores os reportem como invalidos (e o que
      // fazem o SEI e a maioria das ferramentas de mercado):
      //
      //     const PdfMergeOptions(keepInvalidSignatures: true)
      //
      // Para remover tambem o carimbo visual:
      //
      //     const PdfMergeOptions(removeSignatureAppearance: true)
      //
      // Para recusar de vez uma origem assinada (lanca `PdfMergeException`):
      //
      //     const PdfMergeOptions(rejectSignedSources: true)
    ),
  );

  for (final entrada in origens.entries) {
    // A fonte e sempre um `PdfDocumentParser`; `allowRepair` faz um arquivo com
    // tabela de referencias cruzadas danificada ainda ser aproveitavel.
    final parser = PdfDocumentParser(entrada.value, allowRepair: true);

    // `append` importa o documento inteiro. Para um recorte:
    //     merger.importPageRange(parser, 0, 2, label: entrada.key);
    //     merger.importPage(parser, 0, label: entrada.key);
    final paginas = merger.append(parser, label: entrada.key);
    print('${entrada.key}: ${paginas.length} pagina(s) importada(s)');
  }

  // Resolve o que depende de todas as origens. Idempotente.
  merger.finish();

  // Avisos nao fatais: assinaturas invalidadas, links sem destino no intervalo
  // importado, campos renomeados por colisao, arvore de marcacao descartada.
  if (merger.warnings.isEmpty) {
    print('nenhum aviso');
  } else {
    print('avisos (${merger.warnings.length}):');
    for (final aviso in merger.warnings) {
      print('  - $aviso');
    }
  }

  final saida = File('merged.pdf');
  await saida.writeAsBytes(await destino.save());
  print('PDF mesclado em ${saida.absolute.path}');

  // Conferencia: o resultado tem de reabrir e somar as paginas das origens.
  final conferencia = PdfDocumentParser(
    await saida.readAsBytes(),
    allowRepair: true,
  );
  print('total de paginas: ${conferencia.pageCount}');
}

Uint8List _ler(String caminho) {
  final arquivo = File(caminho);
  if (!arquivo.existsSync()) {
    stderr.writeln(
      'Arquivo nao encontrado: ${arquivo.absolute.path}\n'
      'Execute o exemplo a partir da raiz do repositorio.',
    );
    exit(1);
  }
  return arquivo.readAsBytesSync();
}
