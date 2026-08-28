import '../document.dart';
import '../obj/page.dart';
import '../parsing/pdf_document_parser.dart';
import '../parsing/pdf_parser_types.dart';
import 'pdf_annotation_importer.dart';
import 'pdf_catalog_merger.dart';
import 'pdf_flatten_importer.dart';
import 'pdf_form_importer.dart';
import 'pdf_import_context.dart';
import 'pdf_merge_options.dart';
import 'pdf_object_importer.dart';
import 'pdf_outline_importer.dart';
import 'pdf_page_importer.dart';
import 'pdf_signature_policy.dart';

/// Mescla documentos PDF em um documento de destino.
///
/// ```dart
/// final out = PdfDocument();
/// final merger = PdfDocumentMerger(out);
/// merger.append(PdfDocumentParser(bytesA));
/// merger.append(PdfDocumentParser(bytesB));
/// merger.finish();
/// final bytes = await out.save();
/// ```
///
/// O destino precisa ser um documento novo: mesclar dentro de um documento
/// carregado produziria um incremental update contendo objetos de outro
/// arquivo, o que não é um PDF válido.
class PdfDocumentMerger {
  PdfDocumentMerger(PdfDocument destination, {PdfMergeOptions? options})
      : context =
            PdfImportContext(destination, options ?? const PdfMergeOptions()) {
    if (destination.prev != null) {
      throw PdfMergeException(
        'O documento de destino foi carregado de um arquivo existente. '
        'Mesclar exige um PdfDocument novo, porque a saída não pode ser um '
        'incremental update do arquivo de origem.',
      );
    }
    _objects = PdfObjectImporter(context);
    _pages = PdfPageImporter(context, _objects);
    _flatten = PdfFlattenImporter(context, _objects);
    _annotations = PdfAnnotationImporter(context, _objects);
    _forms = PdfFormImporter(context, _objects);
    _outlines = PdfOutlineImporter(context, _objects);
    _catalog = PdfCatalogMerger(context, _objects);
    _signatures = PdfSignaturePolicy(context);
  }

  final PdfImportContext context;

  late final PdfObjectImporter _objects;
  late final PdfPageImporter _pages;
  late final PdfFlattenImporter _flatten;
  late final PdfAnnotationImporter _annotations;
  late final PdfFormImporter _forms;
  late final PdfOutlineImporter _outlines;
  late final PdfCatalogMerger _catalog;
  late final PdfSignaturePolicy _signatures;

  bool _finished = false;
  int _sourceCount = 0;

  /// Opções em uso.
  PdfMergeOptions get options => context.options;

  /// Documento que recebe as páginas.
  PdfDocument get destination => context.destination;

  /// Avisos não fatais: links removidos, assinaturas invalidadas, campos
  /// renomeados.
  List<String> get warnings => List<String>.unmodifiable(context.warnings);

  /// Importa todas as páginas de [source].
  List<PdfPage> append(PdfDocumentParser source, {String? label}) {
    final count = source.pageCount;
    if (count == 0) return <PdfPage>[];
    return importPageRange(source, 0, count - 1, label: label);
  }

  /// Importa uma única página (índice base zero).
  PdfPage importPage(PdfDocumentParser source, int pageIndex, {String? label}) {
    final pages = importPageRange(source, pageIndex, pageIndex, label: label);
    if (pages.isEmpty) {
      throw PdfMergeException('A página $pageIndex não pôde ser importada.');
    }
    return pages.first;
  }

  /// Importa o intervalo `[start, end]` de páginas, inclusive nas duas pontas.
  List<PdfPage> importPageRange(
    PdfDocumentParser source,
    int start,
    int end, {
    String? label,
  }) {
    if (_finished) {
      throw StateError('A mesclagem já foi encerrada por finish().');
    }

    final refs = source.pageRefs;
    if (start < 0 || start >= refs.length) {
      throw ArgumentError.value(start, 'start', 'Fora do intervalo de páginas');
    }
    if (end < start || end >= refs.length) {
      throw ArgumentError.value(end, 'end', 'Fora do intervalo de páginas');
    }

    _sourceCount++;
    context.beginSource(source, label: label ?? 'documento $_sourceCount');

    try {
      if (source.isEncrypted) {
        throw PdfMergeException(
          'O documento "${context.sourceLabel}" está criptografado. '
          'A leitura de PDFs criptografados ainda não é suportada, e mesclar '
          'sem descriptografar produziria conteúdo corrompido.',
        );
      }

      _signatures.inspectSource();

      final imported = <PdfPage>[];

      // Primeira passagem: todas as páginas do intervalo. Só depois de o mapa
      // de páginas estar completo é que destinos e `/P` podem ser resolvidos.
      for (var index = start; index <= end; index++) {
        final ref = refs[index];
        final dict = _pageDict(source, ref);
        if (dict == null) {
          context.warn('página ${index + 1} não pôde ser lida e foi ignorada');
          continue;
        }
        context.importedSourcePages.add(index);
        imported.add(
          context.options.mode == PdfMergeMode.flatten
              ? _flatten.import(ref, dict)
              : _pages.import(ref, dict),
        );
      }

      // Segunda passagem.
      if (context.options.mode != PdfMergeMode.flatten) {
        for (var index = start; index <= end; index++) {
          final ref = refs[index];
          final page = context.pageMap[ref.obj];
          final dict = _pageDict(source, ref);
          if (page == null || dict == null) continue;
          _annotations.importPageAnnotations(page, dict);
        }

        _forms.importSource();
        _outlines.importSource();
        _catalog.mergeSource(isFirstSource: _sourceCount == 1);
      }

      return imported;
    } finally {
      context.endSource();
    }
  }

  /// Conclui a mesclagem, resolvendo o que depende de todas as origens.
  ///
  /// Chamado automaticamente por [PdfDocument.merge]; é idempotente.
  void finish() {
    if (_finished) return;
    _finished = true;
    _catalog.finish();
  }

  PdfDictToken? _pageDict(PdfDocumentParser source, PdfRefToken ref) {
    final object = source.getObject(ref.obj);
    if (object == null || object.value is! PdfDictToken) return null;
    return object.value as PdfDictToken;
  }
}
