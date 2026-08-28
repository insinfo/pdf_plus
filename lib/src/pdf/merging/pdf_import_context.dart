import '../document.dart';
import '../obj/object.dart';
import '../obj/page.dart';
import '../parsing/pdf_document_parser.dart';
import '../parsing/pdf_parser_types.dart';
import 'pdf_merge_options.dart';

/// Estado de uma sessão de mesclagem.
///
/// Guarda o que precisa sobreviver entre as duas passagens da importação
/// (páginas primeiro, anotações e bookmarks depois) e entre documentos de
/// origem sucessivos.
class PdfImportContext {
  PdfImportContext(this.destination, this.options);

  /// Documento que recebe as páginas.
  final PdfDocument destination;

  final PdfMergeOptions options;

  PdfDocumentParser? _source;

  /// Documento de origem da importação em andamento.
  PdfDocumentParser get source {
    final current = _source;
    if (current == null) {
      throw StateError('Nenhum documento de origem em importação.');
    }
    return current;
  }

  /// Objetos já importados da origem atual: número na ORIGEM -> objeto no
  /// DESTINO. Reiniciado a cada origem, porque os números colidem entre
  /// documentos diferentes.
  final Map<int, PdfObject> imported = <int, PdfObject>{};

  /// Páginas já criadas: número do objeto da página na ORIGEM -> página no
  /// DESTINO. Também reiniciado a cada origem.
  final Map<int, PdfPage> pageMap = <int, PdfPage>{};

  /// Números de objeto que são páginas na origem atual.
  ///
  /// Usado para cortar a travessia: importar uma referência de página
  /// arrastaria a árvore de páginas inteira do documento de origem.
  final Set<int> sourcePageIds = <int>{};

  /// Nomes de campos de formulário já ocupados no destino.
  final Set<String> usedFieldNames = <String>{};

  /// Renomeações aplicadas na origem atual: nome original -> nome final.
  final Map<String, String> renamedFields = <String, String>{};

  /// Streams já materializados no destino, por assinatura de conteúdo.
  /// Vale entre origens — é o que permite deduplicar a mesma fonte embutida em
  /// documentos diferentes.
  final Map<String, PdfObject> streamsByDigest = <String, PdfObject>{};

  /// Avisos não fatais acumulados durante a mesclagem.
  final List<String> warnings = <String>[];

  /// Índice, dentro do documento de origem atual, das páginas efetivamente
  /// importadas. Usado para descartar destinos que apontam para fora.
  final Set<int> importedSourcePages = <int>{};

  /// Widgets de formulário importados da origem atual, na ordem em que
  /// apareceram nas páginas. O importador de formulários usa esta lista para
  /// montar `/AcroForm /Fields`.
  final List<PdfImportedWidget> widgets = <PdfImportedWidget>[];

  /// Números de objeto, na origem atual, dos campos terminais já alcançados
  /// por algum widget. O que sobrar de `/AcroForm /Fields` é campo órfão.
  final Set<int> reachedFieldIds = <int>{};

  /// Se a origem atual tem assinatura digital.
  bool sourceHasSignatures = false;

  /// Rótulo do documento de origem, usado nas mensagens de aviso.
  String sourceLabel = 'documento';

  /// Quantidade de páginas que o destino tinha antes da origem atual.
  int pagesBeforeSource = 0;

  /// Prepara o contexto para importar de [parser].
  void beginSource(PdfDocumentParser parser, {String? label}) {
    _source = parser;
    imported.clear();
    pageMap.clear();
    sourcePageIds.clear();
    renamedFields.clear();
    importedSourcePages.clear();
    widgets.clear();
    reachedFieldIds.clear();
    sourceHasSignatures = false;
    sourceLabel = label ?? 'documento';
    pagesBeforeSource = destination.pdfPageList.pages.length;

    for (final ref in parser.pageRefs) {
      sourcePageIds.add(ref.obj);
    }
  }

  /// Encerra a origem atual.
  void endSource() {
    _source = null;
  }

  bool get hasSource => _source != null;

  /// Se [objId] é uma página do documento de origem atual.
  bool isSourcePage(int objId) => sourcePageIds.contains(objId);

  /// Página do destino correspondente a uma página da origem, se importada.
  PdfPage? mappedPage(PdfRefToken ref) => pageMap[ref.obj];

  void warn(String message) => warnings.add('[$sourceLabel] $message');
}

/// Widget de formulário trazido de uma origem, com o vínculo entre o que foi
/// lido e o que foi criado no destino.
class PdfImportedWidget {
  PdfImportedWidget({
    required this.sourceRef,
    required this.sourceDict,
    required this.destination,
    required this.page,
  });

  /// Referência da anotação no documento de origem.
  final PdfRefToken? sourceRef;

  /// Dicionário da anotação na origem.
  final PdfDictToken sourceDict;

  /// Objeto criado no destino.
  final PdfObject destination;

  /// Página do destino onde o widget aparece.
  final PdfPage page;
}
