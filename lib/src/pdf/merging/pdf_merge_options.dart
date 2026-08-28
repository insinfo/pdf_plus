/// Estratégia de mesclagem de páginas.
enum PdfMergeMode {
  /// Importa o grafo de objetos da página de origem.
  ///
  /// Preserva conteúdo, recursos, anotações, links, campos de formulário,
  /// bookmarks, camadas e page labels.
  objectImport,

  /// Achata cada página de origem em um Form XObject desenhado na página nova.
  ///
  /// Rápido e previsível, porém mantém apenas o conteúdo gráfico.
  flatten,
}

/// Política aplicada quando dois documentos têm campos de formulário homônimos.
enum PdfFieldNameConflictPolicy {
  /// Renomeia o campo importado acrescentando um sufixo numérico
  /// (`nome`, `nome_2`, `nome_3`, …).
  renameSuffix,

  /// Mantém o campo já presente no destino e descarta o importado.
  keepFirst,

  /// Lança [PdfMergeException].
  throwError,
}

/// Opções de mesclagem.
class PdfMergeOptions {
  const PdfMergeOptions({
    this.mode = PdfMergeMode.objectImport,
    this.importAnnotations = true,
    this.importFormFields = true,
    this.fieldNameConflict = PdfFieldNameConflictPolicy.renameSuffix,
    this.importBookmarks = true,
    this.importNamedDestinations = true,
    this.importLayers = true,
    this.importPageLabels = true,
    this.importAttachments = false,
    this.dropStructureTree = true,
    this.copyDocumentInfoFromFirst = false,
    this.groupBookmarksPerDocument = false,
    this.rejectSignedSources = false,
    this.keepInvalidSignatures = false,
    this.removeSignatureAppearance = false,
    this.deduplicateResources = true,
  });

  /// Estratégia de importação das páginas.
  final PdfMergeMode mode;

  /// Importa as anotações da página (links, notas, carimbos).
  final bool importAnnotations;

  /// Importa os campos de formulário (`/AcroForm`).
  final bool importFormFields;

  /// O que fazer quando um campo importado tem o mesmo nome de um já presente.
  final PdfFieldNameConflictPolicy fieldNameConflict;

  /// Importa a árvore de bookmarks (`/Outlines`).
  final bool importBookmarks;

  /// Resolve destinos nomeados para destinos explícitos ao importar.
  final bool importNamedDestinations;

  /// Importa camadas / grupos de conteúdo opcional (`/OCProperties`).
  final bool importLayers;

  /// Importa a numeração de páginas (`/PageLabels`).
  final bool importPageLabels;

  /// Importa anexos (`/Names /EmbeddedFiles`).
  final bool importAttachments;

  /// Descarta a árvore de marcação estrutural (tagged PDF).
  final bool dropStructureTree;

  /// Copia `/Info` do primeiro documento de origem para o destino.
  final bool copyDocumentInfoFromFirst;

  /// Agrupa os bookmarks de cada origem sob um nó-pai próprio.
  final bool groupBookmarksPerDocument;

  /// Recusa mesclar quando a origem tem assinatura digital.
  ///
  /// Tem precedência sobre [keepInvalidSignatures] e
  /// [removeSignatureAppearance].
  final bool rejectSignedSources;

  /// Mantém os campos de assinatura da origem, com CMS e certificados.
  ///
  /// A mesclagem reescreve o arquivo inteiro, então toda assinatura existente
  /// deixa de conferir: os visualizadores vão reportá-las como inválidas. É o
  /// comportamento do SEI e da maioria das ferramentas de mercado.
  final bool keepInvalidSignatures;

  /// Remove também o carimbo visual da assinatura.
  ///
  /// Sem efeito quando [keepInvalidSignatures] está ligado.
  final bool removeSignatureAppearance;

  /// Reaproveita um único objeto para streams idênticos vindos de origens
  /// diferentes (programas de fonte, imagens, logotipos repetidos).
  final bool deduplicateResources;

  PdfMergeOptions copyWith({
    PdfMergeMode? mode,
    bool? importAnnotations,
    bool? importFormFields,
    PdfFieldNameConflictPolicy? fieldNameConflict,
    bool? importBookmarks,
    bool? importNamedDestinations,
    bool? importLayers,
    bool? importPageLabels,
    bool? importAttachments,
    bool? dropStructureTree,
    bool? copyDocumentInfoFromFirst,
    bool? groupBookmarksPerDocument,
    bool? rejectSignedSources,
    bool? keepInvalidSignatures,
    bool? removeSignatureAppearance,
    bool? deduplicateResources,
  }) {
    return PdfMergeOptions(
      mode: mode ?? this.mode,
      importAnnotations: importAnnotations ?? this.importAnnotations,
      importFormFields: importFormFields ?? this.importFormFields,
      fieldNameConflict: fieldNameConflict ?? this.fieldNameConflict,
      importBookmarks: importBookmarks ?? this.importBookmarks,
      importNamedDestinations:
          importNamedDestinations ?? this.importNamedDestinations,
      importLayers: importLayers ?? this.importLayers,
      importPageLabels: importPageLabels ?? this.importPageLabels,
      importAttachments: importAttachments ?? this.importAttachments,
      dropStructureTree: dropStructureTree ?? this.dropStructureTree,
      copyDocumentInfoFromFirst:
          copyDocumentInfoFromFirst ?? this.copyDocumentInfoFromFirst,
      groupBookmarksPerDocument:
          groupBookmarksPerDocument ?? this.groupBookmarksPerDocument,
      rejectSignedSources: rejectSignedSources ?? this.rejectSignedSources,
      keepInvalidSignatures:
          keepInvalidSignatures ?? this.keepInvalidSignatures,
      removeSignatureAppearance:
          removeSignatureAppearance ?? this.removeSignatureAppearance,
      deduplicateResources: deduplicateResources ?? this.deduplicateResources,
    );
  }
}

/// Falha de mesclagem que o chamador pode tratar.
class PdfMergeException implements Exception {
  PdfMergeException(this.message);

  final String message;

  @override
  String toString() => 'PdfMergeException: $message';
}
