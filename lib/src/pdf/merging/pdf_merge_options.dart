/// Page merging strategy.
enum PdfMergeMode {
  /// Imports the object graph of the source page.
  ///
  /// Preserves content, resources, annotations, links, form fields, bookmarks,
  /// layers and page labels.
  objectImport,

  /// Flattens each source page into a form XObject drawn on the new page.
  ///
  /// Fast and predictable, but keeps only the graphical content.
  flatten,
}

/// Policy applied when two documents have form fields with the same name.
enum PdfFieldNameConflictPolicy {
  /// Renames the imported field by appending a numeric suffix
  /// (`name`, `name_2`, `name_3`, …).
  renameSuffix,

  /// Keeps the field already present in the destination and discards the
  /// imported one.
  keepFirst,

  /// Throws [PdfMergeException].
  throwError,
}

/// Merge options.
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
    this.importXmpMetadata = false,
    this.dropStructureTree = true,
    this.copyDocumentInfoFromFirst = false,
    this.groupBookmarksPerDocument = false,
    this.rejectSignedSources = false,
    this.keepInvalidSignatures = false,
    this.removeSignatureAppearance = false,
    this.deduplicateResources = true,
  });

  /// Page import strategy.
  final PdfMergeMode mode;

  /// Imports the page annotations (links, notes, stamps).
  final bool importAnnotations;

  /// Imports the form fields (`/AcroForm`).
  final bool importFormFields;

  /// What to do when an imported field has the same name as an existing one.
  final PdfFieldNameConflictPolicy fieldNameConflict;

  /// Imports the bookmark tree (`/Outlines`).
  final bool importBookmarks;

  /// Resolves named destinations into explicit destinations while importing.
  final bool importNamedDestinations;

  /// Imports layers / optional content groups (`/OCProperties`).
  final bool importLayers;

  /// Imports the page numbering (`/PageLabels`).
  final bool importPageLabels;

  /// Imports attachments (`/Names /EmbeddedFiles`).
  final bool importAttachments;

  /// Copies the XMP packet (`/Metadata`) of the first source document.
  ///
  /// Off by default when merging: XMP describes the document it was written
  /// into, and a consolidation of several sources is not that document.
  /// Rewriting a single file is the case where copying makes sense.
  final bool importXmpMetadata;

  /// Discards the structure tree (tagged PDF).
  ///
  /// When off, `/StructTreeRoot` and `/MarkInfo` of the first source document
  /// are copied and the pages keep `/StructParents`. With more than one source
  /// this preserves the tagging of the first one only: the trees of different
  /// documents are not merged.
  final bool dropStructureTree;

  /// Copies `/Info` from the first source document into the destination.
  final bool copyDocumentInfoFromFirst;

  /// Groups the bookmarks of each source under a parent node of its own.
  final bool groupBookmarksPerDocument;

  /// Refuses to merge when the source has digital signatures.
  ///
  /// Takes precedence over [keepInvalidSignatures] and
  /// [removeSignatureAppearance].
  final bool rejectSignedSources;

  /// Keeps the signature fields of the source, with CMS and certificates.
  ///
  /// Merging rewrites the whole file, so every existing signature stops
  /// checking out: viewers will report them as invalid. This is the behavior
  /// of SEI and of most tools on the market.
  final bool keepInvalidSignatures;

  /// Removes the visual stamp of the signature as well.
  ///
  /// No effect when [keepInvalidSignatures] is on.
  final bool removeSignatureAppearance;

  /// Reuses a single object for identical streams coming from different
  /// sources (font programs, images, repeated logos).
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
    bool? importXmpMetadata,
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
      importXmpMetadata: importXmpMetadata ?? this.importXmpMetadata,
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

/// Merge failure the caller can handle.
class PdfMergeException implements Exception {
  PdfMergeException(this.message);

  final String message;

  @override
  String toString() => 'PdfMergeException: $message';
}
