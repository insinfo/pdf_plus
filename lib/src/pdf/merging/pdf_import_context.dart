import '../document.dart';
import '../obj/object.dart';
import '../obj/page.dart';
import '../parsing/pdf_document_parser.dart';
import '../parsing/pdf_parser_types.dart';
import 'pdf_merge_options.dart';

/// State of a merge session.
///
/// Holds what must survive between the two import passes (pages first,
/// annotations and bookmarks afterwards) and between successive source
/// documents.
class PdfImportContext {
  PdfImportContext(this.destination, this.options);

  /// Document that receives the pages.
  final PdfDocument destination;

  final PdfMergeOptions options;

  PdfDocumentParser? _source;

  /// Source document of the import in progress.
  PdfDocumentParser get source {
    final current = _source;
    if (current == null) {
      throw StateError('Nenhum documento de origem em importação.');
    }
    return current;
  }

  /// Objects already imported from the current source: number in the SOURCE ->
  /// object in the DESTINATION. Reset for every source, because the numbers
  /// collide between different documents.
  final Map<int, PdfObject> imported = <int, PdfObject>{};

  /// Pages already created: page object number in the SOURCE -> page in the
  /// DESTINATION. Also reset for every source.
  final Map<int, PdfPage> pageMap = <int, PdfPage>{};

  /// Object numbers that are pages in the current source.
  ///
  /// Used to cut the traversal short: importing a page reference would drag in
  /// the whole page tree of the source document.
  final Set<int> sourcePageIds = <int>{};

  /// Form field names already taken in the destination.
  final Set<String> usedFieldNames = <String>{};

  /// Renames applied in the current source: original name -> final name.
  final Map<String, String> renamedFields = <String, String>{};

  /// Streams already materialized in the destination, keyed by content
  /// signature. Kept across sources — it is what allows deduplicating the same
  /// embedded font coming from different documents.
  final Map<String, PdfObject> streamsByDigest = <String, PdfObject>{};

  /// Non-fatal warnings accumulated during the merge.
  final List<String> warnings = <String>[];

  /// Index, within the current source document, of the pages actually
  /// imported. Used to discard destinations that point outside of it.
  final Set<int> importedSourcePages = <int>{};

  /// Form widgets imported from the current source, in the order they appeared
  /// in the pages. The form importer uses this list to build
  /// `/AcroForm /Fields`.
  final List<PdfImportedWidget> widgets = <PdfImportedWidget>[];

  /// Object numbers, in the current source, of the terminal fields already
  /// reached by some widget. Whatever is left in `/AcroForm /Fields` is an
  /// orphan field.
  final Set<int> reachedFieldIds = <int>{};

  /// Whether the current source has digital signatures.
  bool sourceHasSignatures = false;

  /// Label of the source document, used in the warning messages.
  String sourceLabel = 'documento';

  /// Number of pages the destination had before the current source.
  int pagesBeforeSource = 0;

  /// Prepares the context to import from [parser].
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

  /// Ends the current source.
  void endSource() {
    _source = null;
  }

  bool get hasSource => _source != null;

  /// Whether [objId] is a page of the current source document.
  bool isSourcePage(int objId) => sourcePageIds.contains(objId);

  /// Destination page matching a source page, when it was imported.
  PdfPage? mappedPage(PdfRefToken ref) => pageMap[ref.obj];

  void warn(String message) => warnings.add('[$sourceLabel] $message');
}

/// Form widget brought in from a source, with the link between what was read
/// and what was created in the destination.
class PdfImportedWidget {
  PdfImportedWidget({
    required this.sourceRef,
    required this.sourceDict,
    required this.destination,
    required this.page,
  });

  /// Reference of the annotation in the source document.
  final PdfRefToken? sourceRef;

  /// Dictionary of the annotation in the source.
  final PdfDictToken sourceDict;

  /// Object created in the destination.
  final PdfObject destination;

  /// Destination page where the widget appears.
  final PdfPage page;
}
