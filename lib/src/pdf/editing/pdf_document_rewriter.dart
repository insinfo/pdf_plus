import 'dart:typed_data';

import '../document.dart';
import '../format/object_base.dart';
import '../merging/pdf_document_merger.dart';
import '../merging/pdf_merge_options.dart';
import '../parsing/pdf_document_parser.dart';
import '../parsing/pdf_parser_types.dart';

/// What the rewrite preserves from the source document.
///
/// Each key answers a single question: *does this stay in the new file?*
/// Whatever is not reachable from the document catalog never stays — that is
/// exactly what the rewrite is about.
///
/// The three signature keys ([rejectSignedSources], [keepInvalidSignatures]
/// and [removeSignatureAppearance]) are the same as in [PdfMergeOptions], with
/// the same semantics and the same precedence: rejecting beats keeping, and
/// keeping beats removing the stamp.
class PdfRewriteOptions {
  /// Configures the rewrite.
  const PdfRewriteOptions({
    this.keepDocumentInfo = true,
    this.keepXmpMetadata = true,
    this.keepAttachments = true,
    this.keepLayers = true,
    this.keepBookmarks = true,
    this.keepPageLabels = true,
    this.keepAnnotations = true,
    this.keepFormFields = true,
    this.keepStructureTree = false,
    this.deduplicateResources = true,
    this.rejectSignedSources = false,
    this.keepInvalidSignatures = false,
    this.removeSignatureAppearance = false,
  });

  /// Sanitizing profile: keeps only pages, content and annotations.
  ///
  /// Drops `/Info`, XMP, attachments, bookmarks, form fields, structural
  /// tagging and every trace of the signatures, including the visual stamp.
  /// It is the starting point for producing a file with no inherited metadata.
  const PdfRewriteOptions.sanitized()
      : keepDocumentInfo = false,
        keepXmpMetadata = false,
        keepAttachments = false,
        keepLayers = true,
        keepBookmarks = false,
        keepPageLabels = true,
        keepAnnotations = true,
        keepFormFields = false,
        keepStructureTree = false,
        deduplicateResources = true,
        rejectSignedSources = false,
        keepInvalidSignatures = false,
        removeSignatureAppearance = true;

  /// Copies title, author, creator, subject, keywords and producer from the
  /// `/Info` dictionary.
  final bool keepDocumentInfo;

  /// Copies the XMP packet from the catalog (`/Metadata`).
  ///
  /// The XMP usually repeats the `/Info` and carries edit history; turning
  /// both keys off is what produces a file with no declared provenance.
  final bool keepXmpMetadata;

  /// Copies the embedded files (`/Names /EmbeddedFiles`).
  final bool keepAttachments;

  /// Copies layers / optional content groups (`/OCProperties`).
  final bool keepLayers;

  /// Copies the bookmark tree (`/Outlines`).
  final bool keepBookmarks;

  /// Copies the page numbering (`/PageLabels`).
  final bool keepPageLabels;

  /// Copies the page annotations (links, notes, stamps, widgets).
  final bool keepAnnotations;

  /// Copies the form fields (`/AcroForm`).
  final bool keepFormFields;

  /// Copies the structural tagging (tagged PDF: `/StructTreeRoot`, `/MarkInfo`
  /// and the `/StructParents` of the pages).
  ///
  /// Off by default because the tree is copied as it is: it keeps describing
  /// the document the source used to be. As long as the rewrite does not
  /// change content that is faithful, but any later edit of a page or of a
  /// content stream leaves the tagging out of date.
  final bool keepStructureTree;

  /// Reuses a single object for identical streams (embedded fonts, logos
  /// repeated across several pages).
  final bool deduplicateResources;

  /// Refuses to rewrite a document that has a digital signature.
  ///
  /// Takes precedence over [keepInvalidSignatures] and
  /// [removeSignatureAppearance].
  final bool rejectSignedSources;

  /// Keeps the signature fields with CMS and certificates.
  ///
  /// The signatures stay in the file, but they **no longer check out**: they
  /// cover the exact bytes of the document they were applied to. Meant for
  /// forensics and history, not for validation.
  final bool keepInvalidSignatures;

  /// Also removes the visual stamp of the signature.
  ///
  /// No effect when [keepInvalidSignatures] is on. When off, the widget
  /// becomes a read-only stamp (`/Stamp`): the page keeps the appearance of
  /// being signed and no viewer complains about a broken signature, because
  /// no signature is left to check.
  final bool removeSignatureAppearance;

  /// Translates into the options of the object importer.
  ///
  /// The rewrite is a merge with a single source; what is called *keep* here
  /// is what is called *import* there.
  PdfMergeOptions toMergeOptions() => PdfMergeOptions(
        importAnnotations: keepAnnotations,
        importFormFields: keepFormFields,
        importBookmarks: keepBookmarks,
        importLayers: keepLayers,
        importPageLabels: keepPageLabels,
        importAttachments: keepAttachments,
        importXmpMetadata: keepXmpMetadata,
        dropStructureTree: !keepStructureTree,
        copyDocumentInfoFromFirst: keepDocumentInfo,
        deduplicateResources: deduplicateResources,
        rejectSignedSources: rejectSignedSources,
        keepInvalidSignatures: keepInvalidSignatures,
        removeSignatureAppearance: removeSignatureAppearance,
      );

  /// Copy with the given keys replaced.
  PdfRewriteOptions copyWith({
    bool? keepDocumentInfo,
    bool? keepXmpMetadata,
    bool? keepAttachments,
    bool? keepLayers,
    bool? keepBookmarks,
    bool? keepPageLabels,
    bool? keepAnnotations,
    bool? keepFormFields,
    bool? keepStructureTree,
    bool? deduplicateResources,
    bool? rejectSignedSources,
    bool? keepInvalidSignatures,
    bool? removeSignatureAppearance,
  }) {
    return PdfRewriteOptions(
      keepDocumentInfo: keepDocumentInfo ?? this.keepDocumentInfo,
      keepXmpMetadata: keepXmpMetadata ?? this.keepXmpMetadata,
      keepAttachments: keepAttachments ?? this.keepAttachments,
      keepLayers: keepLayers ?? this.keepLayers,
      keepBookmarks: keepBookmarks ?? this.keepBookmarks,
      keepPageLabels: keepPageLabels ?? this.keepPageLabels,
      keepAnnotations: keepAnnotations ?? this.keepAnnotations,
      keepFormFields: keepFormFields ?? this.keepFormFields,
      keepStructureTree: keepStructureTree ?? this.keepStructureTree,
      deduplicateResources: deduplicateResources ?? this.deduplicateResources,
      rejectSignedSources: rejectSignedSources ?? this.rejectSignedSources,
      keepInvalidSignatures:
          keepInvalidSignatures ?? this.keepInvalidSignatures,
      removeSignatureAppearance:
          removeSignatureAppearance ?? this.removeSignatureAppearance,
    );
  }
}

/// Report of what the rewrite did, for logging, auditing and testing.
class PdfRewriteReport {
  /// Builds the report.
  const PdfRewriteReport({
    required this.objectsBefore,
    required this.objectsAfter,
    required this.bytesBefore,
    required this.bytesAfter,
    required this.pagesBefore,
    required this.pagesAfter,
    required this.signatureFieldsBefore,
    required this.warnings,
  });

  /// Indirect objects in use that the cross-reference table of the source knew
  /// about.
  ///
  /// It is the count of the current revision: objects replaced by later
  /// revisions do not show up here, even though they still take up bytes in
  /// the file. In a document whose xref needed repair, the number reflects
  /// only what the scan managed to index, and can end up smaller than
  /// [objectsAfter].
  final int objectsBefore;

  /// Indirect objects written to the new file.
  final int objectsAfter;

  /// Size of the source file, in bytes.
  final int bytesBefore;

  /// Size of the rewritten file, in bytes.
  final int bytesAfter;

  /// Pages in the source.
  final int pagesBefore;

  /// Pages in the result. A difference here is page loss, and it comes with a
  /// warning.
  final int pagesAfter;

  /// Signature fields found in the source — all of them invalidated by the
  /// rewrite.
  final int signatureFieldsBefore;

  /// Non-fatal warnings from the importer: unreadable objects, dropped
  /// destinations, invalidated signatures, renamed fields.
  ///
  /// Comes from [PdfDocumentMerger.warnings].
  final List<String> warnings;

  /// Bytes saved. Negative when the file grew — which happens when the source
  /// used object streams and the output does not.
  int get bytesSaved => bytesBefore - bytesAfter;

  /// Fraction of the original size that is left (`0.4` = the file kept 40%).
  double get sizeRatio => bytesBefore == 0 ? 1 : bytesAfter / bytesBefore;

  /// Whether any signature was invalidated by the rewrite.
  bool get invalidatedSignatures => signatureFieldsBefore > 0;

  @override
  String toString() => 'PdfRewriteReport(objetos $objectsBefore -> '
      '$objectsAfter, bytes $bytesBefore -> $bytesAfter, páginas '
      '$pagesBefore -> $pagesAfter, avisos ${warnings.length})';
}

/// Result of the rewrite: the new bytes and the report.
class PdfRewriteResult {
  /// Builds the result.
  const PdfRewriteResult({required this.bytes, required this.report});

  /// The rewritten document.
  final Uint8List bytes;

  /// What was done to get to it.
  final PdfRewriteReport report;
}

/// Full rewrite of a PDF, with garbage collection.
///
/// Saving a loaded document produces an *incremental update*: the original
/// bytes are copied whole and the change goes at the end. That preserves
/// signatures, but nothing is ever removed from the file — old revisions,
/// objects nobody references any more and deleted content stay there, readable
/// by any tool that walks the bytes.
///
/// The rewrite does the opposite: it builds a new [PdfDocument] and imports
/// into it the graph reachable from the catalog of the source. Whatever is not
/// reachable simply is not written. There is no "erase" step: there is a step
/// that *copies what matters*, and the rest is left behind.
///
/// ```dart
/// final saneado = await PdfDocumentRewriter.rewrite(bytes);
///
/// // With a report:
/// final result = await PdfDocumentRewriter().rewriteBytes(bytes);
/// print(result.report); // objetos 443 -> 257, bytes 2589459 -> 566480
/// ```
///
/// ## Rewriting breaks every existing signature
///
/// A digital signature covers the exact bytes of the document it was applied
/// to, declared in the `/ByteRange`. The rewrite renumbers objects,
/// recompresses streams and rebuilds the xref: none of those bytes survive,
/// and no digest checks out again. **There is no rewrite that preserves a
/// signature.**
///
/// This is not a side effect to work around — it is the reason the rewrite
/// serves as the basis for sanitizing. As long as the file keeps the old
/// signature, it keeps along with it the revision that signature covered, and
/// it is exactly in that revision that the content one wanted to remove lives.
/// That is why [PdfRewriteOptions.keepInvalidSignatures] exists for forensics
/// and history, never for validation, and why safe redaction (phase 9 of the
/// roadmap) requires a rewrite.
///
/// The default behavior is that of SEI and of most tools on the market: it
/// rewrites, turns the signature widget into a read-only stamp and warns.
/// [PdfRewriteOptions.rejectSignedSources] refuses instead of warning.
///
/// ## What this phase still does NOT do
///
/// - **It is not redaction.** Removing text or an image from inside a content
///   stream is still the business of phases 8 and 9 of the roadmap. The
///   rewrite copies the content streams as they are: whatever was drawn on the
///   page stays drawn, including under a black rectangle. What it guarantees
///   is that no *earlier revision* with the content is left — not that the
///   content of the current revision is gone.
/// - **It does not decrypt.** A document with `/Encrypt` is refused with a
///   [PdfMergeException]; there is no reading security handler.
/// - **It does not preserve the `/ID`.** The new file gets a new identifier,
///   which is correct for a document whose bytes changed entirely, but breaks
///   any external link that depended on the old identifier.
/// - **It does not rewrite the structural tagging.** With
///   [PdfRewriteOptions.keepStructureTree] the tree is copied as it is; it is
///   not rebuilt from the content.
/// - **It does not use object streams in the output.** A very compact source
///   file can grow; the gain comes from dropping revisions, not from
///   recompressing.
/// - **It does not renumber under the caller's control.** The output numbering
///   is the import order; there is no option to preserve the source numbers.
class PdfDocumentRewriter {
  /// Creates a reusable rewriter.
  ///
  /// [compress], [version] and [deflate] apply to the output document, as in
  /// [PdfDocument.merge].
  PdfDocumentRewriter({
    PdfRewriteOptions? options,
    this.compress = true,
    this.version = PdfVersion.pdf_1_5,
    this.deflate,
    this.verbose = false,
  }) : options = options ?? const PdfRewriteOptions();

  /// What to preserve.
  final PdfRewriteOptions options;

  /// Compresses the generated streams.
  final bool compress;

  /// Version declared in the output file.
  final PdfVersion version;

  /// Alternative compressor; `zlib.encode` on `dart:io`.
  final DeflateCallback? deflate;

  /// Emits the serialization trace.
  final bool verbose;

  /// Rewrites [bytes] and returns only the new file.
  ///
  /// Shortcut for whoever does not need the report. See [rewriteBytes].
  static Future<Uint8List> rewrite(
    Uint8List bytes, {
    PdfRewriteOptions? options,
    bool compress = true,
    PdfVersion version = PdfVersion.pdf_1_5,
    DeflateCallback? deflate,
    bool useIsolate = false,
  }) async {
    final result = await PdfDocumentRewriter(
      options: options,
      compress: compress,
      version: version,
      deflate: deflate,
    ).rewriteBytes(bytes, useIsolate: useIsolate);
    return result.bytes;
  }

  /// Rewrites the bytes of a PDF.
  ///
  /// The file is read with repair enabled, so a damaged xref can still be
  /// rewritten — and the rewrite fixes the table, because the output is
  /// written from scratch.
  Future<PdfRewriteResult> rewriteBytes(
    Uint8List bytes, {
    bool useIsolate = false,
  }) {
    final source = PdfDocumentParser(bytes, allowRepair: true);
    return rewriteDocument(
      source,
      bytesBefore: bytes.length,
      useIsolate: useIsolate,
    );
  }

  /// Rewrites a document already opened by a parser.
  ///
  /// Useful when the file came from a reader and is not entirely in memory; in
  /// that case pass [bytesBefore] so the report knows the size of the source.
  Future<PdfRewriteResult> rewriteDocument(
    PdfDocumentParser source, {
    int? bytesBefore,
    bool useIsolate = false,
  }) async {
    if (source.isEncrypted) {
      throw PdfMergeException(
        'O documento está criptografado. A leitura de PDFs criptografados '
        'ainda não é suportada, e regravar sem descriptografar produziria '
        'conteúdo corrompido.',
      );
    }

    final signatureFields = _countSignatureFields(source);
    if (signatureFields > 0 && options.rejectSignedSources) {
      throw PdfMergeException(
        'O documento tem $signatureFields assinatura(s) digital(is). '
        'Regravar invalidaria todas elas e rejectSignedSources está ligado.',
      );
    }

    final destination = PdfDocument(
      compress: compress,
      verbose: verbose,
      version: version,
      deflate: deflate,
    );

    final merger = PdfDocumentMerger(
      destination,
      options: options.toMergeOptions(),
    );
    merger.append(source, label: 'documento');
    merger.finish();

    final output = await destination.save(useIsolate: useIsolate);

    return PdfRewriteResult(
      bytes: output,
      report: PdfRewriteReport(
        objectsBefore: _liveObjectCount(source),
        objectsAfter: destination.objects.where((e) => e.inUse).length,
        // `reader.length` instead of `source.bytes.length`: the latter would
        // materialize the whole file in memory just to measure it.
        bytesBefore: bytesBefore ?? source.reader.length,
        bytesAfter: output.length,
        pagesBefore: source.pageCount,
        pagesAfter: destination.pdfPageList.pages.length,
        signatureFieldsBefore: signatureFields,
        warnings: merger.warnings,
      ),
    );
  }

  /// Objects the source declares in use — free entries do not count.
  int _liveObjectCount(PdfDocumentParser source) {
    var total = 0;
    for (final id in source.objectIds) {
      if (source.storageOf(id) != XrefType.free) total++;
    }
    return total;
  }

  int _countSignatureFields(PdfDocumentParser source) {
    try {
      return source.extractSignatureFields().length;
    } catch (_) {
      // A document whose signature structure cannot be read must not block the
      // rewrite; the per-widget handling still applies.
      return 0;
    }
  }
}
