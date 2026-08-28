/*
 * Copyright (C) 2017, David PHAM-VAN <dev.nfet.net@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import '../document.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/dict_stream.dart';
import '../format/indirect.dart';
import '../format/name.dart';
import '../format/num.dart';
import '../format/string.dart';
import '../merging/pdf_merge_options.dart';
import '../obj/annotation.dart';
import '../obj/object.dart';
import '../obj/outline.dart';
import '../obj/page.dart';
import '../obj/page_label.dart';
import '../parsing/pdf_document_parser.dart';
import '../pdf_names.dart';
import 'object_graph/pdf_object_store.dart';

/// What to do with a reference that now points to a page that no longer
/// exists.
///
/// The reference can be an explicit destination (`[pageRef /XYZ …]`), a named
/// destination, a bookmark, an internal link or the catalog `/OpenAction`.
enum PdfBrokenReferencePolicy {
  /// Deletes the entry that carries the reference: the `/Dest`/`/A` key, the
  /// name/destination pair of the `/Names /Dests` tree, the bookmark item or
  /// the link annotation.
  ///
  /// It is the default, and each removal becomes a warning in
  /// [PdfPageCollectionEditor.warnings].
  remove,

  /// Retargets the reference to the page next to the one that left — the first
  /// survivor after it, or, if it was the last one, the last before it.
  ///
  /// If the document is left with no page at all there is no neighbor, and the
  /// behavior falls back to [remove].
  retarget,

  /// Refuses the operation with a [PdfPageEditException] before any mutation.
  throwError,
}

/// Error from an operation of the page collection.
class PdfPageEditException implements Exception {
  /// Creates the error with the described message.
  PdfPageEditException(this.message);

  /// Description of the problem.
  final String message;

  @override
  String toString() => 'PdfPageEditException: $message';
}

/// Page collection with reference repair.
///
/// It is the single owner of the page tree mutation: [insert], [remove],
/// [removeRange], [move], [reorder] and [duplicate] go through the same index
/// and owner validation and, after each mutation, through the same repair of
/// the structures that point to pages.
///
/// ```dart
/// final editor = PdfPageCollectionEditor(document);
/// editor.remove(3);
/// editor.move(0, 2);
/// final bytes = await document.save();
/// ```
///
/// ## What the repair covers
///
/// - explicit destinations `[pageRef /XYZ …]`, direct or in an indirect object;
/// - named destinations in `/Names /Dests` (name tree, `/Kids` included) and in
///   the old catalog `/Dests`;
/// - `/Outlines`: the destination of each item and, when the page goes away,
///   the item itself — its children move up to the place it held, and `/First`,
///   `/Last`, `/Prev`, `/Next`, `/Parent` and `/Count` are rewritten;
/// - internal links of the pages that stayed: `/Dest` and `/A` with `/S /GoTo`;
/// - `/PageLabels`: the ranges are recomputed for the new order, with a shifted
///   `/St`;
/// - the `/P` of the annotations and the `/AcroForm /Fields` widgets that lived
///   on the removed pages;
/// - the catalog `/OpenAction`.
///
/// Destinations expressed by page number (`[3 /Fit]`) are renumbered too.
/// `/GoToR` and `/Launch` are not touched: their page number refers to the
/// remote file.
///
/// ## What the repair does not cover
///
/// - `/StructTreeRoot`, `/ParentTree` and `/StructParents`: the logical
///   structure tree keeps describing the content that left;
/// - `/Threads` (articles), an orphan `/Popup` and actions chained by `/Next`;
/// - document JavaScript that navigates by page number;
/// - encrypted documents, which the library does not read yet.
///
/// ## Document loaded from a file
///
/// In a loaded document almost the whole graph stays in the original bytes and
/// is resolved by the parser, not by `document.objects`. The editor reads
/// through the [PdfObjectStore] and, when it needs to change something,
/// registers the object it read in the document so that it enters the
/// incremental update. Objects with a stream are not rewritten through that
/// path — from the read view of the store only the dictionary comes — and that
/// is reported in [warnings].
class PdfPageCollectionEditor {
  /// Creates the editor of the page collection of [document].
  PdfPageCollectionEditor(
    this.document, {
    this.brokenReferencePolicy = PdfBrokenReferencePolicy.remove,
  })  : _store = PdfObjectStore.forDocument(document),
        _parser = document.prev is PdfDocumentParser
            ? document.prev as PdfDocumentParser
            : null;

  /// Document whose pages are edited.
  final PdfDocument document;

  /// What to do with a reference to a removed page.
  final PdfBrokenReferencePolicy brokenReferencePolicy;

  final PdfObjectStore _store;
  final PdfDocumentParser? _parser;

  final List<String> _warnings = <String>[];

  /// Non-fatal warnings collected: deleted destinations, removed bookmarks,
  /// retargeted links, objects that could not be rewritten.
  ///
  /// Same spirit as `PdfDocumentMerger.warnings`: nothing here interrupts the
  /// operation, but everything here is a loss or a change of behavior.
  List<String> get warnings => List<String>.unmodifiable(_warnings);

  /// Forgets the collected warnings.
  void clearWarnings() => _warnings.clear();

  void _warn(String message) => _warnings.add(message);

  // ---------------------------------------------------------------------------
  // Reading
  // ---------------------------------------------------------------------------

  List<PdfPage> get _pages => document.pdfPageList.pages;

  /// Pages in document order.
  List<PdfPage> get pages => List<PdfPage>.unmodifiable(_pages);

  /// Number of pages.
  int get length => _pages.length;

  /// Page at position [index].
  PdfPage operator [](int index) {
    _checkIndex(index);
    return _pages[index];
  }

  /// Position of [page], or `-1` if it does not belong to the collection.
  int indexOf(PdfPage page) {
    for (var i = 0; i < _pages.length; i++) {
      if (identical(_pages[i], page)) return i;
    }
    return -1;
  }

  // ---------------------------------------------------------------------------
  // Validation — a single place
  // ---------------------------------------------------------------------------

  /// Checks that [index] addresses an existing page.
  void _checkIndex(int index, [String name = 'index']) {
    if (index < 0 || index >= _pages.length) {
      throw RangeError.index(index, _pages, name, null, _pages.length);
    }
  }

  /// Checks that [index] addresses a valid position to insert at — the end of
  /// the list is accepted.
  void _checkInsertIndex(int index, [String name = 'index']) {
    if (index < 0 || index > _pages.length) {
      throw RangeError.range(index, 0, _pages.length, name);
    }
  }

  /// Checks that [page] belongs to this document.
  void _checkOwner(PdfPage page) {
    if (!identical(page.pdfDocument, document)) {
      throw PdfPageEditException(
        'A página pertence a outro documento. Use insertImported() para '
        'trazer uma página de fora.',
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Operations
  // ---------------------------------------------------------------------------

  /// Inserts [page] at position [index].
  ///
  /// The [PdfPage] constructor already registers the page in
  /// `document.pdfPageList.pages`; that is why a page already in the collection
  /// is **moved** to [index] instead of duplicated. For a second copy use
  /// [duplicate].
  void insert(int index, PdfPage page) {
    _checkOwner(page);
    _checkInsertIndex(index);
    final before = List<PdfPage>.of(_pages);

    final current = indexOf(page);
    if (current >= 0) {
      _pages.removeAt(current);
      _pages.insert(index > current ? index - 1 : index, page);
    } else {
      _pages.insert(index, page);
    }

    _afterMutation(before);
  }

  /// Removes the page at index [index] and returns the removed object.
  PdfPage remove(int index) {
    _checkIndex(index);
    final page = _pages[index];
    _refuseIfPolicyThrows(<PdfPage>[page]);

    final before = List<PdfPage>.of(_pages);
    _pages.removeAt(index);
    _afterMutation(before);
    return page;
  }

  /// Removes the pages in `[start, end)` — [end] exclusive, as in `List`.
  List<PdfPage> removeRange(int start, int end) {
    if (start < 0 || start > _pages.length) {
      throw RangeError.range(start, 0, _pages.length, 'start');
    }
    if (end < start || end > _pages.length) {
      throw RangeError.range(end, start, _pages.length, 'end');
    }
    if (start == end) return <PdfPage>[];

    final removed = _pages.sublist(start, end);
    _refuseIfPolicyThrows(removed);

    final before = List<PdfPage>.of(_pages);
    _pages.removeRange(start, end);
    _afterMutation(before);
    return removed;
  }

  /// Moves the page at [from] to position [to] in the final list.
  void move(int from, int to) {
    _checkIndex(from, 'from');
    _checkIndex(to, 'to');
    if (from == to) return;

    final before = List<PdfPage>.of(_pages);
    final page = _pages.removeAt(from);
    _pages.insert(to, page);
    _afterMutation(before);
  }

  /// Reorders the collection according to [order], which has to be a complete
  /// permutation of the current indices.
  ///
  /// `order[i]` is the **current** index of the page that comes to occupy
  /// position `i`.
  void reorder(List<int> order) {
    if (order.length != _pages.length) {
      throw PdfPageEditException(
        'A nova ordem tem ${order.length} posições, e o documento tem '
        '${_pages.length} páginas. reorder() exige uma permutação completa.',
      );
    }
    final seen = <int>{};
    for (final index in order) {
      if (index < 0 || index >= _pages.length) {
        throw RangeError.index(index, _pages, 'order', null, _pages.length);
      }
      if (!seen.add(index)) {
        throw PdfPageEditException(
          'O índice $index aparece mais de uma vez na nova ordem.',
        );
      }
    }

    final before = List<PdfPage>.of(_pages);
    final reordered = <PdfPage>[for (final index in order) before[index]];
    _pages
      ..clear()
      ..addAll(reordered);
    _afterMutation(before);
  }

  /// Duplicates the page at [index], inserting the copy at [at] — by default
  /// right after the original.
  ///
  /// **The copy is shallow, on purpose.** The new page references the same
  /// content objects, the same `/Resources`, the same fonts and the same
  /// XObjects as the original: there is no renumbering and no stream copy, and
  /// duplicating a 4 MB page costs one dictionary. That is correct because
  /// nothing in this library rewrites an existing content stream in place; once
  /// that exists, duplicating will need a real deep copy.
  ///
  /// To bring in a page from **another** document there is [insertImported],
  /// which reuses the deep import of `PdfDocumentMerger`. It would be of no use
  /// here: source and target are the same document, and the object numbers
  /// already hold.
  ///
  /// The annotations are **not** copied: an annotation belongs to a single page
  /// through `/P`, and sharing it between two would produce exactly the
  /// inconsistency this phase exists to avoid. The loss becomes a warning in
  /// [warnings].
  PdfPage duplicate(int index, {int? at}) {
    _checkIndex(index);
    final source = _pages[index];
    final target = at ?? index + 1;
    _checkInsertIndex(target, 'at');

    final before = List<PdfPage>.of(_pages);

    // The constructor registers the page at the requested position; inserting
    // it again afterwards would make it show up twice in `/Kids`.
    final copy = PdfPage(
      document,
      pageFormat: source.pageFormat,
      rotate: source.rotate,
      index: target,
    );
    final box = source.mediaBoxOverride;
    if (box != null) copy.mediaBoxOverride = List<double>.of(box);

    for (final entry in source.params.values.entries) {
      if (_notCopiedOnDuplicate.contains(entry.key)) continue;
      copy.params[entry.key] = _copyValue(entry.value);
    }

    // The resources of a page created in this session only enter `/Resources`
    // in prepare(); they have to be copied in the model, not in the dictionary.
    copy.fonts.addAll(source.fonts);
    copy.shading.addAll(source.shading);
    copy.patterns.addAll(source.patterns);
    copy.xObjects.addAll(source.xObjects);
    copy.isolatedTransparency = source.isolatedTransparency;
    copy.knockoutTransparency = source.knockoutTransparency;

    final contents = _contentReferencesOf(source);
    if (contents.isNotEmpty) {
      copy.altered = true;
      final list = PdfArray<PdfDataType>(contents);
      list.uniq();
      copy.params[PdfNameTokens.contents] =
          list.values.length == 1 ? list.values.first : list;
    }

    if (source.params.containsKey(PdfNameTokens.annots) ||
        source.annotations.isNotEmpty) {
      _warn('a cópia da página ${index + 1} não leva as anotações do original: '
          'uma anotação pertence a uma única página pelo /P');
    }

    _afterMutation(before);
    return copy;
  }

  /// Imports page [sourcePageIndex] of [source] and inserts it at [index].
  ///
  /// Reuses the deep import of `PdfDocumentMerger` through
  /// `PdfDocument.importPage`: content, resources, fonts and annotations of the
  /// source are materialized in the target with new object numbers. The target
  /// has to be a new document — a loaded document would produce an incremental
  /// update containing objects from another file, and a `PdfMergeException` is
  /// thrown.
  PdfPage insertImported(
    int index,
    PdfDocumentParser source,
    int sourcePageIndex, {
    PdfMergeOptions? options,
  }) {
    _checkInsertIndex(index);
    final before = List<PdfPage>.of(_pages);

    // The importer appends the page at the end; bringing it to the requested
    // place is a move within the same list.
    final page = document.importPage(source, sourcePageIndex, options: options);
    final current = indexOf(page);
    if (current >= 0 && current != index) {
      _pages.removeAt(current);
      _pages.insert(index > current ? index - 1 : index, page);
    }

    _afterMutation(before);
    return page;
  }

  /// Keys that the duplication never copies.
  static const Set<String> _notCopiedOnDuplicate = <String>{
    PdfNameTokens.type, // rewritten by the constructor
    PdfNameTokens.parent, // rewritten by prepare()
    PdfNameTokens.mediaBox, // comes from pageFormat/mediaBoxOverride
    PdfNameTokens.rotate, // comes from rotate
    PdfNameTokens.annots, // see the doc comment of duplicate()
    PdfNameTokens.contents, // handled separately
    '/StructParents', // index of the original in the structure tree
  };

  /// Content references of [page], in the model and in the dictionary.
  List<PdfDataType> _contentReferencesOf(PdfPage page) {
    final result = <PdfDataType>[];
    // A stream created by getGraphics() in which nothing was drawn is dropped
    // in prepare(); copying its reference would leave the copy pointing to an
    // object that is not going to be written.
    if (page.altered) {
      for (final content in page.contents) {
        result.add(content.ref());
      }
    }
    final existing = page.params[PdfNameTokens.contents];
    if (existing is PdfIndirect) {
      result.add(existing);
    } else if (existing is PdfArray) {
      result.addAll(existing.values.whereType<PdfIndirect>());
    }
    return result;
  }

  /// Shallow copy of a value: direct containers are recreated so that the two
  /// pages do not share the same mutable instance; indirect references and
  /// scalars are shared on purpose.
  PdfDataType _copyValue(PdfDataType value, {int depth = 0}) {
    if (depth > 8) return value;
    if (value is PdfDictStream) return value;
    if (value is PdfArray) {
      return PdfArray<PdfDataType>(<PdfDataType>[
        for (final item in value.values) _copyValue(item, depth: depth + 1),
      ]);
    }
    if (value is PdfDict) {
      return PdfDict<PdfDataType>.values(<String, PdfDataType>{
        for (final entry in value.values.entries)
          entry.key: _copyValue(entry.value, depth: depth + 1),
      });
    }
    return value;
  }

  // ---------------------------------------------------------------------------
  // Repair state
  // ---------------------------------------------------------------------------

  Set<PdfObjectId> _removedPageIds = <PdfObjectId>{};
  Map<PdfObjectId, PdfPage?> _replacementOf = <PdfObjectId, PdfPage?>{};
  Map<int, int> _newIndexOfOldIndex = <int, int>{};
  Map<PdfPage, int> _oldIndexOfPage = <PdfPage, int>{};
  int _oldPageCount = 0;
  Set<String> _removedDestNames = <String>{};
  Set<PdfObjectId> _removedAnnotationIds = <PdfObjectId>{};

  PdfPage? _replacementFor(PdfObjectId id) => _replacementOf[id];

  /// Refuses the operation before mutating anything, when the policy is
  /// [PdfBrokenReferencePolicy.throwError] and some reference points to one of
  /// the pages that would leave.
  void _refuseIfPolicyThrows(List<PdfPage> toRemove) {
    if (brokenReferencePolicy != PdfBrokenReferencePolicy.throwError) return;
    final ids = <PdfObjectId>{
      for (final page in toRemove) PdfObjectId.fromObject(page),
    };
    final problems = _scanReferencesTo(ids);
    if (problems.isEmpty) return;
    throw PdfPageEditException(
      'A remoção deixaria ${problems.length} referência(s) para página '
      'inexistente: ${problems.take(5).join('; ')}'
      '${problems.length > 5 ? '; …' : ''}',
    );
  }

  // ---------------------------------------------------------------------------
  // Repair
  // ---------------------------------------------------------------------------

  /// Recomputes the index maps and fixes everything that points to pages.
  void _afterMutation(List<PdfPage> before) {
    final after = _pages;

    final survivors = Set<PdfPage>.identity()..addAll(after);
    final removed = <PdfPage>[
      for (final page in before)
        if (!survivors.contains(page)) page,
    ];

    _oldPageCount = before.length;
    _oldIndexOfPage = Map<PdfPage, int>.identity();
    for (var i = 0; i < before.length; i++) {
      _oldIndexOfPage[before[i]] = i;
    }

    _newIndexOfOldIndex = <int, int>{};
    for (var i = 0; i < after.length; i++) {
      final old = _oldIndexOfPage[after[i]];
      if (old != null) _newIndexOfOldIndex[old] = i;
    }

    _removedPageIds = <PdfObjectId>{
      for (final page in removed) PdfObjectId.fromObject(page),
    };
    _replacementOf = <PdfObjectId, PdfPage?>{
      for (final page in removed)
        PdfObjectId.fromObject(page): _neighbourOf(before, page, survivors),
    };
    _removedDestNames = <String>{};
    _removedAnnotationIds = _annotationIdsOf(removed);

    _store.invalidate();

    // Mandatory order: the named destinations are resolved first, because
    // bookmarks and links point to them by name.
    _repairNamedDestinations();
    _repairOutlines();
    _repairPageAnnotations();
    _repairAcroFormFields();
    _repairOpenAction();
    _repairPageLabels();

    // Revive before retiring: a page that leaves and comes back brings its own
    // content back with it, and a stream shared by two pages stays alive as
    // long as one of them exists.
    _reviveSurvivors(after);
    _retireRemovedPages(removed, after);
  }

  /// Gives back to the document the objects of the pages that are in the
  /// collection.
  ///
  /// It matters when a removed page comes back through [insert]: [remove] had
  /// taken the page, its annotations and its streams out of circulation.
  void _reviveSurvivors(List<PdfPage> survivors) {
    for (final page in survivors) {
      page.inUse = true;
      for (final annot in page.annotations) {
        annot.inUse = true;
      }
      for (final content in page.contents) {
        content.inUse = true;
      }
    }
  }

  /// Live neighbor page of the one that left: the first after it, or the last
  /// before it.
  PdfPage? _neighbourOf(
    List<PdfPage> before,
    PdfPage page,
    Set<PdfPage> survivors,
  ) {
    final index = _oldIndexOfPage[page] ?? before.indexOf(page);
    for (var i = index + 1; i < before.length; i++) {
      if (survivors.contains(before[i])) return before[i];
    }
    for (var i = index - 1; i >= 0; i--) {
      if (survivors.contains(before[i])) return before[i];
    }
    return null;
  }

  /// Object numbers of the annotations of the pages that left.
  Set<PdfObjectId> _annotationIdsOf(List<PdfPage> removed) {
    final ids = <PdfObjectId>{};
    for (final page in removed) {
      for (final annot in page.annotations) {
        ids.add(PdfObjectId.fromObject(annot));
      }
      final annots = _follow(page.params[PdfNameTokens.annots]);
      if (annots is PdfArray) {
        for (final value in annots.values) {
          if (value is PdfIndirect) ids.add(PdfObjectId.fromIndirect(value));
        }
      }
    }
    return ids;
  }

  /// Takes out of circulation the objects only the removed pages used.
  void _retireRemovedPages(List<PdfPage> removed, List<PdfPage> survivors) {
    if (removed.isEmpty) return;

    // After duplicate(), two pages share the same content streams; killing
    // them along with one of them would break the other.
    final kept = <PdfObjectId>{};
    for (final page in survivors) {
      for (final value in _contentReferencesOf(page)) {
        if (value is PdfIndirect) kept.add(PdfObjectId.fromIndirect(value));
      }
    }

    for (final page in removed) {
      page.inUse = false;
      for (final annot in page.annotations) {
        annot.inUse = false;
      }
      for (final content in page.contents) {
        if (!kept.contains(PdfObjectId.fromObject(content))) {
          content.inUse = false;
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Object resolution
  // ---------------------------------------------------------------------------

  /// Follows the indirect references of [value] down to a direct value.
  ///
  /// With [forWrite], every object crossed is registered in
  /// `document.objects`, so that the change made to the returned value enters
  /// the incremental update.
  PdfDataType? _follow(
    PdfDataType? value, {
    bool forWrite = false,
    int maxDepth = 32,
  }) {
    var current = value;
    for (var depth = 0; depth < maxDepth; depth++) {
      if (current is! PdfIndirect) return current;
      final id = PdfObjectId.fromIndirect(current);
      final object = _store.lookupId(id);
      if (object == null) return null;
      if (forWrite) _register(id, object);
      current = object.params;
    }
    return current;
  }

  /// Registers an object read from the source so that it gets rewritten.
  void _register(PdfObjectId id, PdfObject object) {
    if (document.objects.contains(object)) return;
    if (_hasStreamData(id)) {
      _warn('o objeto $id tem stream e não pôde ser reescrito; a correção de '
          'referência dentro dele foi descartada');
      return;
    }
    document.objects.add(object);
    _store.invalidate();
  }

  bool _hasStreamData(PdfObjectId id) {
    final parser = _parser;
    if (parser == null) return false;
    return parser.getObject(id.number)?.streamData != null;
  }

  /// Marks the object pointed to by [value] for rewriting, if it is indirect.
  void _markDirty(PdfDataType? value) => _follow(value, forWrite: true);

  // ---------------------------------------------------------------------------
  // Fixing a destination
  // ---------------------------------------------------------------------------

  /// Fixes the destination [value] in place.
  _RefStatus _repairDestination(PdfDataType? value, {int depth = 0}) {
    if (value == null || depth > 8) return _RefStatus.unchanged;

    if (value is PdfString) {
      return _removedDestNames.contains(_textOf(value))
          ? _RefStatus.broken
          : _RefStatus.unchanged;
    }
    if (value is PdfName) {
      return _removedDestNames.contains(value.value)
          ? _RefStatus.broken
          : _RefStatus.unchanged;
    }
    if (value is PdfArray) return _repairDestinationArray(value);
    if (value is PdfDict) {
      return _repairDestination(value[PdfNameTokens.d], depth: depth + 1);
    }
    if (value is PdfIndirect) {
      final target = _follow(value);
      if (target == null) return _RefStatus.unchanged;
      final status = _repairDestination(target, depth: depth + 1);
      if (status == _RefStatus.changed) _markDirty(value);
      return status;
    }
    return _RefStatus.unchanged;
  }

  /// Fixes an explicit destination `[page …]`, in place.
  _RefStatus _repairDestinationArray(PdfArray array) {
    if (array.values.isEmpty) return _RefStatus.unchanged;
    final first = array.values.first;

    if (first is PdfIndirect) {
      final id = PdfObjectId.fromIndirect(first);
      if (!_removedPageIds.contains(id)) return _RefStatus.unchanged;
      if (brokenReferencePolicy == PdfBrokenReferencePolicy.retarget) {
        final page = _replacementFor(id);
        if (page != null) {
          array.values[0] = page.ref();
          return _RefStatus.changed;
        }
      }
      return _RefStatus.broken;
    }

    // Destination by page number: it only makes sense within the document
    // itself, and that is why it is renumbered along with the order.
    if (first is PdfNum && first.value is int) {
      final old = first.value as int;
      if (old < 0 || old >= _oldPageCount) return _RefStatus.unchanged;
      final replacement = _newIndexOfOldIndex[old];
      if (replacement == null) {
        if (brokenReferencePolicy == PdfBrokenReferencePolicy.retarget) {
          final neighbour = _nearestNewIndex(old);
          if (neighbour != null) {
            array.values[0] = PdfNum(neighbour);
            return _RefStatus.changed;
          }
        }
        return _RefStatus.broken;
      }
      if (replacement == old) return _RefStatus.unchanged;
      array.values[0] = PdfNum(replacement);
      return _RefStatus.changed;
    }

    return _RefStatus.unchanged;
  }

  int? _nearestNewIndex(int oldIndex) {
    for (var i = oldIndex + 1; i < _oldPageCount; i++) {
      final found = _newIndexOfOldIndex[i];
      if (found != null) return found;
    }
    for (var i = oldIndex - 1; i >= 0; i--) {
      final found = _newIndexOfOldIndex[i];
      if (found != null) return found;
    }
    return null;
  }

  /// Fixes an action, if it is an internal jump.
  _RefStatus _repairAction(PdfDataType? value) {
    final dict = _follow(value);
    if (dict is! PdfDict) return _RefStatus.unchanged;
    final subtype = dict[PdfNameTokens.s];
    // `/GoToR` and `/Launch` point to another file: their page number has no
    // relation to the order of this document.
    if (subtype is! PdfName || subtype.value != PdfNameTokens.goto) {
      return _RefStatus.unchanged;
    }
    final status = _repairDestination(dict[PdfNameTokens.d]);
    if (status == _RefStatus.changed) _markDirty(value);
    return status;
  }

  /// Fixes the navigation [holder] carries (`/Dest` and `/A`).
  _RefStatus _repairHolder(PdfDict holder) {
    var status = _RefStatus.unchanged;

    if (holder.containsKey(PdfNameTokens.dest)) {
      final result = _repairDestination(holder[PdfNameTokens.dest]);
      if (result == _RefStatus.broken) return _RefStatus.broken;
      if (result == _RefStatus.changed) status = _RefStatus.changed;
    }
    if (holder.containsKey(PdfNameTokens.action)) {
      final result = _repairAction(holder[PdfNameTokens.action]);
      if (result == _RefStatus.broken) return _RefStatus.broken;
      if (result == _RefStatus.changed) status = _RefStatus.changed;
    }
    return status;
  }

  // ---------------------------------------------------------------------------
  // Named destinations
  // ---------------------------------------------------------------------------

  void _repairNamedDestinations() {
    _repairModelNamedDestinations();
    _repairStoredNamedDestinations();
  }

  /// Named destinations of a new document, created by `PdfNames.addDest`.
  void _repairModelNamedDestinations() {
    final names = document.catalog.names;
    if (names == null) return;
    final dests = names.dests;
    if (dests.isEmpty) return;

    for (final name in dests.keys.toList()) {
      final status = _repairDestination(dests[name]);
      if (status != _RefStatus.broken) continue;
      dests.remove(name);
      _removedDestNames.add(name);
      _warn('o destino nomeado "$name" apontava para uma página removida e foi '
          'apagado');
    }
  }

  /// Named destinations of a loaded document: `/Names /Dests` and the old
  /// catalog `/Dests`.
  void _repairStoredNamedDestinations() {
    final catalog = document.catalog.params;

    final namesValue = catalog[PdfNameTokens.names];
    final namesDict = _follow(namesValue);
    if (namesDict is PdfDict && namesDict.containsKey(PdfNameTokens.dests)) {
      if (_repairNameTree(namesDict[PdfNameTokens.dests])) {
        _markDirty(namesValue);
        namesDict.values.remove(PdfNameTokens.dests);
        if (namesDict.isEmpty) catalog.values.remove(PdfNameTokens.names);
      }
    }

    // `/Dests` from PDF 1.1: a plain dictionary from name to destination.
    final legacyValue = catalog[PdfNameTokens.dests];
    final legacy = _follow(legacyValue);
    if (legacy is PdfDict) {
      var changed = false;
      for (final key in legacy.values.keys.toList()) {
        final status = _repairDestination(legacy[key]);
        if (status == _RefStatus.changed) changed = true;
        if (status != _RefStatus.broken) continue;
        legacy.values.remove(key);
        _removedDestNames.add(key);
        changed = true;
        _warn('o destino nomeado "$key" de /Dests apontava para uma página '
            'removida e foi apagado');
      }
      if (changed) _markDirty(legacyValue);
    }
  }

  /// Walks a name tree fixing the destinations. Returns `true` if the tree was
  /// left empty.
  bool _repairNameTree(PdfDataType? node, {int depth = 0}) {
    if (depth > 32) return false;
    final dict = _follow(node);
    if (dict is! PdfDict) return false;

    var changed = false;
    var empty = true;

    final entriesValue = dict[PdfNameTokens.names];
    final entries = _follow(entriesValue);
    if (entries is PdfArray) {
      final kept = <PdfDataType>[];
      var removedHere = false;
      for (var i = 0; i + 1 < entries.values.length; i += 2) {
        final key = entries.values[i];
        final value = entries.values[i + 1];
        final status = _repairDestination(value);
        if (status == _RefStatus.broken) {
          final name = key is PdfString ? _textOf(key) : '$key';
          _removedDestNames.add(name);
          removedHere = true;
          _warn('o destino nomeado "$name" apontava para uma página removida e '
              'foi apagado');
          continue;
        }
        if (status == _RefStatus.changed) changed = true;
        kept
          ..add(key)
          ..add(value);
      }
      if (removedHere) {
        changed = true;
        _markDirty(entriesValue);
        entries.values
          ..clear()
          ..addAll(kept.cast());
        if (kept.isEmpty) {
          dict.values.remove(PdfNameTokens.names);
          dict.values.remove(PdfNameTokens.limits);
        } else {
          dict[PdfNameTokens.limits] = PdfArray<PdfDataType>(<PdfDataType>[
            kept.first,
            kept[kept.length - 2],
          ]);
        }
      }
      if (kept.isNotEmpty) empty = false;
    }

    final kidsValue = dict[PdfNameTokens.kids];
    final kids = _follow(kidsValue);
    if (kids is PdfArray) {
      final surviving = <PdfDataType>[];
      var kidsChanged = false;
      for (final kid in kids.values) {
        if (_repairNameTree(kid, depth: depth + 1)) {
          kidsChanged = true;
          continue;
        }
        surviving.add(kid);
      }
      if (kidsChanged) {
        _markDirty(kidsValue);
        kids.values
          ..clear()
          ..addAll(surviving.cast());
        if (surviving.isEmpty) dict.values.remove(PdfNameTokens.kids);
        changed = true;
      }
      if (surviving.isNotEmpty) empty = false;
    }

    if (changed) _markDirty(node);
    return empty;
  }

  // ---------------------------------------------------------------------------
  // Bookmarks
  // ---------------------------------------------------------------------------

  void _repairOutlines() {
    _repairModelOutlines();
    _repairStoredOutlines();
  }

  /// Bookmarks of a new document, created as [PdfOutline].
  void _repairModelOutlines() {
    final root = document.catalog.outlines;
    if (root == null) return;
    _repairModelOutlineChildren(root);
  }

  void _repairModelOutlineChildren(PdfOutline parent, {int depth = 0}) {
    if (depth > 40) return;
    for (final child in List<PdfOutline>.of(parent.outlines)) {
      _repairModelOutlineChildren(child, depth: depth + 1);
      if (!_isModelOutlineBroken(child)) continue;

      final index = parent.outlines.indexOf(child);
      if (index < 0) continue;
      parent.outlines.removeAt(index);
      // The children move up to the place of the removed parent: they may
      // point to pages that still exist.
      for (var i = 0; i < child.outlines.length; i++) {
        final grandChild = child.outlines[i];
        grandChild.parent = parent;
        parent.outlines.insert(index + i, grandChild);
      }
      child.outlines.clear();
      child.inUse = false;
      _warn('o bookmark "${child.title ?? child.anchor ?? ''}" apontava para '
          'uma página removida e foi retirado da árvore');
    }
  }

  bool _isModelOutlineBroken(PdfOutline node) {
    final anchor = node.anchor;
    if (anchor != null) return _removedDestNames.contains(anchor);

    final dest = node.dest;
    if (dest == null) return false;
    final id = PdfObjectId.fromObject(dest);
    if (!_removedPageIds.contains(id)) return false;

    if (brokenReferencePolicy == PdfBrokenReferencePolicy.retarget) {
      final replacement = _replacementFor(id);
      if (replacement != null) {
        node.dest = replacement;
        _warn('o bookmark "${node.title ?? ''}" foi reapontado para a página '
            'vizinha');
        return false;
      }
    }
    return true;
  }

  /// Bookmarks of a loaded document: the tree is read, fixed and rewritten
  /// whole when something changes.
  void _repairStoredOutlines() {
    final catalog = document.catalog.params;
    final rootValue = catalog[PdfNameTokens.outlines];
    final root = _follow(rootValue);
    if (root is! PdfDict) return;

    final nodes = <_OutlineNode>[];
    _readOutlineChildren(root, nodes, <int>{}, 0);
    if (nodes.isEmpty) return;

    if (!_pruneOutlineLevel(nodes)) return;

    final rootRef = rootValue is PdfIndirect ? rootValue : null;
    _markDirty(rootValue);
    _writeOutlineTree(root, rootRef, nodes);

    if (nodes.isEmpty) {
      catalog.values.remove(PdfNameTokens.outlines);
      _warn('a árvore de bookmarks ficou vazia e /Outlines saiu do catálogo');
    }
  }

  /// Fixes one level of the tree. Returns `true` if something changed.
  bool _pruneOutlineLevel(List<_OutlineNode> siblings) {
    var touched = false;
    for (var i = 0; i < siblings.length;) {
      final node = siblings[i];
      if (_pruneOutlineLevel(node.children)) touched = true;

      final status = _repairHolder(node.dict);
      if (status == _RefStatus.changed) touched = true;
      if (status != _RefStatus.broken) {
        i++;
        continue;
      }

      siblings.removeAt(i);
      siblings.insertAll(i, node.children);
      node.children.clear();
      touched = true;
      _warn('o bookmark ${_outlineLabel(node)} apontava para uma página '
          'removida e foi retirado da árvore');
    }
    return touched;
  }

  String _outlineLabel(_OutlineNode node) {
    final title = node.dict[PdfNameTokens.title];
    return title is PdfString ? '"${_textOf(title)}"' : '${node.id}';
  }

  void _readOutlineChildren(
    PdfDict parent,
    List<_OutlineNode> into,
    Set<int> visited,
    int depth,
  ) {
    if (depth > 40) return;
    var current = parent[PdfNameTokens.first];
    for (var guard = 0; guard < 100000; guard++) {
      if (current == null) return;
      final id =
          current is PdfIndirect ? PdfObjectId.fromIndirect(current) : null;
      if (id != null && !visited.add(id.number)) return;
      final dict = _follow(current);
      if (dict is! PdfDict) return;

      final node = _OutlineNode(id, dict);
      into.add(node);
      _readOutlineChildren(dict, node.children, visited, depth + 1);
      current = dict[PdfNameTokens.next];
    }
  }

  /// Rewrites the links of the whole tree.
  void _writeOutlineTree(
    PdfDict root,
    PdfIndirect? rootRef,
    List<_OutlineNode> children,
  ) {
    void writeLevel(List<_OutlineNode> siblings, PdfIndirect? parentRef) {
      for (var i = 0; i < siblings.length; i++) {
        final node = siblings[i];
        final dict = node.dict;
        final id = node.id;
        if (id != null) {
          final object = _store.lookupId(id);
          if (object != null) _register(id, object);
        }

        if (parentRef != null) {
          dict[PdfNameTokens.parent] = parentRef;
        } else {
          dict.values.remove(PdfNameTokens.parent);
        }

        final prev = i > 0 ? siblings[i - 1].ref : null;
        if (prev != null) {
          dict[PdfNameTokens.prev] = prev;
        } else {
          dict.values.remove(PdfNameTokens.prev);
        }

        final next = i + 1 < siblings.length ? siblings[i + 1].ref : null;
        if (next != null) {
          dict[PdfNameTokens.next] = next;
        } else {
          dict.values.remove(PdfNameTokens.next);
        }

        if (node.children.isEmpty) {
          dict.values
            ..remove(PdfNameTokens.first)
            ..remove(PdfNameTokens.last)
            ..remove(PdfNameTokens.count);
        } else {
          final first = node.children.first.ref;
          final last = node.children.last.ref;
          if (first != null) dict[PdfNameTokens.first] = first;
          if (last != null) dict[PdfNameTokens.last] = last;
          final visible = _visibleOutlineCount(node.children);
          dict[PdfNameTokens.count] = PdfNum(node.open ? visible : -visible);
        }

        writeLevel(node.children, node.ref);
      }
    }

    writeLevel(children, rootRef);

    if (children.isEmpty) {
      root.values
        ..remove(PdfNameTokens.first)
        ..remove(PdfNameTokens.last);
      root[PdfNameTokens.count] = const PdfNum(0);
      return;
    }
    final first = children.first.ref;
    final last = children.last.ref;
    if (first != null) root[PdfNameTokens.first] = first;
    if (last != null) root[PdfNameTokens.last] = last;
    root[PdfNameTokens.count] = PdfNum(_visibleOutlineCount(children));
  }

  int _visibleOutlineCount(List<_OutlineNode> siblings) {
    var total = 0;
    for (final node in siblings) {
      total += 1;
      if (node.open) total += _visibleOutlineCount(node.children);
    }
    return total;
  }

  // ---------------------------------------------------------------------------
  // Annotations of the pages that stayed
  // ---------------------------------------------------------------------------

  void _repairPageAnnotations() {
    for (final page in _pages) {
      _repairModelAnnotations(page);
      _repairStoredAnnotations(page);
    }
  }

  /// Annotations created in this session: only the link by named destination
  /// can break, because a link by page holds the page object.
  void _repairModelAnnotations(PdfPage page) {
    if (page.annotations.isEmpty || _removedDestNames.isEmpty) return;
    for (final annot in List<PdfAnnot>.of(page.annotations)) {
      final content = annot.annot;
      if (content is! PdfAnnotNamedLink) continue;
      if (!_removedDestNames.contains(content.dest)) continue;
      page.annotations.remove(annot);
      annot.inUse = false;
      _warn('o link para o destino nomeado "${content.dest}" saiu da página '
          '${indexOf(page) + 1}');
    }
  }

  /// Annotations that came from the file: `/Dest`, `/A /S /GoTo` and `/P`.
  void _repairStoredAnnotations(PdfPage page) {
    final annotsValue = page.params[PdfNameTokens.annots];
    final annots = _follow(annotsValue);
    if (annots is! PdfArray || annots.values.isEmpty) return;

    final pageRef = page.ref();
    final kept = <PdfDataType>[];
    var changed = false;

    for (final value in annots.values) {
      final dict = _follow(value);
      if (dict is! PdfDict) {
        kept.add(value);
        continue;
      }

      final status = _repairHolder(dict);
      if (status == _RefStatus.broken) {
        changed = true;
        _warn('uma anotação da página ${indexOf(page) + 1} apontava para uma '
            'página removida e saiu de /Annots');
        continue;
      }
      if (status == _RefStatus.changed) _markDirty(value);

      // `/P` has to point to the page that hosts the annotation.
      final owner = dict[PdfNameTokens.p];
      if (owner is PdfIndirect && owner != pageRef) {
        dict[PdfNameTokens.p] = pageRef;
        _markDirty(value);
      }

      kept.add(value);
    }

    if (!changed) return;
    _markDirty(annotsValue);
    annots.values
      ..clear()
      ..addAll(kept.cast());
    if (kept.isEmpty && annotsValue is PdfArray) {
      page.params.values.remove(PdfNameTokens.annots);
    }
  }

  // ---------------------------------------------------------------------------
  // Form widgets
  // ---------------------------------------------------------------------------

  /// Takes out of `/AcroForm /Fields` the widgets that lived on the removed
  /// pages.
  void _repairAcroFormFields() {
    if (_removedAnnotationIds.isEmpty) return;
    final catalog = document.catalog.params;
    final formValue = catalog[PdfNameTokens.acroForm];
    final form = _follow(formValue);
    if (form is! PdfDict) return;

    final fieldsValue = form[PdfNameTokens.fields];
    final fields = _follow(fieldsValue);
    if (fields is! PdfArray) return;

    if (!_pruneFieldArray(fields)) return;
    _markDirty(fieldsValue);
    _markDirty(formValue);
  }

  bool _pruneFieldArray(PdfArray array, {int depth = 0}) {
    if (depth > 16) return false;
    final kept = <PdfDataType>[];
    var changed = false;

    for (final value in array.values) {
      if (value is PdfIndirect &&
          _removedAnnotationIds.contains(PdfObjectId.fromIndirect(value))) {
        changed = true;
        _warn('o widget ${value.ser} morava em uma página removida e saiu de '
            '/AcroForm /Fields');
        continue;
      }

      final dict = _follow(value);
      if (dict is PdfDict) {
        final kidsValue = dict[PdfNameTokens.kids];
        final kids = _follow(kidsValue);
        if (kids is PdfArray && _pruneFieldArray(kids, depth: depth + 1)) {
          _markDirty(kidsValue);
          _markDirty(value);
          if (kids.values.isEmpty) {
            changed = true;
            continue;
          }
        }
      }
      kept.add(value);
    }

    if (!changed) return false;
    array.values
      ..clear()
      ..addAll(kept.cast());
    return true;
  }

  // ---------------------------------------------------------------------------
  // /OpenAction
  // ---------------------------------------------------------------------------

  void _repairOpenAction() {
    final catalog = document.catalog.params;
    final value = catalog[PdfNameTokens.openAction];
    if (value == null) return;

    final resolved = _follow(value);
    // `/OpenAction` is a destination or an action; only the dictionary with
    // `/S` is an action.
    final status = resolved is PdfDict && resolved.containsKey(PdfNameTokens.s)
        ? _repairAction(value)
        : _repairDestination(value);

    if (status != _RefStatus.broken) return;
    catalog.values.remove(PdfNameTokens.openAction);
    _warn('/OpenAction apontava para uma página removida e saiu do catálogo');
  }

  // ---------------------------------------------------------------------------
  // /PageLabels
  // ---------------------------------------------------------------------------

  void _repairPageLabels() {
    _repairModelPageLabels();
    _repairStoredPageLabels();
  }

  /// Labels of a new document, in `PdfPageLabels.labels`.
  void _repairModelPageLabels() {
    final labels = document.catalog.pageLabels;
    if (labels == null || labels.labels.isEmpty) return;

    final starts = labels.labels.keys.toList()..sort();
    final ranges = _planLabelRanges(starts);
    if (_rangesAreIdentity(ranges, starts)) return;

    final rebuilt = <int, PdfPageLabel>{};
    for (final range in ranges) {
      final source = labels.labels[range.sourceStart];
      if (source == null) continue;
      rebuilt[range.newStart] = range.offset == 0
          ? source
          : PdfPageLabel(
              source.prefix,
              style: source.style,
              subsequent: (source.subsequent ?? 0) + range.offset,
            );
    }
    labels.labels
      ..clear()
      ..addAll(rebuilt);
    _warn('as faixas de /PageLabels foram recalculadas para a ordem nova');
  }

  /// Labels of a loaded document: the number tree is read whole and rewritten
  /// as a flat `/Nums`.
  void _repairStoredPageLabels() {
    final catalog = document.catalog.params;
    final value = catalog[PdfNameTokens.pagelabels];
    final root = _follow(value);
    if (root is! PdfDict) return;

    final collected = <int, PdfDict>{};
    _readNumberTree(root, collected, 0);
    if (collected.isEmpty) return;

    final starts = collected.keys.toList()..sort();
    final ranges = _planLabelRanges(starts);
    if (_rangesAreIdentity(ranges, starts)) return;

    final nums = PdfArray<PdfDataType>();
    for (final range in ranges) {
      final source = collected[range.sourceStart];
      if (source == null) continue;
      nums
        ..add(PdfNum(range.newStart))
        ..add(_shiftLabel(source, range.offset));
    }

    _markDirty(value);
    if (nums.values.isEmpty) {
      catalog.values.remove(PdfNameTokens.pagelabels);
      _warn('/PageLabels ficou sem faixas e saiu do catálogo');
      return;
    }
    root.values
      ..remove(PdfNameTokens.kids)
      ..remove(PdfNameTokens.limits);
    root[PdfNameTokens.nums] = nums;
    _warn('as faixas de /PageLabels foram recalculadas para a ordem nova');
  }

  void _readNumberTree(PdfDict node, Map<int, PdfDict> into, int depth) {
    if (depth > 32) return;
    final nums = _follow(node[PdfNameTokens.nums]);
    if (nums is PdfArray) {
      for (var i = 0; i + 1 < nums.values.length; i += 2) {
        final key = nums.values[i];
        final label = _follow(nums.values[i + 1]);
        if (key is PdfNum && key.value is int && label is PdfDict) {
          into[key.value as int] = label;
        }
      }
    }
    final kids = _follow(node[PdfNameTokens.kids]);
    if (kids is PdfArray) {
      for (final kid in kids.values) {
        final dict = _follow(kid);
        if (dict is PdfDict) _readNumberTree(dict, into, depth + 1);
      }
    }
  }

  PdfDict _shiftLabel(PdfDict label, int offset) {
    if (offset == 0) return label;
    final copy = PdfDict<PdfDataType>.values(
      Map<String, PdfDataType>.of(label.values),
    );
    final start = label[PdfNameTokens.st];
    final base = start is PdfNum ? start.value.toInt() : 1;
    copy[PdfNameTokens.st] = PdfNum(base + offset);
    return copy;
  }

  /// Splits the new order into label ranges, tying each one to the old range it
  /// came from.
  List<_LabelRange> _planLabelRanges(List<int> starts) {
    final ranges = <_LabelRange>[];
    int? previousSource;
    int? previousOffset;

    for (var i = 0; i < _pages.length; i++) {
      final old = _oldIndexOfPage[_pages[i]];
      final source = old == null ? null : _rangeStartFor(starts, old);
      if (old == null || source == null) {
        // New page, or one before the first range: it continues the label of
        // the previous range and forces the next page to open a range.
        previousSource = null;
        previousOffset = null;
        continue;
      }

      final offset = old - source;
      if (previousSource == source &&
          previousOffset != null &&
          offset == previousOffset + 1) {
        previousOffset = offset;
        continue;
      }

      ranges.add(_LabelRange(i, source, offset));
      previousSource = source;
      previousOffset = offset;
    }

    // The first range has to start at page 0.
    if (ranges.isNotEmpty && ranges.first.newStart != 0) {
      ranges.insert(0, _LabelRange(0, ranges.first.sourceStart, 0));
    }
    return ranges;
  }

  bool _rangesAreIdentity(List<_LabelRange> ranges, List<int> starts) {
    if (ranges.length != starts.length) return false;
    for (var i = 0; i < ranges.length; i++) {
      final range = ranges[i];
      if (range.newStart != starts[i] ||
          range.sourceStart != starts[i] ||
          range.offset != 0) {
        return false;
      }
    }
    return true;
  }

  int? _rangeStartFor(List<int> starts, int index) {
    int? found;
    for (final start in starts) {
      if (start > index) break;
      found = start;
    }
    return found;
  }

  // ---------------------------------------------------------------------------
  // Read-only scan, for the throwError policy
  // ---------------------------------------------------------------------------

  /// Describes the references that point to the pages in [removedIds], without
  /// changing anything.
  List<String> _scanReferencesTo(Set<PdfObjectId> removedIds) {
    final problems = <String>[];
    final removedNames = <String>{};

    bool pointsToRemoved(PdfDataType? value, {int depth = 0}) {
      if (value == null || depth > 8) return false;
      if (value is PdfString) return removedNames.contains(_textOf(value));
      if (value is PdfName) return removedNames.contains(value.value);
      if (value is PdfArray) {
        final first = value.values.isEmpty ? null : value.values.first;
        return first is PdfIndirect &&
            removedIds.contains(PdfObjectId.fromIndirect(first));
      }
      if (value is PdfDict) {
        return pointsToRemoved(value[PdfNameTokens.d], depth: depth + 1);
      }
      if (value is PdfIndirect) {
        return pointsToRemoved(_follow(value), depth: depth + 1);
      }
      return false;
    }

    bool holderIsBroken(PdfDict holder) {
      if (pointsToRemoved(holder[PdfNameTokens.dest])) return true;
      final action = _follow(holder[PdfNameTokens.action]);
      if (action is! PdfDict) return false;
      final subtype = action[PdfNameTokens.s];
      if (subtype is! PdfName || subtype.value != PdfNameTokens.goto) {
        return false;
      }
      return pointsToRemoved(action[PdfNameTokens.d]);
    }

    // Named destinations first: the lost names break whoever cites them.
    final modelNames = document.catalog.names;
    if (modelNames != null) {
      modelNames.dests.forEach((name, dest) {
        if (!pointsToRemoved(dest)) return;
        removedNames.add(name);
        problems.add('destino nomeado "$name"');
      });
    }

    void scanNameTree(PdfDataType? node, int depth) {
      if (depth > 32) return;
      final dict = _follow(node);
      if (dict is! PdfDict) return;
      final entries = _follow(dict[PdfNameTokens.names]);
      if (entries is PdfArray) {
        for (var i = 0; i + 1 < entries.values.length; i += 2) {
          if (!pointsToRemoved(entries.values[i + 1])) continue;
          final key = entries.values[i];
          final name = key is PdfString ? _textOf(key) : '$key';
          removedNames.add(name);
          problems.add('destino nomeado "$name"');
        }
      }
      final kids = _follow(dict[PdfNameTokens.kids]);
      if (kids is PdfArray) {
        for (final kid in kids.values) {
          scanNameTree(kid, depth + 1);
        }
      }
    }

    final catalog = document.catalog.params;
    final namesDict = _follow(catalog[PdfNameTokens.names]);
    if (namesDict is PdfDict) scanNameTree(namesDict[PdfNameTokens.dests], 0);
    final legacy = _follow(catalog[PdfNameTokens.dests]);
    if (legacy is PdfDict) {
      legacy.values.forEach((key, value) {
        if (!pointsToRemoved(value)) return;
        removedNames.add(key);
        problems.add('destino nomeado "$key"');
      });
    }

    void scanModelOutline(PdfOutline node, int depth) {
      if (depth > 40) return;
      for (final child in node.outlines) {
        final anchor = child.anchor;
        final dest = child.dest;
        if (anchor != null && removedNames.contains(anchor)) {
          problems.add('bookmark "${child.title ?? anchor}"');
        } else if (dest != null &&
            removedIds.contains(PdfObjectId.fromObject(dest))) {
          problems.add('bookmark "${child.title ?? ''}"');
        }
        scanModelOutline(child, depth + 1);
      }
    }

    final modelOutlines = document.catalog.outlines;
    if (modelOutlines != null) scanModelOutline(modelOutlines, 0);

    void scanStoredOutline(PdfDict parent, Set<int> visited, int depth) {
      if (depth > 40) return;
      var current = parent[PdfNameTokens.first];
      for (var guard = 0; guard < 100000; guard++) {
        if (current == null) return;
        if (current is PdfIndirect && !visited.add(current.ser)) return;
        final dict = _follow(current);
        if (dict is! PdfDict) return;
        if (holderIsBroken(dict)) {
          final title = dict[PdfNameTokens.title];
          problems.add(
              'bookmark ${title is PdfString ? '"${_textOf(title)}"' : ''}');
        }
        scanStoredOutline(dict, visited, depth + 1);
        current = dict[PdfNameTokens.next];
      }
    }

    final outlinesRoot = _follow(catalog[PdfNameTokens.outlines]);
    if (outlinesRoot is PdfDict) scanStoredOutline(outlinesRoot, <int>{}, 0);

    for (final page in _pages) {
      if (removedIds.contains(PdfObjectId.fromObject(page))) continue;
      for (final annot in page.annotations) {
        final content = annot.annot;
        if (content is PdfAnnotNamedLink &&
            removedNames.contains(content.dest)) {
          problems.add('link para "${content.dest}"');
        }
      }
      final annots = _follow(page.params[PdfNameTokens.annots]);
      if (annots is! PdfArray) continue;
      for (final value in annots.values) {
        final dict = _follow(value);
        if (dict is PdfDict && holderIsBroken(dict)) {
          problems.add('link da página ${indexOf(page) + 1}');
        }
      }
    }

    final openAction = catalog[PdfNameTokens.openAction];
    if (openAction != null) {
      final resolved = _follow(openAction);
      final broken =
          resolved is PdfDict && resolved.containsKey(PdfNameTokens.s)
              ? holderIsBroken(
                  PdfDict<PdfDataType>.values(<String, PdfDataType>{
                  PdfNameTokens.action: openAction,
                }))
              : pointsToRemoved(openAction);
      if (broken) problems.add('/OpenAction');
    }

    return problems;
  }

  /// Text of a PDF string, handling the UTF-16BE BOM.
  static String _textOf(PdfString value) {
    final bytes = value.value;
    if (bytes.length >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff) {
      final buffer = StringBuffer();
      for (var i = 2; i + 1 < bytes.length; i += 2) {
        buffer.writeCharCode((bytes[i] << 8) | bytes[i + 1]);
      }
      return buffer.toString();
    }
    return String.fromCharCodes(bytes);
  }
}

/// What happened to a navigation reference.
enum _RefStatus {
  /// Nothing changed.
  unchanged,

  /// The reference was retargeted.
  changed,

  /// The reference points to a page that no longer exists.
  broken,
}

/// Node of the bookmark tree read from a loaded document.
class _OutlineNode {
  _OutlineNode(this.id, this.dict)
      : open = _isOpen(dict[PdfNameTokens.count]);

  static bool _isOpen(PdfDataType? count) =>
      count is! PdfNum || count.value >= 0;

  /// Identity of the item object, when it is indirect.
  final PdfObjectId? id;

  /// Dictionary of the item.
  final PdfDict dict;

  /// Children, in reading order.
  final List<_OutlineNode> children = <_OutlineNode>[];

  /// Whether the item shows up open in the reader, from the sign of the
  /// original `/Count`.
  final bool open;

  /// Indirect reference of the item, when it has one.
  PdfIndirect? get ref => id?.toIndirect();
}

/// `/PageLabels` range in the new order, tied to the old source range.
class _LabelRange {
  const _LabelRange(this.newStart, this.sourceStart, this.offset);

  /// Index, in the new order, where the range starts.
  final int newStart;

  /// Start index of the old range the label came from.
  final int sourceStart;

  /// Offset of the first page of the new range within the old range.
  final int offset;
}
