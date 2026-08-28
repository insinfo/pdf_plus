import 'dart:convert';
import 'dart:typed_data';

import '../color.dart';
import '../document.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/indirect.dart';
import '../format/name.dart';
import '../format/num.dart';
import '../format/string.dart';
import '../obj/annotation.dart';
import '../obj/object.dart';
import '../obj/page.dart';
import '../obj/xobject.dart';
import '../pdf_names.dart';
import 'object_graph/pdf_object_store.dart';
import 'pdf_box.dart';
import 'pdf_coordinate_transformer.dart';
import 'pdf_page_content_editor.dart';

/// Makes writable an object that only exists in the bytes of the loaded
/// document.
///
/// In a document opened from a file, the dictionary of an annotation, of the
/// `/AcroForm` or of the `/Fields` array normally is **not** a [PdfObject]: it
/// stays in the file and the [PdfObjectStore] hands it over only as a read
/// view. To change it in the incremental update, a new object with the **same
/// number and the same generation** has to be materialized, which then
/// overrides the original — that is what `PdfSignatureFieldEditor` already does
/// for the signature fields.
///
/// This class concentrates that step so that the annotation collection and the
/// form flattener do not repeat the rule, and it guarantees that **an object is
/// materialized only once**: the second change to the same annotation finds the
/// [PdfObject] already created and writes inside it, instead of writing the
/// same number twice into the output file.
///
/// It is a provisional stand-in for the `PdfMutationContext` planned for phase
/// F2 of the roadmap: there is no dirty set, no rollback and no signed-document
/// policy here.
class PdfLoadedObjectMutator {
  /// Creates the materializer over [store].
  PdfLoadedObjectMutator(this.store);

  /// Creates the materializer with the store bound to the parser of [document].
  factory PdfLoadedObjectMutator.forDocument(PdfDocument document) =>
      PdfLoadedObjectMutator(PdfObjectStore.forDocument(document));

  /// The object resolution used to read the original value.
  final PdfObjectStore store;

  /// The edited document.
  PdfDocument get document => store.document;

  /// The dictionary of [reference], ready to take changes.
  ///
  /// Returns `null` when the reference does not resolve to a dictionary.
  PdfDict<PdfDataType>? dictFor(PdfIndirect reference) {
    final existing = _materialized(reference);
    if (existing is PdfDict<PdfDataType>) return existing;

    final source = store.resolveDict(reference);
    if (source == null) return null;

    // Shallow copy: the values keep pointing to the same objects, which stay
    // in the original file.
    final copy =
        PdfDict<PdfDataType>.values(Map<String, PdfDataType>.of(source.values));
    _replace(reference, copy);
    return copy;
  }

  /// The array of [reference], ready to take changes.
  PdfArray<PdfDataType>? arrayFor(PdfIndirect reference) {
    final existing = _materialized(reference);
    if (existing is PdfArray<PdfDataType>) return existing;

    final source = store.resolveArray(reference);
    if (source == null) return null;

    final copy = PdfArray<PdfDataType>(List<PdfDataType>.of(source.values));
    _replace(reference, copy);
    return copy;
  }

  /// The already materialized content of [reference], if there is a usable one.
  PdfDataType? _materialized(PdfIndirect reference) {
    final id = PdfObjectId.fromIndirect(reference);
    if (!store.containsId(id)) return null;
    return store.lookupId(id)?.params;
  }

  /// Writes [value] as the new content of the object pointed to by [reference].
  void _replace(PdfIndirect reference, PdfDataType value) {
    PdfObject<PdfDataType>(
      document,
      objser: reference.ser,
      objgen: reference.gen,
      params: value,
    );
    // The store index rebuilds itself when `document.objects` changes size,
    // but invalidating makes the intent explicit and covers the rare case
    // where another removal kept the size.
    store.invalidate();
  }
}

/// The existing normal appearance (`/AP /N`) of an annotation.
///
/// The form XObject is still the object from the original file: only its
/// identity, its `/BBox` and its `/Matrix` travel here, which is what is needed
/// to position it on the page.
class PdfAppearanceStream {
  /// Describes the appearance from the already resolved data.
  const PdfAppearanceStream({
    required this.id,
    required this.bbox,
    required this.matrix,
    this.stateName,
  });

  /// Identity of the form XObject in the document.
  final PdfObjectId id;

  /// The `/BBox` of the form, already normalized.
  final PdfBox bbox;

  /// The `/Matrix` of the form, as `[a b c d e f]`; identity when absent.
  final List<double> matrix;

  /// Name of the state chosen in `/AP /N`, when `/N` is a dictionary of states
  /// (`/Off`, `/Yes`, ...). `null` when `/N` already is the form.
  final String? stateName;

  /// The `/BBox` after being transformed by the `/Matrix`.
  ///
  /// It is the rectangle the reader actually paints, and it is over it — not
  /// over the raw `/BBox` — that the scale up to the widget `/Rect` is
  /// computed.
  PdfBox get transformedBBox {
    final a = matrix[0];
    final b = matrix[1];
    final c = matrix[2];
    final d = matrix[3];
    final e = matrix[4];
    final f = matrix[5];

    final xs = <double>[];
    final ys = <double>[];
    for (final corner in <List<double>>[
      <double>[bbox.left, bbox.bottom],
      <double>[bbox.right, bbox.bottom],
      <double>[bbox.right, bbox.top],
      <double>[bbox.left, bbox.top],
    ]) {
      xs.add(a * corner[0] + c * corner[1] + e);
      ys.add(b * corner[0] + d * corner[1] + f);
    }

    return PdfBox(
      xs.reduce((p, e) => p < e ? p : e),
      ys.reduce((p, e) => p < e ? p : e),
      xs.reduce((p, e) => p > e ? p : e),
      ys.reduce((p, e) => p > e ? p : e),
    );
  }

  /// The `cm` matrix that brings this appearance inside [rect].
  ///
  /// It is the PDFBox path (`PDAcroForm.resolveTransformationMatrix`): the
  /// transformed `/BBox` is scaled up to the size of the widget `/Rect` and
  /// then shifted to its lower-left corner. A zero dimension in the
  /// transformed box does not cause a division by zero: the scale stays at 1.
  List<double> placementMatrix(PdfBox rect) {
    final source = transformedBBox;
    final scaleX = source.width > 0 ? rect.width / source.width : 1.0;
    final scaleY = source.height > 0 ? rect.height / source.height : 1.0;
    return <double>[
      scaleX,
      0,
      0,
      scaleY,
      rect.left - source.left * scaleX,
      rect.bottom - source.bottom * scaleY,
    ];
  }

  @override
  String toString() =>
      'PdfAppearanceStream($id, bbox: $bbox, state: $stateName)';
}

/// Mirror of a form XObject that stays in the bytes of the loaded document.
///
/// `PdfGraphics.drawFormXObject` needs a [PdfXObject] to register the resource
/// on the page and write `/Name Do`. The appearance of a loaded annotation is
/// not a [PdfXObject]: it is an object from the original file that must not be
/// copied nor rewritten. This mirror supplies only the two things the drawing
/// consumes — the resource name and the indirect reference — and leaves
/// `document.objects` in the constructor, so that the writer never serializes
/// it and erases the real appearance.
class _MirroredFormXObject extends PdfXObject {
  _MirroredFormXObject._(PdfDocument document, this.source)
      : super(document, null) {
    document.objects.remove(this);
  }

  /// The mirror of [source] in [document], created a single time.
  ///
  /// The [PdfObject] constructor consumes one object number of the document.
  /// Without the cache, an appearance shared by dozens of pages — the header
  /// stamp of a report, for instance — would spend one number per page, all of
  /// them for objects that will never be written.
  factory _MirroredFormXObject.of(PdfDocument document, PdfObjectId source) {
    final cache = _cache[document] ??= <PdfObjectId, _MirroredFormXObject>{};
    return cache[source] ??= _MirroredFormXObject._(document, source);
  }

  static final Expando<Map<PdfObjectId, _MirroredFormXObject>> _cache =
      Expando<Map<PdfObjectId, _MirroredFormXObject>>('mirroredFormXObjects');

  /// Identity of the mirrored object.
  final PdfObjectId source;

  @override
  PdfIndirect ref() => source.toIndirect();

  @override
  String get name => '/Xap${source.number}_${source.generation}';
}

/// Draws existing appearances onto a page.
///
/// Every write goes through the [PdfPageContentEditor]: the original page
/// content is not touched and the drawing stays isolated in `q ... Q`. The form
/// XObject is not copied — the page only gains, in `/Resources /XObject`, a new
/// name pointing to the object that was already in the file.
class PdfAppearancePainter {
  /// Creates the painter of page [page].
  PdfAppearancePainter(this.page) : editor = PdfPageContentEditor(page);

  /// The painted page.
  final PdfPage page;

  /// The content editor that wraps the original content.
  final PdfPageContentEditor editor;

  /// Coordinate converter of the page.
  PdfCoordinateTransformer get transformer => editor.transformer;

  /// Paints [appearance] inside [rect], in user space coordinates.
  void paint(PdfAppearanceStream appearance, PdfBox rect) {
    final mirror =
        _MirroredFormXObject.of(page.pdfDocument, appearance.id);

    editor.drawOverlay((canvas) {
      canvas.drawFormXObject(
        mirror,
        matrix: appearance.placementMatrix(rect.normalized()),
      );
    });

    _isolateXObjectResources();
  }

  /// Gives the page an `/XObject` of its own before `prepare()` writes into it.
  ///
  /// When the page `/Resources` was an indirect reference, the content editor
  /// materializes a **shallow** copy of the original dictionary; the `/XObject`
  /// sub-dictionary is still the same instance on every page that shares that
  /// resource object. Without this copy, the name registered for one page would
  /// show up on the others too — a useless resource, not a broken reference,
  /// but predictable garbage all the same.
  void _isolateXObjectResources() {
    final resources = page.params[PdfNameTokens.resources];
    if (resources is! PdfDict) return;
    if (identical(resources, _isolatedFor)) return;

    final xObjects = resources[PdfNameTokens.xObject];
    if (xObjects is PdfDict) {
      resources[PdfNameTokens.xObject] = PdfDict<PdfDataType>.values(
        Map<String, PdfDataType>.of(xObjects.values),
      );
    }
    _isolatedFor = resources;
  }

  PdfDict? _isolatedFor;
}

/// Single access point to the document `/AcroForm` during editing.
///
/// The roadmap (§3, item D3) records that `PdfAcroForm`,
/// `PdfSignatureFieldEditor`, `PdfAnnotWidget` and `PdfCatalog.prepare()` touch
/// `/AcroForm` and `/Fields` through different paths, which produces a
/// duplicated field, an orphan one, or one removed from a single tree. This
/// class is the single path of the two new deliveries — the annotation
/// collection and the flattener — until the `PdfFormEditor` from phase F6
/// actually exists.
class PdfAcroFormAccess {
  /// Creates the access to the form of [document].
  PdfAcroFormAccess(this.document, this.mutator);

  /// Creates the access with a materializer of its own.
  factory PdfAcroFormAccess.forDocument(PdfDocument document) =>
      PdfAcroFormAccess(document, PdfLoadedObjectMutator.forDocument(document));

  /// The edited document.
  final PdfDocument document;

  /// The materializer of loaded objects.
  final PdfLoadedObjectMutator mutator;

  PdfObjectStore get _store => mutator.store;

  /// Whether the catalog declares an `/AcroForm`.
  bool get exists =>
      document.catalog.params.containsKey(PdfNameTokens.acroForm);

  /// The resolved `/AcroForm` dictionary, read only.
  PdfDict? get dictionary =>
      _store.resolveDict(document.catalog.params[PdfNameTokens.acroForm]);

  /// The resolved `/Fields` array, read only.
  PdfArray? get fields => _store.resolveArray(dictionary?[PdfNameTokens.fields]);

  /// The `/AcroForm` dictionary ready for writing, or `null` if there is none.
  PdfDict<PdfDataType>? writableDictionary() {
    final value = document.catalog.params[PdfNameTokens.acroForm];
    if (value is PdfDict<PdfDataType>) return value;
    if (value is PdfIndirect) return mutator.dictFor(value);
    if (value is PdfDict) {
      // Direct dictionary with a narrower type: copy it so that any value can
      // be written into it.
      final copy = PdfDict<PdfDataType>.values(
          Map<String, PdfDataType>.of(value.values));
      document.catalog.params[PdfNameTokens.acroForm] = copy;
      return copy;
    }
    return null;
  }

  /// The `/Fields` array ready for writing, or `null` if there is none.
  PdfArray<PdfDataType>? writableFields() {
    final form = writableDictionary();
    if (form == null) return null;
    final value = form[PdfNameTokens.fields];
    if (value is PdfArray<PdfDataType>) return value;
    if (value is PdfIndirect) return mutator.arrayFor(value);
    if (value is PdfArray) {
      final copy = PdfArray<PdfDataType>(List<PdfDataType>.of(value.values));
      form[PdfNameTokens.fields] = copy;
      return copy;
    }
    return null;
  }

  /// Removes from `/Fields` the entry that points to [reference].
  ///
  /// Looks in the root first and then descends through `/Kids`. An intermediate
  /// node left without children is removed along with it: a field with no
  /// widget and no `/Kids` is no longer reachable by the reader, and leaving it
  /// pointing to nothing is exactly the inconsistency item D3 of the roadmap
  /// describes.
  ///
  /// Returns `true` when some entry was taken out.
  bool removeField(PdfIndirect reference) {
    final fields = writableFields();
    if (fields == null) return false;
    return _removeFromFieldList(fields, reference, 0);
  }

  bool _removeFromFieldList(
    PdfArray<PdfDataType> list,
    PdfIndirect reference,
    int depth,
  ) {
    if (depth > 32) return false;

    final index = list.values.indexWhere(
      (value) => value is PdfIndirect && value == reference,
    );
    if (index >= 0) {
      list.values.removeAt(index);
      return true;
    }

    for (var i = 0; i < list.values.length; i++) {
      final entry = list.values[i];
      if (entry is! PdfIndirect) continue;

      final kidsValue = _store.resolveDict(entry)?[PdfNameTokens.kids];
      if (kidsValue == null) continue;

      final field = mutator.dictFor(entry);
      if (field == null) continue;

      final kids = _writableChildList(field);
      if (kids == null) continue;

      if (!_removeFromFieldList(kids, reference, depth + 1)) continue;

      if (kids.values.isEmpty) {
        field.values.remove(PdfNameTokens.kids);
        // An intermediate node with no children and no widget of its own
        // draws nothing.
        if (!field.containsKey(PdfNameTokens.subtype)) {
          list.values.removeAt(i);
        }
      }
      return true;
    }

    return false;
  }

  /// The `/Kids` of [field] ready for writing.
  PdfArray<PdfDataType>? _writableChildList(PdfDict<PdfDataType> field) {
    final value = field[PdfNameTokens.kids];
    if (value is PdfArray<PdfDataType>) return value;
    if (value is PdfIndirect) return mutator.arrayFor(value);
    if (value is PdfArray) {
      final copy = PdfArray<PdfDataType>(List<PdfDataType>.of(value.values));
      field[PdfNameTokens.kids] = copy;
      return copy;
    }
    return null;
  }

  /// Deletes `/NeedAppearances`: after flattening there is no appearance to
  /// regenerate.
  void removeNeedAppearances() {
    writableDictionary()?.values.remove(PdfNameTokens.needAppearances);
  }

  /// Takes the `/AcroForm` out of the catalog when no field is left.
  ///
  /// Returns `true` when the dictionary was removed.
  bool removeWhenEmpty() {
    final form = writableDictionary();
    if (form == null) return false;

    final fields = writableFields();
    if (fields != null && fields.values.isNotEmpty) return false;

    document.catalog.params.values.remove(PdfNameTokens.acroForm);
    return true;
  }
}

/// Typed view of an annotation already present on a loaded page.
///
/// The view does **not** duplicate the object: it reads through the
/// [PdfObjectStore] and, on the first change, materializes a replacement with
/// the same number, the way the incremental update requires.
class PdfAnnotationView {
  PdfAnnotationView._(this._collection, this.reference, this._direct);

  final PdfAnnotationCollection _collection;

  /// The dictionary when the annotation is written directly inside `/Annots`.
  ///
  /// The entry is located by identity, not by index: removing another
  /// annotation of the same page shifts the positions, and a view kept from
  /// before would delete the wrong entry.
  final PdfDict? _direct;

  /// The indirect reference of the annotation, or `null` when it is written
  /// directly inside the `/Annots` array of the page.
  final PdfIndirect? reference;

  /// The page that owns the annotation.
  PdfPage get page => _collection.page;

  PdfObjectStore get _store => _collection.store;

  /// The annotation dictionary, for reading.
  PdfDict get dictionary {
    final ref = reference;
    if (ref != null) {
      return _store.resolveDict(ref) ?? PdfDict<PdfDataType>();
    }
    return _direct ?? PdfDict<PdfDataType>();
  }

  /// The annotation dictionary, ready for writing.
  ///
  /// Returns `null` when the annotation cannot be materialized.
  PdfDict<PdfDataType>? writableDictionary() {
    final ref = reference;
    if (ref != null) return _collection.mutator.dictFor(ref);

    // The annotation written directly in the array already belongs to the
    // page: the dictionary converted by the parser is an instance exclusive to
    // it, and writing into it affects nobody else.
    return _direct;
  }

  /// The `/Subtype` of the annotation, with the leading slash (`/Link`,
  /// `/Widget`, ...).
  String? get subtype {
    final value = dictionary[PdfNameTokens.subtype];
    return value is PdfName ? value.value : null;
  }

  /// Whether the annotation is a form widget.
  bool get isWidget => subtype == PdfNameTokens.widget;

  /// The `/Rect` of the annotation, in user space and already normalized.
  PdfBox? get rect {
    final value = _store.resolveArray(dictionary[PdfNameTokens.rect]);
    return PdfBox.tryFromArray(value)?.normalized();
  }

  /// Writes the `/Rect` of the annotation, in user space.
  set rect(PdfBox? value) {
    final target = writableDictionary();
    if (target == null) return;
    if (value == null) {
      target.values.remove(PdfNameTokens.rect);
    } else {
      target[PdfNameTokens.rect] = value.toPdfArray();
    }
  }

  /// The `/Rect` in "top-left" coordinates, as the user sees the page.
  PdfTopLeftRect? get rectTopLeft {
    final box = rect;
    if (box == null) return null;
    return _collection.transformer.rectToTopLeft(box.toRect());
  }

  /// Writes the `/Rect` from "top-left" coordinates.
  set rectTopLeft(PdfTopLeftRect? value) {
    if (value == null) {
      rect = null;
      return;
    }
    rect = PdfBox.fromRect(_collection.transformer.rectFromTopLeftRect(value));
  }

  /// The text of `/Contents`, or `null` when absent.
  String? get contents => _decodeText(dictionary[PdfNameTokens.contents]);

  /// Writes `/Contents`; `null` removes the key.
  set contents(String? value) {
    final target = writableDictionary();
    if (target == null) return;
    if (value == null) {
      target.values.remove(PdfNameTokens.contents);
    } else {
      target[PdfNameTokens.contents] = PdfString.fromString(value);
    }
  }

  /// The unique name of the annotation (`/NM`), or `null` when absent.
  String? get name => _decodeText(dictionary[PdfNameTokens.nm]);

  /// Writes `/NM`; `null` removes the key.
  set name(String? value) {
    final target = writableDictionary();
    if (target == null) return;
    if (value == null) {
      target.values.remove(PdfNameTokens.nm);
    } else {
      target[PdfNameTokens.nm] = PdfString.fromString(value);
    }
  }

  /// The raw value of `/F`, or 0 when absent.
  int get flags {
    final value = _store.resolve(dictionary[PdfNameTokens.f]);
    return value is PdfNum ? value.value.toInt() : 0;
  }

  /// Writes `/F`.
  set flags(int value) {
    final target = writableDictionary();
    if (target == null) return;
    target[PdfNameTokens.f] = PdfNum(value);
  }

  /// `/F` read as a set of flags.
  Set<PdfAnnotFlags> get flagSet {
    final value = flags;
    return <PdfAnnotFlags>{
      for (final flag in PdfAnnotFlags.values)
        if (value & (1 << flag.index) != 0) flag,
    };
  }

  /// Writes `/F` from a set of flags.
  set flagSet(Set<PdfAnnotFlags> value) {
    var encoded = 0;
    for (final flag in value) {
      encoded |= 1 << flag.index;
    }
    flags = encoded;
  }

  /// Turns a `/F` flag on or off.
  void setFlag(PdfAnnotFlags flag, bool enabled) {
    final bit = 1 << flag.index;
    flags = enabled ? (flags | bit) : (flags & ~bit);
  }

  /// Whether the annotation is marked as invisible to the reader.
  bool get isHidden =>
      flags & (1 << PdfAnnotFlags.hidden.index) != 0 ||
      flags & (1 << PdfAnnotFlags.noView.index) != 0;

  /// The `/C` color of the annotation, or `null` when absent or transparent.
  ///
  /// An array of one number is gray, of three is RGB and of four is CMYK; the
  /// empty array means transparent, and becomes `null`.
  PdfColor? get color {
    final value = _store.resolveArray(dictionary[PdfNameTokens.c]);
    if (value == null) return null;

    final components = <double>[];
    for (final item in value.values) {
      if (item is! PdfNum) return null;
      components.add(item.value.toDouble().clamp(0.0, 1.0));
    }

    switch (components.length) {
      case 1:
        return PdfColor(components[0], components[0], components[0]);
      case 3:
        return PdfColor(components[0], components[1], components[2]);
      case 4:
        return PdfColorCmyk(
            components[0], components[1], components[2], components[3]);
      default:
        return null;
    }
  }

  /// Writes `/C`; `null` removes the key.
  set color(PdfColor? value) {
    final target = writableDictionary();
    if (target == null) return;
    if (value == null) {
      target.values.remove(PdfNameTokens.c);
    } else {
      target[PdfNameTokens.c] = PdfArray.fromColor(value);
    }
  }

  /// The normal appearance of this annotation, or `null` when there is no
  /// usable one.
  ///
  /// When `/AP /N` is a dictionary of states, the state is chosen by `/AS`; if
  /// there is a single state and no `/AS`, that one is used. A dictionary of
  /// several states without `/AS` is ambiguous and returns `null` — making the
  /// state up would mean deciding for the document.
  PdfAppearanceStream? get normalAppearance {
    final appearances = _store.resolveDict(dictionary[PdfNameTokens.ap]);
    if (appearances == null) return null;

    final normal = appearances[PdfNameTokens.n];
    final direct = _formStream(normal, null);
    if (direct != null) return direct;

    final states = _store.resolveDict(normal);
    if (states == null) return null;

    final selected = dictionary[PdfNameTokens.as];
    var state = selected is PdfName ? selected.value : null;
    if (state == null && states.values.length == 1) {
      state = states.values.keys.first;
    }
    if (state == null) return null;

    return _formStream(states[state], state);
  }

  /// Why [normalAppearance] returned `null`, for use in warnings.
  ///
  /// `null` when there is a usable appearance.
  String? get missingAppearanceReason {
    if (normalAppearance != null) return null;

    final appearances = _store.resolveDict(dictionary[PdfNameTokens.ap]);
    if (appearances == null) return 'sem /AP';

    final normal = appearances[PdfNameTokens.n];
    if (normal == null) return 'com /AP, mas sem /AP /N';

    final states = _store.resolveDict(normal);
    if (states != null && !states.containsKey(PdfNameTokens.bbox)) {
      final selected = dictionary[PdfNameTokens.as];
      if (selected is! PdfName && states.values.length > 1) {
        return 'com /AP /N em ${states.values.length} estados '
            '(${states.values.keys.join(', ')}) e sem /AS que escolha um';
      }
      return 'com /AP /N em estados, mas o estado escolhido não é um form '
          'XObject com /BBox';
    }

    return 'com /AP /N que não é um form XObject com /BBox';
  }

  PdfAppearanceStream? _formStream(PdfDataType? value, String? stateName) {
    if (value is! PdfIndirect) return null;

    final form = _store.resolveDict(value);
    if (form == null) return null;

    final bbox = PdfBox.tryFromArray(
      _store.resolveArray(form[PdfNameTokens.bbox]),
    );
    if (bbox == null) return null;

    return PdfAppearanceStream(
      id: PdfObjectId.fromIndirect(value),
      bbox: bbox.normalized(),
      matrix: _readMatrix(_store.resolveArray(form[PdfNameTokens.matrix])),
      stateName: stateName,
    );
  }

  @override
  String toString() =>
      'PdfAnnotationView($subtype, ${reference ?? 'direto'}, rect: $rect)';
}

/// Typed collection of the annotations already present on a page.
///
/// It is gap §2.2 item 3 of the roadmap: there were classes to **create**
/// annotations ([PdfAnnot]), but none to list, change, remove or flatten the
/// ones that came from the file. The collection works over the `/Annots` array
/// of the page and over the dictionaries resolved by the [PdfObjectStore],
/// without duplicating an object.
///
/// ```dart
/// final document = PdfDocument.parseFromBytes(bytes);
/// final annotations = PdfAnnotationCollection.onPage(document, 1);
/// for (final annotation in annotations.annotations) {
///   print('${annotation.subtype} ${annotation.rect}');
/// }
/// annotations.annotations.first.contents = 'Revisar';
/// annotations.remove(annotations.annotations.last);
/// final bytes = await document.save();
/// ```
///
/// ## Known limits
///
/// - the two-way coherence with `/Popup`, `/Parent` and `/IRT` planned for F5
///   is not maintained yet: removing an annotation does not remove its popup;
/// - `/P` is not rewritten, because the annotation stays on the same page;
/// - there is no appearance generation. [flatten] draws the appearance that
///   already exists and refuses the annotation that has none.
class PdfAnnotationCollection {
  /// Creates the collection of the annotations of [page].
  ///
  /// [store], [mutator] and [acroForm] exist for whoever edits several pages in
  /// the same operation — the form flattener, for instance — and needs all of
  /// them to share the same resolution and the same materializer. When omitted,
  /// the collection creates its own.
  factory PdfAnnotationCollection(
    PdfPage page, {
    PdfObjectStore? store,
    PdfLoadedObjectMutator? mutator,
    PdfAcroFormAccess? acroForm,
  }) {
    final resolvedStore = store ??
        mutator?.store ??
        acroForm?.mutator.store ??
        PdfObjectStore.forDocument(page.pdfDocument);
    final resolvedMutator =
        mutator ?? acroForm?.mutator ?? PdfLoadedObjectMutator(resolvedStore);
    return PdfAnnotationCollection._(
      page,
      resolvedStore,
      resolvedMutator,
      acroForm ?? PdfAcroFormAccess(page.pdfDocument, resolvedMutator),
    );
  }

  PdfAnnotationCollection._(
    this.page,
    this.store,
    this.mutator,
    this.acroForm,
  )   : document = page.pdfDocument,
        transformer = PdfCoordinateTransformer.forPage(page);

  /// Creates the collection of the page with index [pageIndex] (zero based).
  factory PdfAnnotationCollection.onPage(PdfDocument document, int pageIndex) {
    final pages = PdfPageContentEditor.distinctPages(document);
    if (pageIndex < 0 || pageIndex >= pages.length) {
      throw RangeError.index(pageIndex, pages, 'pageIndex');
    }
    return PdfAnnotationCollection(pages[pageIndex]);
  }

  /// The page whose annotations the collection sees.
  final PdfPage page;

  /// The document that owns the page.
  final PdfDocument document;

  /// The object resolution, with a fallback to the source parser.
  final PdfObjectStore store;

  /// The materializer used in the changes.
  final PdfLoadedObjectMutator mutator;

  /// The single path for changing the `/AcroForm`.
  final PdfAcroFormAccess acroForm;

  /// Coordinate converter of this page.
  final PdfCoordinateTransformer transformer;

  final List<String> _warnings = <String>[];
  List<PdfAnnotationView>? _views;
  PdfAppearancePainter? _painter;

  /// What the collection could not do, in the order it happened.
  List<String> get warnings => List<String>.unmodifiable(_warnings);

  /// The annotations of the page, in the order of the `/Annots` array.
  List<PdfAnnotationView> get annotations => _views ??= _buildViews();

  /// Number of annotations.
  int get length => annotations.length;

  /// The annotation at index [index].
  PdfAnnotationView operator [](int index) => annotations[index];

  /// The annotations of a specific `/Subtype`, for example `/Link`.
  Iterable<PdfAnnotationView> whereSubtype(String subtype) =>
      annotations.where((view) => view.subtype == subtype);

  /// The annotation whose `/NM` equals [name], or `null`.
  PdfAnnotationView? byName(String name) {
    for (final view in annotations) {
      if (view.name == name) return view;
    }
    return null;
  }

  /// The appearance painter of this page, created on demand.
  ///
  /// Instantiating the [PdfPageContentEditor] already adds the pair of streams
  /// that wraps the original content, so it is only born when some appearance
  /// is really going to be drawn.
  PdfAppearancePainter get painter => _painter ??= PdfAppearancePainter(page);

  /// Removes [view] from the page.
  ///
  /// Takes the entry out of `/Annots` and, when the annotation is a form
  /// widget, out of `/AcroForm /Fields` too. Returns `true` when something was
  /// removed.
  bool remove(PdfAnnotationView view) {
    final annots = _writableAnnots();
    if (annots == null) return false;

    final removed = _removeEntry(annots, view);
    if (!removed) {
      _warnings.add('Anotação ${view.reference ?? 'direta'} não está em '
          '/Annots da página ${page.objser}.');
      return false;
    }

    final reference = view.reference;
    if (view.isWidget && reference != null) {
      acroForm.removeField(reference);
    }

    _views?.remove(view);
    return true;
  }

  /// Flattens [view]: draws its normal appearance on the page and removes it.
  ///
  /// Refuses and records a warning when the annotation has no usable `/AP /N`
  /// or has no `/Rect`: claiming it was flattened without drawing anything
  /// would lose the content silently. Returns `true` when the annotation was
  /// drawn and removed.
  bool flatten(PdfAnnotationView view) {
    final rect = view.rect;
    if (rect == null || rect.isEmpty) {
      _warnings.add('Anotação ${view.reference ?? 'direta'} sem /Rect '
          'utilizável: não foi achatada.');
      return false;
    }

    final appearance = view.normalAppearance;
    if (appearance == null) {
      _warnings.add('Anotação ${view.reference ?? 'direta'} '
          '${view.missingAppearanceReason ?? 'sem /AP /N utilizável'}: '
          'não foi achatada.');
      return false;
    }

    painter.paint(appearance, rect);
    return remove(view);
  }

  /// Flattens every annotation that has an appearance.
  ///
  /// The ones that do not stay on the page, each with a warning in [warnings].
  /// Returns how many were flattened.
  int flattenAll() {
    var count = 0;
    for (final view in List<PdfAnnotationView>.of(annotations)) {
      if (flatten(view)) count++;
    }
    return count;
  }

  List<PdfAnnotationView> _buildViews() {
    final annots = _readableAnnots();
    if (annots == null) return <PdfAnnotationView>[];

    final views = <PdfAnnotationView>[];
    for (var i = 0; i < annots.values.length; i++) {
      final entry = annots.values[i];
      if (entry is PdfIndirect) {
        if (store.resolveDict(entry) == null) {
          _warnings.add('Entrada $i de /Annots aponta para $entry, que não '
              'resolve; ignorada.');
          continue;
        }
        views.add(PdfAnnotationView._(this, entry, null));
        continue;
      }
      if (entry is PdfDict) {
        views.add(PdfAnnotationView._(this, null, entry));
      }
    }
    return views;
  }

  /// The `/Annots` array of the page, for reading.
  PdfArray? _readableAnnots() {
    final value = page.params[PdfNameTokens.annots];
    if (value is PdfArray) return value;
    if (value is PdfIndirect) return store.resolveArray(value);
    return null;
  }

  /// The `/Annots` array of the page, ready for writing.
  ///
  /// When `/Annots` is still an indirect reference — the parser usually
  /// materializes it when loading the page, but not always — the array is
  /// copied into the page dictionary. The original object is left unreferenced,
  /// not dangling.
  PdfArray<PdfDataType>? _writableAnnots() {
    final value = page.params[PdfNameTokens.annots];
    if (value is PdfArray<PdfDataType>) return value;
    if (value is PdfArray) {
      final copy = PdfArray<PdfDataType>(List<PdfDataType>.of(value.values));
      page.params[PdfNameTokens.annots] = copy;
      return copy;
    }
    if (value is PdfIndirect) {
      final source = store.resolveArray(value);
      if (source == null) return null;
      final copy = PdfArray<PdfDataType>(List<PdfDataType>.of(source.values));
      page.params[PdfNameTokens.annots] = copy;
      return copy;
    }
    return null;
  }

  bool _removeEntry(PdfArray<PdfDataType> annots, PdfAnnotationView view) {
    final reference = view.reference;
    if (reference != null) {
      final before = annots.values.length;
      annots.values.removeWhere(
        (value) => value is PdfIndirect && value == reference,
      );
      return annots.values.length != before;
    }

    final direct = view._direct;
    if (direct == null) return false;
    final index = annots.values.indexWhere((e) => identical(e, direct));
    if (index < 0) return false;
    annots.values.removeAt(index);
    return true;
  }
}

/// Reads the `/Matrix` of a form XObject; absent or invalid becomes identity.
List<double> _readMatrix(PdfArray? value) {
  const identity = <double>[1, 0, 0, 1, 0, 0];
  if (value == null || value.values.length != 6) return identity;

  final matrix = <double>[];
  for (final item in value.values) {
    if (item is! PdfNum) return identity;
    final number = item.value.toDouble();
    if (!number.isFinite) return identity;
    matrix.add(number);
  }
  return matrix;
}

/// Converts a PDF string into text.
///
/// The `FE FF` prefix marks UTF-16BE; without it the specification requires
/// PDFDocEncoding, whose overlap with latin-1 covers what shows up in
/// `/Contents` and `/NM`.
String? _decodeText(PdfDataType? value) {
  if (value is! PdfString) return null;
  final bytes = value.value;

  if (bytes.length >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff) {
    final units = <int>[];
    for (var i = 2; i + 1 < bytes.length; i += 2) {
      units.add((bytes[i] << 8) | bytes[i + 1]);
    }
    return String.fromCharCodes(units);
  }

  try {
    return latin1.decode(Uint8List.fromList(bytes));
  } catch (_) {
    return String.fromCharCodes(bytes);
  }
}
