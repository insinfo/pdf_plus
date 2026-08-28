import 'dart:convert';
import 'dart:typed_data';

import '../document.dart';
import '../format/array.dart';
import '../format/base.dart';
import '../format/dict.dart';
import '../format/indirect.dart';
import '../format/name.dart';
import '../format/string.dart';
import '../obj/page.dart';
import '../pdf_names.dart';
import 'object_graph/pdf_object_store.dart';
import 'pdf_annotation_collection.dart';
import 'pdf_box.dart';
import 'pdf_coordinate_transformer.dart';
import 'pdf_page_content_editor.dart';

/// What to do with a widget the reader does not show.
///
/// A widget with `/F` marked as `hidden` or `noView`, or with a `/Rect` with no
/// area, draws nothing on screen. PDFBox skips drawing it and removes the field
/// anyway; keeping it is the conservative choice, and it is the one that
/// preserves an invisible signature field.
enum PdfInvisibleFieldPolicy {
  /// Removes the field without drawing, recording a warning. It is the default,
  /// and it is the PDFBox behavior.
  remove,

  /// Keeps the field as it is, recording a warning.
  keep,
}

/// Flattening options.
class PdfFormFlattenOptions {
  /// Creates the options.
  const PdfFormFlattenOptions({
    this.invisibleFields = PdfInvisibleFieldPolicy.remove,
    this.removeAcroFormWhenEmpty = true,
  });

  /// What to do with a widget that does not appear on screen.
  final PdfInvisibleFieldPolicy invisibleFields;

  /// Whether the `/AcroForm` should leave the catalog when no field is left.
  ///
  /// With `false`, the dictionary stays in place with an empty `/Fields` —
  /// useful for whoever needs to preserve `/DR` or `/DA` for a later step.
  final bool removeAcroFormWhenEmpty;
}

/// A field that the flattening drew and removed.
class PdfFlattenedField {
  /// Records the flattened field.
  const PdfFlattenedField({
    required this.name,
    required this.fieldType,
    required this.pageIndex,
    required this.rect,
    required this.displayRect,
    required this.appearance,
    required this.appearanceState,
  });

  /// Fully qualified name of the field (`parent.child`).
  final String name;

  /// The effective `/FT`, already accounting for inheritance: `/Tx`, `/Btn`,
  /// `/Ch` or `/Sig`.
  final String? fieldType;

  /// Page index, zero based.
  final int pageIndex;

  /// The area taken up, in user space.
  final PdfBox rect;

  /// The same area in "top-left" coordinates, as the user sees the page.
  final PdfTopLeftRect displayRect;

  /// The form XObject that was drawn, which is still the object from the
  /// original file: the flattening references the appearance, it does not copy
  /// it.
  final PdfObjectId appearance;

  /// The `/AP /N` state used, when `/N` was a dictionary of states.
  final String? appearanceState;

  @override
  String toString() => 'PdfFlattenedField($name, página $pageIndex, $rect)';
}

/// The result of the flattening.
class PdfFormFlattenResult {
  /// Builds the result.
  const PdfFormFlattenResult({
    required this.flattened,
    required this.warnings,
    required this.remainingFields,
    required this.acroFormRemoved,
  });

  /// The fields that were drawn and removed.
  final List<PdfFlattenedField> flattened;

  /// What could not be flattened, and why.
  final List<String> warnings;

  /// How many fields are still in `/AcroForm /Fields`.
  final int remainingFields;

  /// Whether the `/AcroForm` left the catalog.
  final bool acroFormRemoved;

  /// Whether every field was flattened, with nothing left pending.
  bool get isComplete => warnings.isEmpty && remainingFields == 0;

  @override
  String toString() => 'PdfFormFlattenResult(${flattened.length} achatados, '
      '$remainingFields restantes, ${warnings.length} avisos)';
}

/// A widget located in the field tree, with the name already qualified.
class _WidgetTarget {
  _WidgetTarget({
    required this.reference,
    required this.name,
    required this.fieldType,
  });

  final PdfIndirect reference;
  final String name;
  final String? fieldType;
}

/// Real form flattening: draws the appearance and deletes the field.
///
/// It is the missing delivery of phase F6 of the roadmap. The `flattenFields()`
/// of `PdfAcroForm` removes the `/AcroForm` without drawing anything — its
/// `_flattenField` is an empty skeleton — so the filled-in value disappears
/// from the page. Here the path is the PDFBox one (`PDAcroForm.flatten`):
///
/// 1. locate the widget in the `/Fields` tree, inheriting `/FT` and composing
///    the fully qualified name;
/// 2. take the form XObject of the normal appearance (`/AP /N`), choosing the
///    state by `/AS` when `/N` is a dictionary of states;
/// 3. draw that XObject on the page, scaled from the `/BBox` transformed by
///    the `/Matrix` up to the `/Rect` of the widget;
/// 4. only then remove the widget from `/Annots` and the field from
///    `/AcroForm /Fields`.
///
/// **No appearance is synthesized.** A field without a usable `/AP /N` raises
/// a warning and is **not** removed: claiming it was flattened without drawing
/// anything would lose the content silently (roadmap §9, "a flattened field
/// disappearing").
///
/// ```dart
/// final document = PdfDocument.parseFromBytes(bytes);
/// final result = PdfFormFlattener(document).flatten();
/// print('${result.flattened.length} campos achatados');
/// print(result.warnings);
/// final flat = await document.save();
/// ```
///
/// ## What the flattening covers
///
/// Any widget with a normal appearance, whatever the `/FT`: text, checkbox,
/// radio, button, combo, list and signature. What changes between them is only
/// the appearance already written, and that is what goes to the page. Fields
/// with `/Kids` are walked, and a widget with `/AP /N` in states picks the
/// state by `/AS` — that is how the mark of a checked checkbox is preserved.
///
/// ## What it does not cover
///
/// - **Generating an appearance.** `/NeedAppearances true` with a filled `/V`
///   and no `/AP` does not become drawing; the field survives with a warning.
///   That depends on the `PdfAppearanceService` planned for F5/F6.
/// - **`/AP /N` in states without `/AS`.** Picking a state would mean deciding
///   for the document; the field survives with a warning.
/// - **XFA.** A dynamic XFA form stays in the catalog; removing it is an
///   explicit option planned for F6.
/// - **Signatures.** Flattening invalidates any existing signature, like any
///   other content change.
class PdfFormFlattener {
  /// Creates the flattener for [document].
  PdfFormFlattener(
    this.document, {
    this.options = const PdfFormFlattenOptions(),
  })  : store = PdfObjectStore.forDocument(document),
        _pages = PdfPageContentEditor.distinctPages(document) {
    mutator = PdfLoadedObjectMutator(store);
    acroForm = PdfAcroFormAccess(document, mutator);
  }

  /// The edited document.
  final PdfDocument document;

  /// The flattening options.
  final PdfFormFlattenOptions options;

  /// The object resolution, with a fallback to the source parser.
  final PdfObjectStore store;

  /// The materializer shared by every change of this operation.
  late final PdfLoadedObjectMutator mutator;

  /// The single path for changing the `/AcroForm`.
  late final PdfAcroFormAccess acroForm;

  final List<PdfPage> _pages;
  final List<String> _warnings = <String>[];
  final Map<PdfPage, PdfAnnotationCollection> _collections =
      <PdfPage, PdfAnnotationCollection>{};

  Map<int, PdfPage>? _pagesByObject;
  Map<PdfIndirect, PdfPage>? _pagesByAnnotation;

  /// Flattens the form fields.
  ///
  /// Without [fieldNames], flattens all of them. With the list, only the fields
  /// whose fully qualified name is in it; the rest stay in the form and the
  /// `/AcroForm` remains in the catalog.
  PdfFormFlattenResult flatten({Iterable<String>? fieldNames}) {
    // The warnings belong to this call; the collections do not: calling
    // [flatten] again with another list of names has to reuse the content
    // editor already created for each page, otherwise the page would get a
    // second pair of streams wrapping the original content.
    _warnings.clear();

    if (!acroForm.exists) {
      _warnings.add('O documento não tem /AcroForm: nada a achatar.');
      return PdfFormFlattenResult(
        flattened: const <PdfFlattenedField>[],
        warnings: List<String>.unmodifiable(_warnings),
        remainingFields: 0,
        acroFormRemoved: false,
      );
    }

    final selected = fieldNames == null ? null : Set<String>.of(fieldNames);
    final targets = _collectWidgets();

    final flattened = <PdfFlattenedField>[];
    for (final target in targets) {
      if (selected != null && !selected.contains(target.name)) continue;
      final field = _flattenWidget(target);
      if (field != null) flattened.add(field);
    }

    if (selected != null) {
      for (final name in selected) {
        if (targets.any((target) => target.name == name)) continue;
        _warnings.add('Campo "$name" não existe no formulário.');
      }
    }

    // After flattening there is no appearance to regenerate; leaving
    // `/NeedAppearances true` would make the reader try to rebuild fields that
    // no longer exist.
    acroForm.removeNeedAppearances();

    final remaining = acroForm.fields?.values.length ?? 0;
    final removed = options.removeAcroFormWhenEmpty &&
        remaining == 0 &&
        acroForm.removeWhenEmpty();

    return PdfFormFlattenResult(
      flattened: List<PdfFlattenedField>.unmodifiable(flattened),
      warnings: List<String>.unmodifiable(_warnings),
      remainingFields: remaining,
      acroFormRemoved: removed,
    );
  }

  /// Draws and removes a widget; returns `null` when it survived.
  PdfFlattenedField? _flattenWidget(_WidgetTarget target) {
    final page = _pageOf(target.reference);
    if (page == null) {
      _warnings.add('Campo "${target.name}": não foi possível descobrir em que '
          'página está o widget ${target.reference}; mantido.');
      return null;
    }

    final collection = _collectionFor(page);
    final view = _viewOf(collection, target.reference);
    if (view == null) {
      _warnings.add('Campo "${target.name}": o widget ${target.reference} não '
          'está em /Annots da página; removido apenas de /Fields.');
      acroForm.removeField(target.reference);
      return null;
    }

    final rect = view.rect;
    final invisible = rect == null || rect.isEmpty || view.isHidden;
    if (invisible) {
      if (options.invisibleFields == PdfInvisibleFieldPolicy.keep) {
        _warnings.add('Campo "${target.name}": widget invisível '
            '(oculto ou sem área); mantido.');
        return null;
      }
      _warnings.add('Campo "${target.name}": widget invisível '
          '(oculto ou sem área); removido sem desenhar.');
      collection.remove(view);
      return null;
    }

    final appearance = view.normalAppearance;
    if (appearance == null) {
      // The hard rule: with no appearance written there is nothing to draw,
      // and removing would erase the field value from the page.
      _warnings.add('Campo "${target.name}": '
          '${view.missingAppearanceReason ?? 'sem /AP /N utilizável'}; '
          'mantido. O achatamento não sintetiza aparência.');
      return null;
    }

    collection.painter.paint(appearance, rect);

    if (!collection.remove(view)) {
      _warnings.add('Campo "${target.name}": a aparência foi desenhada, mas o '
          'widget não pôde ser removido de /Annots.');
      return null;
    }

    return PdfFlattenedField(
      name: target.name,
      fieldType: target.fieldType,
      pageIndex: _pageIndex[page] ?? -1,
      rect: rect,
      displayRect: collection.transformer.rectToTopLeft(rect.toRect()),
      appearance: appearance.id,
      appearanceState: appearance.stateName,
    );
  }

  /// Walks `/Fields` and returns the widgets, with a qualified name and an
  /// inherited `/FT`.
  List<_WidgetTarget> _collectWidgets() {
    final fields = acroForm.fields;
    if (fields == null) {
      _warnings.add('O /AcroForm não tem /Fields utilizável.');
      return const <_WidgetTarget>[];
    }

    final targets = <_WidgetTarget>[];
    final visited = <PdfIndirect>{};
    for (final entry in fields.values) {
      _collectField(entry, null, null, 0, visited, targets);
    }
    return targets;
  }

  void _collectField(
    PdfDataType? entry,
    String? parentName,
    String? inheritedType,
    int depth,
    Set<PdfIndirect> visited,
    List<_WidgetTarget> targets,
  ) {
    if (depth > 32) {
      _warnings.add('Árvore de campos com mais de 32 níveis a partir de '
          '"${parentName ?? '(raiz)'}"; ramo ignorado.');
      return;
    }

    if (entry is! PdfIndirect) {
      _warnings.add('Campo gravado diretamente em /Fields sob '
          '"${parentName ?? '(raiz)'}": achatar exigiria reescrever o array; '
          'mantido.');
      return;
    }
    if (!visited.add(entry)) return;

    final dict = store.resolveDict(entry);
    if (dict == null) {
      _warnings.add('Entrada $entry de /Fields não resolve; ignorada.');
      return;
    }

    final part = _decodeText(dict[PdfNameTokens.t]);
    final name = _composeName(parentName, part);

    final typeValue = dict[PdfNameTokens.ft];
    final fieldType = typeValue is PdfName ? typeValue.value : inheritedType;

    final kids = store.resolveArray(dict[PdfNameTokens.kids]);
    if (kids != null && kids.values.isNotEmpty) {
      for (final kid in kids.values) {
        final kidDict = store.resolveDict(kid);
        final isWidgetOnly = kidDict != null &&
            !kidDict.containsKey(PdfNameTokens.t) &&
            _isWidget(kidDict);
        if (isWidgetOnly && kid is PdfIndirect) {
          targets.add(_WidgetTarget(
            reference: kid,
            name: name,
            fieldType: fieldType,
          ));
          continue;
        }
        _collectField(kid, name, fieldType, depth + 1, visited, targets);
      }
      return;
    }

    if (_isWidget(dict)) {
      // Field and widget in the same object — the most common case.
      targets.add(_WidgetTarget(
        reference: entry,
        name: name,
        fieldType: fieldType,
      ));
      return;
    }

    _warnings.add('Campo "$name" não tem widget nem /Kids; mantido.');
  }

  bool _isWidget(PdfDict dict) {
    final subtype = dict[PdfNameTokens.subtype];
    if (subtype is PdfName) return subtype.value == PdfNameTokens.widget;
    // Some generators omit `/Subtype` on the object that joins field and
    // widget; having a `/Rect` is already enough for the reader to draw it.
    return dict.containsKey(PdfNameTokens.rect);
  }

  String _composeName(String? parentName, String? part) {
    if (parentName == null || parentName.isEmpty) return part ?? '';
    if (part == null || part.isEmpty) return parentName;
    return '$parentName.$part';
  }

  /// The annotation collection of the page, sharing store and materializer.
  PdfAnnotationCollection _collectionFor(PdfPage page) =>
      _collections[page] ??= PdfAnnotationCollection(
        page,
        store: store,
        mutator: mutator,
        acroForm: acroForm,
      );

  PdfAnnotationView? _viewOf(
    PdfAnnotationCollection collection,
    PdfIndirect reference,
  ) {
    for (final view in collection.annotations) {
      if (view.reference == reference) return view;
    }
    return null;
  }

  /// The page of the widget [reference], by `/P` and, failing that, by looking
  /// it up in `/Annots`.
  PdfPage? _pageOf(PdfIndirect reference) {
    final dict = store.resolveDict(reference);
    final parent = dict?[PdfNameTokens.p];
    if (parent is PdfIndirect) {
      final page = _pageByObject[parent.ser];
      if (page != null) return page;
    }
    return _pageByAnnotation[reference];
  }

  Map<int, PdfPage> get _pageByObject => _pagesByObject ??= <int, PdfPage>{
        for (final page in _pages) page.objser: page,
      };

  late final Map<PdfPage, int> _pageIndex = <PdfPage, int>{
    for (var i = 0; i < _pages.length; i++) _pages[i]: i,
  };

  Map<PdfIndirect, PdfPage> get _pageByAnnotation {
    var index = _pagesByAnnotation;
    if (index != null) return index;

    index = <PdfIndirect, PdfPage>{};
    for (final page in _pages) {
      final value = page.params[PdfNameTokens.annots];
      final annots =
          value is PdfArray ? value : store.resolveArray(value);
      if (annots == null) continue;
      for (final entry in annots.values) {
        if (entry is PdfIndirect) index.putIfAbsent(entry, () => page);
      }
    }
    _pagesByAnnotation = index;
    return index;
  }
}

/// Converts a PDF string into text, the way `/T` stores it.
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
