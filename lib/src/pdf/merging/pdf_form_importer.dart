import 'dart:convert';
import 'dart:typed_data';

import '../format/array.dart';
import '../format/bool.dart';
import '../format/dict.dart';
import '../format/num.dart';
import '../format/string.dart';
import '../obj/object.dart';
import '../parsing/parser_objects.dart';
import '../parsing/parser_tokens.dart';
import '../parsing/pdf_parser_types.dart';
import '../pdf_names.dart';
import 'pdf_import_context.dart';
import 'pdf_merge_options.dart';
import 'pdf_object_importer.dart';
import 'pdf_signature_policy.dart';

/// Builds the `/AcroForm` of the merged document.
///
/// The field hierarchy is flattened: every terminal field goes to the top of
/// `/Fields` with the fully qualified name in `/T`. Fields with several
/// widgets — radio groups, fields spanning pages — stay grouped under a single
/// field through `/Kids`.
class PdfFormImporter {
  PdfFormImporter(this.context, this.objects)
      : _signatures = PdfSignaturePolicy(context);

  final PdfImportContext context;
  final PdfObjectImporter objects;
  final PdfSignaturePolicy _signatures;

  /// Keys that belong to the field, not to the widget.
  static const _fieldKeys = <String>{
    PdfNameTokens.ft,
    PdfNameTokens.t,
    PdfNameTokens.tu,
    PdfNameTokens.tm,
    PdfNameTokens.ff,
    PdfNameTokens.v,
    PdfNameTokens.dv,
    PdfNameTokens.da,
    PdfNameTokens.q,
    PdfNameTokens.opt,
    PdfNameTokens.maxLen,
    PdfNameTokens.ti,
    PdfNameTokens.i,
    PdfNameTokens.lock,
    PdfNameTokens.sigRef,
  };

  void importSource() {
    if (!context.options.importFormFields) return;

    final groups = <int, _FieldGroup>{};

    for (final widget in context.widgets) {
      final chain = _chainOf(widget.sourceDict, widget.sourceRef);
      if (chain.terminalRef == null || chain.terminalIsWidget) {
        if (widget.sourceRef != null) {
          context.reachedFieldIds.add(widget.sourceRef!.obj);
        }
        _registerField(
          object: widget.destination,
          name: chain.qualifiedName,
        );
        continue;
      }

      context.reachedFieldIds.add(chain.terminalRef!.obj);
      groups
          .putIfAbsent(
            chain.terminalRef!.obj,
            () => _FieldGroup(chain.terminalRef!, chain.terminalDict!,
                chain.qualifiedName),
          )
          .widgets
          .add(widget);
    }

    for (final group in groups.values) {
      _importFieldGroup(group);
    }

    _importOrphanFields();
    _mergeAcroFormDictionary();
  }

  // ---------------------------------------------------------------------------

  void _importFieldGroup(_FieldGroup group) {
    final action = _signatures.classify(group.dict);
    // `drop` removes everything; `stamp` makes the field disappear and leaves
    // only the stamp, which the page import already created.
    if (action == PdfSignatureAction.drop ||
        action == PdfSignatureAction.stamp) {
      return;
    }

    const skipped = <String>{
      PdfNameTokens.kids,
      PdfNameTokens.parent,
      PdfNameTokens.t,
    };

    final field = PdfObject<PdfDict>(context.destination, params: PdfDict());
    context.imported[group.ref.obj] = field;

    group.dict.values.forEach((key, value) {
      if (skipped.contains(key)) return;
      final converted = objects.convert(value);
      if (converted != null) field.params[key] = converted;
    });

    final kids = PdfArray();
    for (final widget in group.widgets) {
      final params = widget.destination.params;
      if (params is PdfDict) {
        params[PdfNameTokens.parent] = field.ref();
        // What belongs to the field is not repeated on the widget.
        for (final key in _fieldKeys) {
          params.values.remove(key);
        }
      }
      kids.add(widget.destination.ref());
    }
    field.params[PdfNameTokens.kids] = kids;

    _registerField(object: field, name: group.qualifiedName);
  }

  /// Fields no widget reached.
  ///
  /// `/AcroForm /Fields` may hold a field with no widget at all — a hidden data
  /// field, or an invisible signature, which is the shape of the documents
  /// exported by SEI. Discovering fields through the pages alone would lose
  /// them.
  void _importOrphanFields() {
    final acroForm = _sourceAcroForm();
    if (acroForm == null) return;

    final fields = context.source.resolve(acroForm.values[PdfNameTokens.fields]);
    if (fields is! PdfArrayToken) return;

    for (final entry in fields.values) {
      _visitOrphanCandidate(entry, parentName: null, depth: 0);
    }
  }

  void _visitOrphanCandidate(dynamic entry,
      {required String? parentName, required int depth}) {
    if (depth > 32) return;

    final ref = PdfParserObjects.asRef(entry);
    final dict = context.source.resolve(entry);
    if (dict is! PdfDictToken) return;

    final own = _fieldName(dict);
    final qualified = parentName == null
        ? (own ?? '')
        : (own == null ? parentName : '$parentName.$own');

    final kids = context.source.resolve(dict.values[PdfNameTokens.kids]);
    final kidList = kids is PdfArrayToken ? kids.values : const <dynamic>[];
    final hasFieldKids = kidList.any((kid) {
      final kidDict = context.source.resolve(kid);
      if (kidDict is! PdfDictToken) return false;
      final subtype =
          PdfParserObjects.asName(kidDict.values[PdfNameTokens.subtype]);
      return subtype != PdfNameTokens.widget;
    });

    if (hasFieldKids) {
      for (final kid in kidList) {
        _visitOrphanCandidate(kid, parentName: qualified, depth: depth + 1);
      }
      return;
    }

    if (ref == null) return;
    if (context.reachedFieldIds.contains(ref.obj)) return;
    // Widgets of this field may have been reached individually.
    for (final kid in kidList) {
      final kidRef = PdfParserObjects.asRef(kid);
      if (kidRef != null && context.imported.containsKey(kidRef.obj)) return;
    }

    final action = _signatures.classify(dict);
    if (action == PdfSignatureAction.drop ||
        action == PdfSignatureAction.stamp) {
      if (action == PdfSignatureAction.stamp) {
        context.warn(
          'assinatura sem widget removida do formulário: a mesclagem a '
          'invalidaria',
        );
      }
      return;
    }

    final imported = objects.importRef(ref);
    if (imported == null) return;
    final object = context.imported[ref.obj];
    if (object == null) return;

    final params = object.params;
    if (params is PdfDict) {
      params.values.remove(PdfNameTokens.parent);
    }

    context.reachedFieldIds.add(ref.obj);
    _registerField(object: object, name: qualified);
  }

  // ---------------------------------------------------------------------------

  /// Appends the field to `/AcroForm /Fields`, resolving name collisions.
  void _registerField({
    required PdfObject object,
    required String name,
  }) {
    final params = object.params;
    final effective = _resolveName(name);
    if (effective == null) return; // keepFirst: field discarded

    if (params is PdfDict && effective.isNotEmpty) {
      params[PdfNameTokens.t] = PdfString.fromString(effective);
    }

    _acroFormFields().add(object.ref());
  }

  String? _resolveName(String name) {
    if (name.isEmpty) return name;
    if (!context.usedFieldNames.contains(name)) {
      context.usedFieldNames.add(name);
      return name;
    }

    switch (context.options.fieldNameConflict) {
      case PdfFieldNameConflictPolicy.throwError:
        throw PdfMergeException(
          'O campo de formulário "$name" já existe no documento de destino.',
        );
      case PdfFieldNameConflictPolicy.keepFirst:
        context.warn('campo "$name" descartado por já existir no destino');
        return null;
      case PdfFieldNameConflictPolicy.renameSuffix:
        for (var index = 2; index < 100000; index++) {
          final candidate = '${name}_$index';
          if (context.usedFieldNames.contains(candidate)) continue;
          context.usedFieldNames.add(candidate);
          context.renamedFields[name] = candidate;
          context.warn('campo "$name" renomeado para "$candidate"');
          return candidate;
        }
        throw PdfMergeException(
          'Não foi possível desambiguar o nome de campo "$name".',
        );
    }
  }

  /// Merges the form-level keys of the source into the destination.
  void _mergeAcroFormDictionary() {
    final source = _sourceAcroForm();
    if (source == null) return;

    final target = _acroForm();

    for (final key in const <String>[
      PdfNameTokens.da,
      PdfNameTokens.q,
    ]) {
      if (target.containsKey(key)) continue;
      final converted = objects.convert(source.values[key]);
      if (converted != null) target[key] = converted;
    }

    final needAppearances =
        context.source.resolve(source.values[PdfNameTokens.needAppearances]);
    if (needAppearances == true) {
      target[PdfNameTokens.needAppearances] = const PdfBool(true);
    }

    if (context.options.keepInvalidSignatures && context.sourceHasSignatures) {
      final current = target[PdfNameTokens.sigflags];
      final currentValue = current is PdfNum ? current.value.toInt() : 0;
      final sourceFlags =
          PdfParserObjects.asInt(source.values[PdfNameTokens.sigflags]) ?? 3;
      target[PdfNameTokens.sigflags] = PdfNum(currentValue | sourceFlags);
    }

    _mergeResourceDictionary(source, target);
  }

  /// `/DR`: resources used by the field appearances.
  void _mergeResourceDictionary(PdfDictToken source, PdfDict target) {
    final sourceDr = context.source.resolve(source.values[PdfNameTokens.dr]);
    if (sourceDr is! PdfDictToken) return;

    final existing = target[PdfNameTokens.dr];
    final targetDr = existing is PdfDict ? existing : PdfDict();
    if (existing is! PdfDict) target[PdfNameTokens.dr] = targetDr;

    sourceDr.values.forEach((category, value) {
      final resolved = context.source.resolve(value);
      final current = targetDr[category];

      if (resolved is PdfDictToken && current is PdfDict) {
        resolved.values.forEach((name, entry) {
          if (current.containsKey(name)) {
            // Renaming would require rewriting every /DA string that names
            // the resource.
            context.warn(
              'recurso "$name" de /AcroForm /DR já existia no destino e o do '
              'documento importado foi ignorado',
            );
            return;
          }
          final converted = objects.convert(entry);
          if (converted != null) current[name] = converted;
        });
        return;
      }

      if (current == null) {
        final converted = objects.convert(value);
        if (converted != null) targetDr[category] = converted;
      }
    });
  }

  // ---------------------------------------------------------------------------

  PdfDictToken? _sourceAcroForm() {
    final root = context.source.rootDict;
    if (root == null) return null;
    final acroForm =
        context.source.resolve(root.values[PdfNameTokens.acroForm]);
    return acroForm is PdfDictToken ? acroForm : null;
  }

  PdfDict _acroForm() {
    final catalogParams = context.destination.catalog.params;
    final existing = catalogParams[PdfNameTokens.acroForm];
    if (existing is PdfDict) return existing;
    final created = PdfDict();
    catalogParams[PdfNameTokens.acroForm] = created;
    return created;
  }

  PdfArray _acroFormFields() {
    final form = _acroForm();
    final existing = form[PdfNameTokens.fields];
    if (existing is PdfArray) return existing;
    final created = PdfArray();
    form[PdfNameTokens.fields] = created;
    return created;
  }

  /// Walks `/Parent` building the fully qualified name.
  _FieldChain _chainOf(PdfDictToken widgetDict, PdfRefToken? widgetRef) {
    final names = <String>[];
    final ownName = _fieldName(widgetDict);

    PdfRefToken? terminalRef;
    PdfDictToken? terminalDict;
    var terminalIsWidget = false;

    if (ownName != null) {
      // Widget and field in the same object: the common case.
      terminalIsWidget = true;
      terminalRef = widgetRef;
      terminalDict = widgetDict;
      names.add(ownName);
    }

    dynamic parentValue = widgetDict.values[PdfNameTokens.parent];
    for (var depth = 0; depth < 32; depth++) {
      final parentRef = PdfParserObjects.asRef(parentValue);
      final parentDict = context.source.resolve(parentValue);
      if (parentDict is! PdfDictToken) break;

      if (!terminalIsWidget && terminalRef == null) {
        terminalRef = parentRef;
        terminalDict = parentDict;
      }

      final parentName = _fieldName(parentDict);
      if (parentName != null) names.insert(0, parentName);

      parentValue = parentDict.values[PdfNameTokens.parent];
    }

    return _FieldChain(
      qualifiedName: names.join('.'),
      terminalRef: terminalRef,
      terminalDict: terminalDict,
      terminalIsWidget: terminalIsWidget,
    );
  }

  String? _fieldName(PdfDictToken dict) {
    final value = context.source.resolve(dict.values[PdfNameTokens.t]);
    if (value is PdfStringToken) {
      try {
        return PdfParserTokens.decodePdfString(
            Uint8List.fromList(value.bytes));
      } catch (_) {
        return utf8.decode(value.bytes, allowMalformed: true);
      }
    }
    if (value is PdfNameToken) return value.value;
    return null;
  }
}

class _FieldChain {
  const _FieldChain({
    required this.qualifiedName,
    required this.terminalRef,
    required this.terminalDict,
    required this.terminalIsWidget,
  });

  final String qualifiedName;
  final PdfRefToken? terminalRef;
  final PdfDictToken? terminalDict;

  /// Widget and field are the same object.
  final bool terminalIsWidget;
}

class _FieldGroup {
  _FieldGroup(this.ref, this.dict, this.qualifiedName);

  final PdfRefToken ref;
  final PdfDictToken dict;
  final String qualifiedName;
  final List<PdfImportedWidget> widgets = <PdfImportedWidget>[];
}

