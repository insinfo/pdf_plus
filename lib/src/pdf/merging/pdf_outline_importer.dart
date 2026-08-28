import 'dart:convert';
import 'dart:typed_data';

import '../color.dart';
import '../format/array.dart';
import '../format/null_value.dart';
import '../obj/outline.dart';
import '../obj/page.dart';
import '../parsing/parser_objects.dart';
import '../parsing/parser_tokens.dart';
import '../parsing/pdf_parser_types.dart';
import '../pdf_names.dart';
import 'pdf_import_context.dart';
import 'pdf_object_importer.dart';

/// Imports the bookmark tree (`/Outlines`) of a source.
///
/// The nodes are **recreated** through the [PdfOutline] model instead of being
/// cloned: the model owns `/First`, `/Last`, `/Prev`, `/Next` and `/Count` and
/// rewrites those keys on save, so a tree grafted in by hand would be
/// overwritten.
class PdfOutlineImporter {
  PdfOutlineImporter(this.context, this.objects);

  final PdfImportContext context;
  final PdfObjectImporter objects;

  void importSource() {
    if (!context.options.importBookmarks) return;

    final root = context.source.rootDict;
    if (root == null) return;

    final outlines =
        context.source.resolve(root.values[PdfNameTokens.outlines]);
    if (outlines is! PdfDictToken) return;

    final first = outlines.values[PdfNameTokens.first];
    if (first == null) return;

    var parent = context.destination.outline;

    if (context.options.groupBookmarksPerDocument) {
      final group = PdfOutline(
        context.destination,
        title: context.sourceLabel,
        dest: _firstImportedPage(),
      );
      parent.add(group);
      parent = group;
    }

    _importSiblings(first, parent, 0);
  }

  void _importSiblings(dynamic firstRef, PdfOutline parent, int depth) {
    if (depth > 32) {
      context.warn('árvore de bookmarks profunda demais; ramo ignorado');
      return;
    }

    var current = firstRef;
    final visited = <int>{};

    for (var guard = 0; guard < 100000; guard++) {
      final ref = PdfParserObjects.asRef(current);
      if (ref != null && !visited.add(ref.obj)) {
        // Circular `/Next` chain: a malformed file must not hang.
        break;
      }

      final node = context.source.resolve(current);
      if (node is! PdfDictToken) break;

      final outline = _createNode(node, parent);
      if (outline != null) {
        final child = node.values[PdfNameTokens.first];
        if (child != null) _importSiblings(child, outline, depth + 1);
      }

      final next = node.values[PdfNameTokens.next];
      if (next == null) break;
      current = next;
    }
  }

  PdfOutline? _createNode(PdfDictToken node, PdfOutline parent) {
    final title = _title(node);
    final destination = _resolveDestination(node);

    final outline = PdfOutline(
      context.destination,
      title: title ?? '',
      dest: destination?.page,
      color: _color(node),
      style: _style(node),
    );
    outline.destinationOverride = destination?.array;
    parent.add(outline);

    if (destination == null) {
      context.warn(
        'bookmark "${title ?? ''}" importado sem destino: a página apontada '
        'não faz parte do intervalo importado ou não pôde ser lida',
      );
    }

    return outline;
  }

  /// Resolves the destination of a bookmark, be it `/Dest` or
  /// `/A << /S /GoTo >>`.
  _OutlineDestination? _resolveDestination(PdfDictToken node) {
    try {
      dynamic dest = node.values[PdfNameTokens.dest];

      if (dest == null) {
        final action = context.source.resolve(node.values[PdfNameTokens.action]);
        if (action is PdfDictToken) {
          final type = PdfParserObjects.asName(action.values[PdfNameTokens.s]);
          if (type != PdfNameTokens.goto) return null;
          dest = action.values[PdfNameTokens.d];
        }
      }

      if (dest == null) return null;
      return _explicitDestination(dest);
    } catch (error) {
      // Reading the name tree of a malformed file can fail in many ways;
      // none of them justifies bringing the merge down.
      context.warn('destino de bookmark não pôde ser lido: $error');
      return null;
    }
  }

  _OutlineDestination? _explicitDestination(dynamic dest) {
    var target = context.source.resolve(dest);

    if (target is PdfStringToken) {
      target = _lookupNamed(_decode(target.bytes));
    } else if (target is PdfNameToken) {
      target = _lookupNamed(target.value);
    }

    if (target is PdfDictToken) {
      target = context.source.resolve(target.values[PdfNameTokens.d]);
    }
    if (target is! PdfArrayToken || target.values.isEmpty) return null;

    final pageRef = PdfParserObjects.asRef(target.values.first);
    if (pageRef == null) return null;
    final page = context.pageMap[pageRef.obj];
    if (page == null) return null;

    final array = objects.convertArray(target);
    if (array.values.isEmpty || array.values.first is PdfNull) return null;

    return _OutlineDestination(page, array);
  }

  dynamic _lookupNamed(String name) {
    if (!context.options.importNamedDestinations) return null;
    final root = context.source.rootDict;
    if (root == null) return null;

    final names = context.source.resolve(root.values[PdfNameTokens.names]);
    if (names is PdfDictToken) {
      final tree = context.source.resolve(names.values[PdfNameTokens.dests]);
      if (tree is PdfDictToken) {
        final found = _searchNameTree(tree, name, 0);
        if (found != null) return found;
      }
    }

    final legacy = context.source.resolve(root.values[PdfNameTokens.dests]);
    if (legacy is PdfDictToken) {
      final direct = legacy.values['/$name'] ?? legacy.values[name];
      if (direct != null) return context.source.resolve(direct);
    }
    return null;
  }

  dynamic _searchNameTree(PdfDictToken node, String name, int depth) {
    if (depth > 32) return null;

    final names = context.source.resolve(node.values[PdfNameTokens.names]);
    if (names is PdfArrayToken) {
      for (var i = 0; i + 1 < names.values.length; i += 2) {
        final key = names.values[i];
        final keyName = key is PdfStringToken
            ? _decode(key.bytes)
            : (key is PdfNameToken ? key.value : null);
        if (keyName == name) return context.source.resolve(names.values[i + 1]);
      }
    }

    final kids = context.source.resolve(node.values[PdfNameTokens.kids]);
    if (kids is PdfArrayToken) {
      for (final kid in kids.values) {
        final kidNode = context.source.resolve(kid);
        if (kidNode is! PdfDictToken) continue;
        final found = _searchNameTree(kidNode, name, depth + 1);
        if (found != null) return found;
      }
    }
    return null;
  }

  PdfPage? _firstImportedPage() {
    final pages = context.destination.pdfPageList.pages;
    if (context.pagesBeforeSource < pages.length) {
      return pages[context.pagesBeforeSource];
    }
    return pages.isEmpty ? null : pages.last;
  }

  String? _title(PdfDictToken node) {
    final value = context.source.resolve(node.values[PdfNameTokens.title]);
    if (value is PdfStringToken) return _decode(value.bytes);
    if (value is PdfNameToken) return value.value;
    return null;
  }

  PdfColor? _color(PdfDictToken node) {
    final value = context.source.resolve(node.values[PdfNameTokens.c]);
    if (value is! PdfArrayToken || value.values.length < 3) return null;
    final components = <double>[];
    for (final item in value.values.take(3)) {
      if (item is int) components.add(item.toDouble());
      if (item is double) components.add(item);
    }
    if (components.length != 3) return null;
    return PdfColor(components[0], components[1], components[2]);
  }

  PdfOutlineStyle _style(PdfDictToken node) {
    final value =
        PdfParserObjects.asInt(node.values[PdfNameTokens.f]) ?? 0;
    if (value < 0 || value >= PdfOutlineStyle.values.length) {
      return PdfOutlineStyle.normal;
    }
    return PdfOutlineStyle.values[value];
  }

  String _decode(List<int> bytes) {
    try {
      return PdfParserTokens.decodePdfString(Uint8List.fromList(bytes));
    } catch (_) {
      return utf8.decode(bytes, allowMalformed: true);
    }
  }
}

class _OutlineDestination {
  const _OutlineDestination(this.page, this.array);

  final PdfPage page;
  final PdfArray array;
}
